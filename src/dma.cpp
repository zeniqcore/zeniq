// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dma.h>

#include <config.h>
#include <consensus/activation.h>
#include <consensus/validation.h>
#include <netmessagemaker.h>
#include <pubkey.h>
#include <script/sign.h>
#include <script/standard.h>
#include <txmempool.h>
#include <validation.h>
#include <validationinterface.h>

#include <miner.h>

#include <algorithm>
#include <memory>
#include <random>
#include <utility>
#include <map>

using Signature = std::vector<uint8_t>;
using OutSigs = std::vector<Signature>;

Minter *g_Minter = nullptr;

Minter *Minter::Create(const std::vector<std::string> &mintingKeys,
                       const uint8_t *dmaBegin, const uint8_t *dmaEnd) {
    std::unique_ptr<Minter> uMinter(new Minter(dmaBegin, dmaEnd));
    if (uMinter->Initialize(mintingKeys)) {
        return uMinter.release();
    }
    return nullptr;
}

Minter::Minter(const uint8_t *dmaBegin, const uint8_t *dmaEnd)
    : m_config(GetConfig()) {
    for (int i = 0, index = 0; i < (dmaEnd - dmaBegin);
         i += sizeof(uint160), ++index) {
        CKeyID t;
        std::reverse_copy(dmaBegin + i, dmaBegin + i + sizeof(CKeyID),
                          t.begin());
        m_index[t] = index;
    }
}

bool Minter::Initialize(const std::vector<std::string> &mintingKeys) {
    LOCK(cs_minter);
    try {
        for (const std::string &key_dst : mintingKeys) {
            AddKeyDst(key_dst);
        }
    } catch (const std::runtime_error &e) {
        LogPrintf("%s\n", e.what());
        return false;
    }
    return true;
}

MinterKey::MinterKey(const std::string &key, const std::string &dst,
                     const Minter &minter) {
    privateKey = DecodeSecret(key);
    if (!privateKey.IsValid()) {
        throw std::runtime_error("Fatal: mining: malformed key");
    }
    keyID = privateKey.GetPubKey().GetID();
    const auto foundminter = minter.m_index.find(keyID);
    if (foundminter == minter.m_index.end()) {
        throw std::runtime_error("Fatal: mining: illegal key");
    }
    index = foundminter->second;
    dstString = dst;
    if (dst.empty()) {
#ifdef ENABLE_WALLET
        mintDestination = CNoDestination(); // => from first wallet
#else
        mintDestination = privateKey.GetPubKey().GetID();
#endif
    } else {
        mintDestination = // CNoDestination if dst not Base58 => from wallet
            DecodeDestination(dst, minter.m_config.GetChainParams());
    }
    LogPrintf("Minting to %d : %s : %s\n", index, keyID.ToString(),
              mintDestination.which()
                  ? EncodeDestination(mintDestination, minter.m_config).c_str()
                  : dst + " wallet"
                  );
}

void Minter::AddKeyDst(const std::string &key_dst) {
    auto colon = key_dst.find(':');
    std::string key;
    std::string dst;
    if (colon == std::string::npos) {
        key = key_dst;
    } else {
        key = key_dst.substr(0, colon);
        dst = key_dst.substr(colon + 1);
    }

    MinterKey mk(key, dst, *this);
    m_minterkeys.push_back(mk);
    m_minterkeystore.AddKey(mk.privateKey);
}

bool Minter::SignPayFromMinter(const CTransaction &txFrom,
                               CMutableTransaction &txTo, unsigned int nIn,
                               SigHashType sigHashType) {
    auto const context = std::nullopt;
    return SignSignature(m_minterkeystore, txFrom, txTo, nIn, sigHashType,
                         context);
}

template <typename T>
static uint256 MinterHash(const T &t, int height,
                          const uint256 &hashPrevBlock) {
    CHashWriter ss2(SER_GETHASH, 0);
    ss2 << static_cast<uint32_t>(height);
    ss2 << t;
    ss2 << hashPrevBlock;
    const auto ret = ss2.GetHash();
    return ret;
}

#ifdef DMA_TESTING
bool MinterBucket_ReturnValueForTest = true;
#endif

static bool MinterBucket(const CKeyID &keyid, int height,
                         const uint256 &hashPrevBlock) {
#ifdef DMA_TESTING
    return MinterBucket_ReturnValueForTest;
#else
    return (MinterHash(keyid, height, hashPrevBlock).GetUint64(0) & 127) ==
           (hashPrevBlock.GetUint64(0) & 127);
#endif
}

#define EPOCH_BLOCKS 55000
static Amount SubsidyMinter(int height, int index) {
    int64_t nSubsidy = (MAX_MINTER_SUBSIDY * COIN) / SATOSHI;
    const int epoch = height / EPOCH_BLOCKS;
    if (epoch > 23) {
        nSubsidy >>= 23;
    } else if (epoch) {
        // linear halving
        const int64_t qStart = nSubsidy >> (epoch - 1);
        const int64_t qEnd = nSubsidy >> epoch;
        const int rel = height - epoch * EPOCH_BLOCKS;
        const int64_t delta = qStart - qEnd;
        const int64_t sub = (delta * rel) / EPOCH_BLOCKS;
        nSubsidy = qStart - sub;
    }

    // 4% less for each minter generation after 10, percent halving every 50k
    const int gen = index / 1000;
    int permil = 40;
    for (int g = 10; g <= gen; ++g) {
        if (!(g % 50)) {
            permil = permil / 2;
            if (!permil) {
                permil = 1;
            }
        }
        int64_t minus4 = (nSubsidy * permil) / 1000;
        nSubsidy -= minus4;
    }

    if (nSubsidy < 1000) {
        return Amount::zero();
    }

    return nSubsidy * SATOSHI;
}

Amount Minter::SubsidyMiner(int height, const CTransaction &coinbase) {
    Amount subsidy = Amount::zero();
    Amount sumMinting = Amount::zero();
    const int txOutCount = coinbase.vout.size();
    for (int ndx = 2; ndx < txOutCount; ++ndx) {
        subsidy += 1 * COIN;
        sumMinting += coinbase.vout[ndx].nValue;
    }

    if (height < GetConsensus().ZeniqOpaliteHeight) {
        return subsidy;
    }

    const Amount maxSub = 3 * sumMinting / 100;
    if (subsidy < maxSub) {
        return subsidy;
    }
    return maxSub;
}

int Minter::TxOutValid(const CTxOut &txOut, int height,
                        const Signature &outsig,
                        const uint256 &hashPrevBlock) {
    // check signing key
    CPubKey pubkey;
    if (!pubkey.RecoverCompact(
            MinterHash(txOut.scriptPubKey, height, hashPrevBlock), outsig)) {
        return -1;
    }
    auto keyID = pubkey.GetID();
    // check valid minter
    LOCK(cs_minter);
    const auto foundminter = m_index.find(keyID);
    if (foundminter == m_index.end()) {
        return -1;
    }
    // check amount
    if (txOut.nValue != SubsidyMinter(height, foundminter->second)) {
        return -1;
    }
    // check that minter bucket is for hashPrevBlock
    if (m_config.GetChainParams().GetConsensus().IsZenitNet() &&
        !MinterBucket(keyID, height, hashPrevBlock)) {
        return -1;
    }

    return foundminter->second;
}

#ifdef ENABLE_WALLET
CWallet *GetFirstWallet() {
    auto vpwallets = GetWallets();
    return vpwallets.size() >= 1 ? vpwallets[0].get() : nullptr;
}
#endif

class MinterTransactions : public std::vector<CTransactionRef> {
public:
    void AddMaybe(const MinterKey &mk, const uint256 &currentBlockHash,
                  int height, bool IsZenitNet) {
        // don't send to mempool if key not in bucket
        if (IsZenitNet && !MinterBucket(mk.keyID, height, currentBlockHash)) {
            return;
        }

        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vout.resize(2);
        mtx.nLockTime = height;

        CTxIn &txIn = mtx.vin[0];
        txIn.nSequence = CTxIn::SEQUENCE_FINAL;

        CTxOut &txOutPay = mtx.vout[0];
        CTxOut &txOutSig = mtx.vout[1];

        txOutPay.nValue = SubsidyMinter(height, mk.index);
        txOutPay.scriptPubKey = GetScriptForDestination(mk.mintDestination);
#ifdef ENABLE_WALLET
        static std::map<int,CScript> script_for_height;
        if (txOutPay.scriptPubKey.empty()) { // for CNoDestination
            txOutPay.scriptPubKey = script_for_height[height];
            if (txOutPay.scriptPubKey.empty()) {
                CWallet *pwallet = nullptr;
                if (!mk.dstString.empty()) {
                    std::shared_ptr<CWallet> wallet = GetWallet(mk.dstString);
                    pwallet = wallet.get();
                }
                if (!pwallet) {
                    pwallet = GetFirstWallet();
                }
                if (pwallet) {
                    std::shared_ptr<CReserveScript> reserve;
                    pwallet->GetScriptForMining(reserve);
                    txOutPay.scriptPubKey = script_for_height[height] =
                        reserve.get()->reserveScript;
                } else {
                    txOutPay.scriptPubKey = GetScriptForDestination(
                        mk.privateKey.GetPubKey().GetID());
                    LogPrintf("Neither destination nor wallet %s: "
                            "resorting to minting key", mk.dstString);
                }
            }
            while (script_for_height.size() > 2*N_MINTER_TX_RELAY) {
                script_for_height.erase(script_for_height.begin());
            }
        }
#endif

        txOutSig.nValue = Amount::zero();

        Signature sig;
        if (!mk.privateKey.SignCompact(
                MinterHash(txOutPay.scriptPubKey, height, currentBlockHash),
                sig)) {
            return;
        }
        txOutSig.scriptPubKey << OP_RETURN << sig;

        CTransactionRef tx = MakeTransactionRef(mtx);
        if (tx->IsDMA()) {
            emplace_back(tx);
        }
    }
};

extern void AddToRelayMap(const CTransactionRef &tx);
void Minter::ToMempool(const CBlockIndex *tip) {
    MinterTransactions mintertxs;
    for (int rel = 0; rel < N_MINTER_TX_RELAY; ++rel) {
        LOCK(cs_minter);
        for (const auto &mk : m_minterkeys) {
            mintertxs.AddMaybe(
                mk, tip->GetBlockHash(), tip->nHeight + 1,
                m_config.GetChainParams().GetConsensus().IsZenitNet());
        }
        tip = tip->pprev;
        if (!tip) {
            break;
        }
    }
    std::vector<CInv> vInv;
    for (const CTransactionRef &tx : mintertxs) {
        CValidationState state;
        LOCK2(cs_main, g_mempool.cs);
        bool ret = ::AcceptToMemoryPool(
            m_config, g_mempool, state, tx, nullptr /* pfMissingInputs */,
            true /* bypass_limits */, Amount::zero());
        if (!ret && state.GetRejectCode() != REJECT_DUPLICATE) {
            LogPrintf("ToMempool: AcceptToMemoryPool failed:%s\n",
                      tx->ToString());
        } else { // even if REJECT_DUPLICATE, do relay (see MINTER_MILLI_RELAY)
            CInv inv(MSG_TX, tx->GetId());
            vInv.push_back(inv);
            AddToRelayMap(tx);
        }
    }
    if (!vInv.empty()) {
        g_connman->ForEachNode([&vInv](CNode *pnode) {
            const CNetMsgMaker msgMaker(pnode->GetSendVersion());
            g_connman->PushMessage(pnode, msgMaker.Make(NetMsgType::INV, vInv));
        });
    }
}

void Minter::MinterThread() {
    const CBlockIndex *lastTip = nullptr;
    uint64_t lastTime = 0;
    for (;;) {
        const CBlockIndex *tip = ::ChainActive().Tip();
        if (!tip) {
            MilliSleep(10);
            continue;
        }
        if (IsInitialBlockDownload()) {
            MilliSleep(100);
            continue;
        }
        const uint64_t now = GetTimeMillis();
        const uint64_t age = now - lastTime;
        if (tip == lastTip && age < MINTER_MILLI_RELAY) {
            MilliSleep(10);
            continue;
        }
        lastTip = tip;
        lastTime = now;

        ToMempool(tip);
    }
}

static bool MinterSignatures(const CTxOut &txOutSig, OutSigs &outSigs) {
    CScript::const_iterator pc = txOutSig.scriptPubKey.begin();
    if (pc == txOutSig.scriptPubKey.end()) {
        return false;
    }

    opcodetype opcode1;
    std::vector<uint8_t> data1;
    if (!txOutSig.scriptPubKey.GetOp(pc, opcode1, data1)) {
        return false;
    }

    if (opcode1 != OP_RETURN) {
        return false;
    }

    while (pc != txOutSig.scriptPubKey.end()) {
        opcodetype opcode;
        Signature outsig;
        if (!txOutSig.scriptPubKey.GetOp(pc, opcode, outsig)) {
            return false;
        }
        if (opcode > OP_16) {
            // not a push
            return false;
        }
        outSigs.push_back(outsig);
    }
    return true;
}

void Minter::ToCoinbase(CMutableTransaction &coinbaseTx, const int height,
                        const CTxMemPool *mempool,
                        const BlockHash &hashPrevBlock, CBlock *pblock,
                        const Amount fees, const Consensus::Params &consensus) {
    if (!consensus.IsZenitNet()) {
        return;
    }
    coinbaseTx.vout[0].nValue = Amount::zero();
    coinbaseTx.vin[0].scriptSig = CScript()
                                  << ScriptInt::fromIntUnchecked(height);
    coinbaseTx.vout.resize(2);
    coinbaseTx.vout[1].nValue = Amount::zero();
    coinbaseTx.vout[1].scriptPubKey << OP_RETURN;

    struct Entry {
        std::vector<uint8_t> outsig;
        CTxOut txOutPay;
    };
    std::vector<Entry> Entries;

    std::set<int> unique;
    for (auto &entry : mempool->GetIndex()) {
        const CTransactionRef tx = entry.GetSharedTx();
        if (!tx->IsDMA(height)) {
            continue;
        }

        const CTxOut &txOutPay = tx->vout[0];
        const CTxOut &txOutSig = tx->vout[1];

        OutSigs outSigs;
        if (!MinterSignatures(txOutSig, outSigs)) {
            continue;
        }
        if (outSigs.size() != 1) {
            continue;
        }

        auto itOutSig = outSigs.begin();
        int index = TxOutValid(txOutPay, height, *itOutSig, hashPrevBlock);
        bool duplicate = !unique.insert(index).second;
        if (index != -1 && !duplicate) {
            Entries.emplace_back(Entry{*itOutSig, txOutPay});
        }
    }

    if (Entries.empty()) {
        // MinterBucket can be empty for a small minter network
        // (less or about 128)
        ++t_NewBlock.counterNoMinter;
    }

    static auto rd = std::random_device{};
    static auto rdengine = std::default_random_engine{rd()};
    std::shuffle(std::begin(Entries), std::end(Entries), rdengine);
    for (const Entry &a : Entries) {
        coinbaseTx.vout[1].scriptPubKey << a.outsig;
        coinbaseTx.vout.push_back(a.txOutPay);
    }

    pblock->EncodeMinterCount(coinbaseTx.vout.size());
    coinbaseTx.vout[0].nValue = // overwrite GetBlockSubsidy
        MinerReward(fees, height, CTransaction(coinbaseTx));
}

bool Minter::TxValid(const CTransaction &tx, CValidationState &state) {
    CChain &chainActive = ::ChainActive();
    if (static_cast<int64_t>(tx.nLockTime) + N_MINTER_TX_RELAY <=
        chainActive.Height()) {
        return state.Invalid(false, REJECT_DUPLICATE, "txn-too-old");
    }
    int height = tx.nLockTime;
    if (height > 0 && chainActive.Height() >= height) {
        CBlockIndex *prevBlock = chainActive[height - 1];
        if (prevBlock) {
            const CTxOut &txOutPay = tx.vout[0];
            const CTxOut &txOutSig = tx.vout[1];
            OutSigs outSigs;
            if (!MinterSignatures(txOutSig, outSigs) ||
                (outSigs.size() != 1) ||
                (-1 == TxOutValid(txOutPay, height, *outSigs.begin(),
                            prevBlock->GetBlockHash()))) {
                return state.Invalid(false, REJECT_INVALID,
                                     "txn-illegal-minter");
            }
        }
    }
    return true;
}

void Minter::RemoveOld() {
    auto itend = g_mempool.mapTx.get<0>().end();
    for (auto it = g_mempool.mapTx.get<0>().begin(); it != itend; ++it) {
        const CTransactionRef tx = it->GetSharedTx();
        if (!tx->IsDMA()) {
            continue;
        }
        if (static_cast<int64_t>(tx->nLockTime) + N_MINTER_TX_RELAY <=
            ::ChainActive().Height()) {
            CTxMemPool::setEntries stage;
            stage.insert(it);
            g_mempool.RemoveStaged(stage, MemPoolRemovalReason::BLOCK);
            g_mempool.ClearPrioritisation(tx->GetId());
        }
    }
}

void Minter::Exit() {
    if (g_Minter) {
        delete g_Minter;
        g_Minter = nullptr;
    }
}

void Minter::MinterForTest() {
    if (g_Minter) {
        return;
    }
    static uint8_t dmaData[]{0x7a, 0x60, 0xeb, 0xf6, 0xe2, 0xc1, 0x72,
                             0x0f, 0x66, 0x4b, 0x7a, 0xfb, 0xba, 0xb8,
                             0x4c, 0x56, 0xbc, 0x73, 0x51, 0x99};
    static std::vector<std::string> mintingKeys{
        "M9qqUGNW9v1SoAB5LYNT151XRwyuY5hsGB9paXjoX9jKStBevcMz"};
    // above constants for minter_tests (pre-calculates blockinfo.nonce's)
    // created with the following
    if (!GetConfig().GetChainParams().GetConsensus().IsZenitNet()) {
        CKey privTest;
        privTest.MakeNewKey(true);
        auto b = privTest.GetPubKey().GetID().begin();
        std::reverse_copy(b, b + sizeof(CKeyID), dmaData);
        mintingKeys = {EncodeSecret(privTest)};
    }
    g_Minter = Minter::Create(mintingKeys, dmaData, dmaData + sizeof(dmaData));
}

bool Minter::CheckCoinbase(const CTransaction &coinbase,
                           CValidationState &state,
                           const uint256 *hashPrevBlock) {
    ////////////////////////// check coinbase.vin
    const CScript &cbInScript = coinbase.vin[0].scriptSig;

    if (cbInScript.size() < 1 || // height only, no OP_0
        cbInScript.size() > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-inlength");
    }

    if (!cbInScript.IsPushOnly()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-pushop");
    }
    CScript::const_iterator pc = cbInScript.begin();
    opcodetype opcode;
    std::vector<uint8_t> data;
    if (!cbInScript.GetOp(pc, opcode, data)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-noop");
    }
    if (!CScriptNum::IsMinimallyEncoded(data, 4)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-minimal");
    }

    // BIP34: height in coinbase
    int height;
    if (data.size()) {
        CScriptNum numHeight(data, true,
                             CScriptNum::MAXIMUM_ELEMENT_SIZE_64_BIT);
        height = numHeight.getint64();
    } else {
        height = CScript::DecodeOP_N(opcode);
    }
    if (height < 0) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-height-negative");
    }
    if (!height) { // no transactions for genesis block
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-genesis");
    }

    if (cbInScript.GetOp(pc, opcode)) {
        // extra data in CB
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-extraop");
    }

    /////////////////////////// check coinbase.vout
    const int txOutCount = coinbase.vout.size();
    if (txOutCount < 3) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-outlength");
    }

    const CTxOut txOutSig = coinbase.vout[1];
    if (txOutSig.nValue != Amount::zero()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-sig-not-zero");
    }

    OutSigs outSigs;
    if (!MinterSignatures(txOutSig, outSigs)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-content");
    }

    if (static_cast<int64_t>(outSigs.size()) != txOutCount - 2) {
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-sigsize");
    }

    bool beyond_opalite = height > GetConsensus().ZeniqCheckMinterDuplicates;
    if (hashPrevBlock) {
        std::set<int> unique;
        auto itOutSig = outSigs.begin();
        for (int ndx = 2; ndx < txOutCount; ++ndx, ++itOutSig) {
            int index = TxOutValid(coinbase.vout[ndx], height, *itOutSig,
                        *hashPrevBlock);
            bool duplicate = !unique.insert(index).second;
            if ((beyond_opalite && duplicate) || index == -1) {
                return state.DoS(100, false, REJECT_INVALID,
                                 "bad-cb-outinvalid");
            }
        }
    }

    // tx.vout[0].nValue <= nFees/2+SubsidyMiner (MinerReward())
    // checked later in validation.cpp
    // as it needs the transactions to calculate nFees

    return true;
}

static uint32_t MinMinterCount(const CBlockIndex *p) {
    uint32_t sum = 0;
    uint32_t n = 0;
    while (p && n++ < 36) {
        sum += p->MinterCount();
        p = p->pprev;
    }
    uint32_t avg = n ? sum / n : 0;
    return avg / MAX_MINTER_DROP_FROM_AVG_36;
}

bool Minter::ContextualCheck(const CBlockHeader &block, CValidationState &state,
                             const CBlockIndex *pindexPrev) {
    if (!pindexPrev) {
        return true;
    }
    const int height = pindexPrev->nHeight + 1;
    const uint32_t voutsize = block.MinterCount();
    if (!voutsize && height >= GetConsensus().ZeniqMinterCountInVersionHeight) {
        return state.DoS(
            100,
            error("%s: minting info is no longer optional (height %d)",
                  __func__, height),
            REJECT_CHECKPOINT, "missing-mint-info");
    }
    uint32_t minvoutsize = MinMinterCount(pindexPrev);
    if (voutsize && voutsize < minvoutsize) {
        return state.DoS(
            40,
            error("%s: not enough minting (height %d, min %d, mint %d)",
                  __func__, height, minvoutsize, voutsize),
            REJECT_CHECKPOINT, "minter-drop");
    }
    return true;
}

bool Minter::CheckMinterCount(CValidationState &state, const CBlock &block) {
    const uint32_t voutsize = block.MinterCount();
    if (voutsize) {
        const uint32_t cbvoutsize = block.vtx[0]->vout.size();
        if (voutsize != cbvoutsize) {
            return state.DoS(
                100, false, REJECT_INVALID, "bad-mint-info", false,
                strprintf(
                    "Minting count check failed (txid %s, hdr %d, cb %d) %s",
                    block.vtx[0]->GetId().ToString(), voutsize, cbvoutsize,
                    state.GetDebugMessage()));
        }
    }
    return true;
}

bool Minter::TxSkip(const CTransaction &tx) {
    if (static_cast<int64_t>(tx.nLockTime) <=
        ::ChainActive().Height() - N_MINTER_TX_RELAY) {
        // too old
        return true;
    }
    if (static_cast<int64_t>(tx.nLockTime) >
        ::ChainActive().Height() + N_MINTER_TX_RELAY) {
        // too far in the future
        return true;
    }
    return false;
}

thread_local NewBlock t_NewBlock;

bool NewBlock::TooLowMinterCount(const CBlock *pblock) {
    uint32_t voutsize = pblock->vtx[0]->vout.size();
    if (voutsize < 3) {
        return true;
    }
    auto tip = ::ChainActive().Tip();
    if (voutsize < tip->MinterCount() / MAX_MINTER_DROP) {
        return true;
    }
    if (voutsize < MinMinterCount(tip)) {
        return true;
    }
    return false;
}

CBlockIndex *
NewBlock::ChainActiveTipOrPrevious(const Consensus::Params &consensus) {
    CBlockIndex *pindexPrev = ::ChainActive().Tip();
    if (!consensus.IsZenitNet() || !g_Minter) {
        return pindexPrev;
    }
    if (lastOkTip != pindexPrev) {
        lastOkTip = pindexPrev;
        fromPreviousTip = nullptr;
        lastOkTime = GetTime();
        counterNoMinter = 0;
    } else {
        const auto age = GetTime() - lastOkTime;
        if (age > NOMINTER_START_TIME) {
            if (counterNoMinter > MAX_COUNTER_NOMINTER) {
                fromPreviousTip = pindexPrev;
                pindexPrev = pindexPrev->pprev;
                fromPreviousTip->nTimePreviousTip = GetTime();
                fromPreviousTip->nChainWork =
                    fromPreviousTip->pprev->nChainWork +
                    (GetBlockProof(*fromPreviousTip) / 4);
                LogPrintf("Miner: tip is not mineable, discarding it\n");
            }
        } else {
            counterNoMinter = 0;
        }
    }
    return pindexPrev;
}

void NewBlock::CopyFromPreviousTip(CBlockTemplate *pblocktemplate,
                                   const Consensus::Params &consensus) {
    CBlock blk;
    assert(ReadBlockFromDisk(blk, fromPreviousTip, consensus));
    for (const CTransactionRef &tx : blk.vtx) {
        if (tx->IsCoinBase()) {
            continue;
        }
        pblocktemplate->entries.emplace_back(tx, ::minRelayTxFee.GetFeePerK(),
                                             1);
    }
}

bool NewBlock::UsePreviousTip(const CBlockIndex *tip) {
    if (!tip || !tip->nTimePreviousTip) {
        return false;
    }
    const auto age = GetTime() - tip->nTimePreviousTip;
    if (age >= 0 && age < MAX_PREVIOUSTIP_TIME) {
        return true;
    }
    return false;
}

