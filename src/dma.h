// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <key.h>
#include <key_io.h>
#include <keystore.h>
#include <primitives/transaction.h>
#include <util/time.h>
#include <validationinterface.h>
#if ENABLE_WALLET
#include <wallet/wallet.h>
#endif

#include <cstdint>
#include <unordered_map>
#include <vector>

#define MAX_MINTER_SUBSIDY 100
#define N_MINTER_TX_RELAY 3
#define MINTER_MINING_MIN_NODES 6
#define MAX_MINTER_DROP 8
#define MAX_MINTER_DROP_FROM_AVG_36 4
#define MAX_COUNTER_NOMINTER 20
#define NOMINTER_START_TIME 60
#define MAX_PREVIOUSTIP_TIME 300
#define MAX_NONCE_TIME 5
#define NOMINTER_SLEEP_MILLI 500
#define MINTER_MILLI_RELAY 15000

struct BlockHash;

class Minter;
struct MinterKey {
    int index;
    CKey privateKey;
    CKeyID keyID;
    CTxDestination mintDestination;
    std::string dstString;
    MinterKey(const std::string &key, const std::string &dst,
              const Minter &dma);
};
using MinterKeys = std::vector<MinterKey>;

struct CBlockTemplate;

class NewBlock {
private:
    CBlockIndex *lastOkTip;
    uint64_t lastOkTime;
    CBlockIndex *fromPreviousTip;

public:
    int counterNoMinter;
    NewBlock()
        : lastOkTip(nullptr), lastOkTime(GetTime()), fromPreviousTip(nullptr),
          counterNoMinter(0) {}
    bool TooLowMinterCount(const CBlock *pblock);
    CBlockIndex *ChainActiveTipOrPrevious(const Consensus::Params &consensus);
    CBlockIndex *UsedPreviousTip() { return fromPreviousTip; }
    void CopyFromPreviousTip(CBlockTemplate *pblocktemplate,
                             const Consensus::Params &consensus);
    static bool UsePreviousTip(const CBlockIndex *tip);
    // only used in src/test/miner_tests.cpp
    uint64_t LastOkTime() { return lastOkTime; }
};

class Minter final : public CValidationInterface {
public:
    static Minter *Create(const std::vector<std::string> &mintingKeys,
                          const uint8_t *dmaBegin, const uint8_t *dmaEnd);
    static void MinterForTest();
    static void Exit();

public:
    void ToMempool(const CBlockIndex *tip);
    void ToCoinbase(CMutableTransaction &coinbaseTx, const int height,
                    const CTxMemPool *mempool, const BlockHash &hashPrevBlock,
                    CBlock *pblock, const Amount fees,
                    const Consensus::Params &consensus);
    Amount SubsidyMiner(int height, const CTransaction &coinbase);
    Amount MinerReward(Amount fees, int height, const CTransaction &coinbase) {
        return fees / 2 + SubsidyMiner(height, coinbase);
    }
    void RemoveOld();
    bool TxValid(const CTransaction &tx, CValidationState &state);
    int TxOutValid(const CTxOut &txOut, int height,
                    const std::vector<uint8_t> &scriptPubKeyData,
                    const uint256 &hashPrevBlock);

    bool CheckCoinbase(const CTransaction &tx, CValidationState &state,
                       const uint256 *hashPrevBlock);
    bool ContextualCheck(const CBlockHeader &block, CValidationState &state,
                         const CBlockIndex *pindexPrev);
    bool CheckMinterCount(CValidationState &state, const CBlock &block);

    bool TxSkip(const CTransaction &tx);

    void MinterThread();

    bool
    SignPayFromMinter(const CTransaction &txFrom, CMutableTransaction &txTo,
                      unsigned int nIn,
                      SigHashType sigHashType = SigHashType().withForkId());
    // see CheckSighashEncoding and MANDATORY_SCRIPT_VERIFY_FLAGS

private:
    const Consensus::Params &GetConsensus() {
        return m_config.GetChainParams().GetConsensus();
    }
    Minter(const uint8_t *dmaBegin, const uint8_t *dmaEnd);
    bool Initialize(const std::vector<std::string> &mintingKeys);
    void AddKeyDst(const std::string &key_dst);

private:
    RecursiveMutex cs_minter;
    const Config &m_config;
    struct KeyIdHasher {
        constexpr size_t operator()(const uint160 &key) const {
            return (size_t)key.GetUint64(0);
        }
    };
    std::unordered_map<const uint160, int, KeyIdHasher> m_index;
    MinterKeys m_minterkeys;
    CBasicKeyStore m_minterkeystore;
    friend MinterKey;
};


#ifdef ENABLE_WALLET
CWallet *GetFirstWallet();
#endif

extern thread_local NewBlock t_NewBlock;
extern Minter *g_Minter;

