// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <config.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <policy/policy.h>
#include <pubkey.h>
#include <script/standard.h>
#include <txmempool.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <validation.h>

#include <dma.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

extern bool MinterBucket_ReturnValueForTest;
bool CheckProofOfWork(const BlockHash &hash, uint32_t nBits,
                      const Consensus::Params &params);

BOOST_FIXTURE_TEST_SUITE(miner_tests, TestingSetup)

// BOOST_CHECK_EXCEPTION predicates to check the specific validation error
class HasReason {
public:
    explicit HasReason(const std::string &reason) : m_reason(reason) {}
    bool operator()(const std::runtime_error &e) const {
        return std::string(e.what()).find(m_reason) != std::string::npos;
    };

private:
    const std::string m_reason;
};

static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);

static BlockAssembler AssemblerForTest(const CChainParams &params,
                                       const CTxMemPool &mempool) {
    BlockAssembler::Options options;
    options.blockMinFeeRate = blockMinFeeRate;
    return BlockAssembler(params, mempool, options);
}

#define NBLOCKINFO (COINBASE_MATURITY+10)
uint32_t blockinfo_nonce[NBLOCKINFO] = {
2832633871 , 442807713  , 191795749  , 1916268433 , 3598267653 ,
1469035760 , 22653609   , 15876557   , 16800821   , 56892707   ,
24932803   , 65541227   , 9849071    , 23912711   , 680235     ,
7944345    , 318400     , 215502     , 20150040   , 17087647   ,
7752871    , 10630518   , 25917477   , 11582467   , 12574498   ,
7490855    , 16442315   , 44421279   , 1705651    , 36035555   ,
30064246   , 9896169    , 86675378   , 26369491   , 50650485   ,
5973651    , 2871673    , 12718497   , 5216901    , 5565406    ,
2073034    , 33427611   , 20714604   , 4534259    , 9428274    ,
21181985   , 54505186   , 23534486   , 1428067    , 22436495   ,
11088581   , 895188     , 6127090    , 41096631   , 24331517   ,
9347229    , 13765482   , 4320648    , 20039922   , 56619637   ,
93392097   , 4188262    , 9273013    , 14205847   , 81029468   ,
16032732   , 73731      , 6521898    , 1976952    , 1595263    ,
4747710    , 39998919   , 1033799    , 13631932   , 4385889    ,
23881710   , 10589668   , 23790440   , 5626764    , 7105030    ,
600002     , 17146861   , 874622     , 3831027    , 13435752   ,
166342     , 4558113    , 5555948    , 7159655    , 2736912    ,
9924547    , 18042320   , 37736829   , 18941345   , 20189059   ,
2461261    , 1522943    , 3429845    , 60814171   , 7700604    ,
35525850   , 8783012    , 104581725  , 10492165   , 8140585    ,
4174500    , 3022110    , 15678064   , 9051194    , 4786776
};

using CBlockIndexPtr = std::unique_ptr<CBlockIndex>;

static CBlockIndexPtr CreateBlockIndex(int nHeight) {
    CBlockIndexPtr index(new CBlockIndex);
    index->nHeight = nHeight;
    index->pprev = ::ChainActive().Tip();
    return index;
}

static bool TestSequenceLocks(const CTransaction &tx, int flags)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    LOCK(::g_mempool.cs);
    return CheckSequenceLocks(::g_mempool, tx, flags);
}

// Test suite for feerate transaction selection.
// Implemented as an additional function, rather than a separate test case, to
// allow reusing the blockchain created in CreateNewBlock_validity.
static void TestPackageSelection(const CChainParams &chainparams,
                                 const CScript &scriptPubKey,
                                 const std::vector<CTransactionRef> &txFirst)
    EXCLUSIVE_LOCKS_REQUIRED(cs_main, ::g_mempool.cs) {
    // Test the ancestor feerate transaction selection.
    TestMemPoolEntryHelper entry;

    // Test that a medium fee transaction will be selected before a higher fee
    // transaction when the high-fee tx has a low fee parent.
    CMutableTransaction tx;
    tx.vin.resize(1);
    //tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vin[0].scriptSig = CScript()<<OP_1<<OP_1<<OP_EQUAL<<OP_1<<OP_1<<OP_EQUAL<<OP_EQUAL;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vout.resize(1);
    tx.vout[0].nValue = int64_t(100000000LL - 1000) * SATOSHI;
    // This tx has a low fee: 1000 satoshis.
    // Save this txid for later use.
    TxId parentTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(1000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(true)
                               .FromTx(tx));

    // This tx has a medium fee: 10000 satoshis.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 0);
    tx.vout[0].nValue = int64_t(100000000LL - 10000) * SATOSHI;
    TxId mediumFeeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(10000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(true)
                               .FromTx(tx));

    // This tx has a high fee, but depends on the first transaction.
    tx.vin[0].prevout = COutPoint(parentTxId, 0);
    // 50k satoshi fee.
    tx.vout[0].nValue = int64_t(100000000LL - 1000 - 50000) * SATOSHI;
    TxId highFeeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(50000 * SATOSHI)
                               .Time(GetTime())
                               .SpendsCoinbase(false)
                               .FromTx(tx));

    g_Minter->ToMempool(::ChainActive().Tip());

    std::unique_ptr<CBlockTemplate> pblocktemplate =
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey);


    BOOST_CHECK(pblocktemplate->block.vtx[1]->GetId() == mediumFeeTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[2]->GetId() == parentTxId);
    BOOST_CHECK(pblocktemplate->block.vtx[3]->GetId() == highFeeTxId);

    // Test that a tranactions with ancestor below the block min tx fee doesn't get included
    tx.vin[0].prevout = COutPoint(highFeeTxId, 0);
    // 0 fee.
    tx.vout[0].nValue = int64_t(100000000LL - 1000 - 50000) * SATOSHI;
    TxId freeTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(Amount::zero()).FromTx(tx));

    // Add a child transaction with high fee.
    Amount feeToUse = 50000 * SATOSHI;

    tx.vin[0].prevout = COutPoint(freeTxId, 0);
    tx.vout[0].nValue =
        int64_t(100000000LL - 1000 - 50000) * SATOSHI - feeToUse;
    TxId highFeeDecendantTxId = tx.GetId();
    g_mempool.addUnchecked(entry.Fee(feeToUse).FromTx(tx));

    g_Minter->ToMempool(::ChainActive().Tip());

    pblocktemplate =
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey);

    // Verify that the free tx and its high fee descendant tx didn't get selected.
    for (const auto &txn : pblocktemplate->block.vtx) {
        BOOST_CHECK(txn->GetId() != freeTxId);
        BOOST_CHECK(txn->GetId() != highFeeDecendantTxId);
    }
}

void TestCoinbaseMessageEB(uint64_t eb, const std::string &cbmsg) {
    GlobalConfig config;
    config.SetExcessiveBlockSize(eb);

    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;

    g_Minter->ToMempool(::ChainActive().Tip());
    std::unique_ptr<CBlockTemplate> pblocktemplate =
        BlockAssembler(config, g_mempool).CreateNewBlock(scriptPubKey);

    CBlock *pblock = &pblocktemplate->block;

    // IncrementExtraNonce creates a valid coinbase and merkleRoot
    if (config.GetChainParams().GetConsensus().IsZenitNet()) {
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    } else {
        unsigned int extraNonce = 0;
        IncrementExtraNonce(pblock, ::ChainActive().Tip(), config.GetExcessiveBlockSize(),
                        extraNonce);
    }
    unsigned int nHeight = ::ChainActive().Tip()->nHeight + 1;
    //std::vector<uint8_t> vec(cbmsg.begin(), cbmsg.end());
    BOOST_CHECK(pblock->vtx[0]->vin[0].scriptSig == (CScript() << ScriptInt::fromIntUnchecked(nHeight)));
    //Zeniq: just nHeight (BIP34Height), but no extraNonce and vec=EBx.y in coinbase
}

// Coinbase scriptSig has to contains the correct EB value
// converted to MB, rounded down to the first decimal
BOOST_AUTO_TEST_CASE(CheckCoinbase_EB) {
    TestCoinbaseMessageEB(1000001, "/EB1.0/");
    TestCoinbaseMessageEB(2000000, "/EB2.0/");
    TestCoinbaseMessageEB(8000000, "/EB8.0/");
    TestCoinbaseMessageEB(8320000, "/EB8.3/");
}

void dma_wrong_dma_in_coinbase(CScript &scriptPubKey) {
    g_mempool.clear();
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    g_Minter->ToMempool(::ChainActive().Tip());
    std::unique_ptr<CBlockTemplate> pblocktemplate = AssemblerForTest(
            chainparams, g_mempool).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(!t_NewBlock.TooLowMinterCount(&pblocktemplate->block));
    CBlock *pblock = &pblocktemplate->block;
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    //while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, chainparams.GetConsensus())){
    //    ++pblock->nNonce;
    //}
    pblock->nNonce = 69935475;
    std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
    MinterBucket_ReturnValueForTest = false;
    BOOST_CHECK(!ProcessNewBlock(config, shared_pblock, true, nullptr));
    MinterBucket_ReturnValueForTest = true;
    BOOST_CHECK(ProcessNewBlock(config, shared_pblock, true, nullptr));
}


void dma_nominter_tests(int delta_nomintertime, CScript &scriptPubKey, int CNT=MAX_COUNTER_NOMINTER) {
    g_mempool.clear();
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    auto mt = t_NewBlock.LastOkTime();
    auto tip = ChainActive().Tip();
    bool useprevioustip = false;
    for (int i=1; i<=CNT; ++i) {
         SetMockTime(mt + i*delta_nomintertime);
         //no DMAtoMempool() => simulate no DMA's
         std::unique_ptr<CBlockTemplate> pblocktemplate = AssemblerForTest(
                 chainparams, g_mempool).CreateNewBlock(scriptPubKey);
         BOOST_CHECK(t_NewBlock.TooLowMinterCount(&pblocktemplate->block));
         if (!useprevioustip) {
             useprevioustip = t_NewBlock.UsedPreviousTip() &&
                       NewBlock::UsePreviousTip(::ChainActive().Tip());
             if (useprevioustip){
                 BOOST_CHECK(t_NewBlock.UsedPreviousTip() == tip);
             }
         }
    }
    if (delta_nomintertime < NOMINTER_START_TIME) {
        if (CNT > NOMINTER_START_TIME + MAX_COUNTER_NOMINTER){
            BOOST_CHECK(useprevioustip);
        } else {
            BOOST_CHECK(!useprevioustip);
        }
    } else {
         BOOST_CHECK(useprevioustip);
    }
}


// NOTE: These tests rely on CreateNewBlock doing its own self-validation!
BOOST_AUTO_TEST_CASE(CreateNewBlock_validity) {
    // Note that by default, these tests run with size accounting enabled.
    GlobalConfig config;
    const CChainParams &chainparams = config.GetChainParams();
    auto params = chainparams.GetConsensus();
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    CMutableTransaction tx;
    CScript script;
    TestMemPoolEntryHelper entry;
    entry.nFee = 11 * SATOSHI;

    fCheckpointsEnabled = false;

    // Simple block creation, nothing special yet:
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    // We can't make transactions until we have inputs.
    // Therefore, load 100 blocks :)
    int baseheight = 0;
    std::vector<CTransactionRef> txFirst;
    for (size_t i = 0; i < NBLOCKINFO; ++i) {
        // pointer for convenience.
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            pblock->nVersion = ComputeBlockVersion(::ChainActive().Tip(),params);
            pblock->nTime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            int height = i+1;
            txCoinbase.vin[0].scriptSig = CScript() << ScriptInt::fromIntUnchecked(height); //BIP34Height
            txCoinbase.vout.resize(1);
            txCoinbase.vout[0].scriptPubKey = CScript();

            g_Minter->ToMempool(::ChainActive().Tip());
            g_Minter->ToCoinbase(
                    txCoinbase,height,&g_mempool,pblock->hashPrevBlock,
                    pblock, Amount::zero(), chainparams.GetConsensus());

            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            if (txFirst.size() == 0) {
                baseheight = ::ChainActive().Height();
            }
            if (txFirst.size() < 4) {
                txFirst.push_back(pblock->vtx[0]);
            }
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->nNonce = blockinfo_nonce[i];
            // // Zeniq to recalc the nonces to meet pow                                                      //pow 
            // while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, chainparams.GetConsensus())){       //pow 
            //     ++pblock->nNonce;                                                                          //pow 
            // }                                                                                              //pow 
            // std::ofstream log("block_nonce.txt", std::ios_base::app | std::ios_base::out);                 //pow 
            // log << pblock->nNonce << " " << pblock->hashPrevBlock << std::endl;                            //pow 
        }
        std::shared_ptr<const CBlock> shared_pblock =
            std::make_shared<const CBlock>(*pblock);
        BOOST_CHECK(ProcessNewBlock(config, shared_pblock, true, nullptr));
        pblock->hashPrevBlock = pblock->GetHash();
    }

    {
    LOCK(cs_main);
    LOCK(::g_mempool.cs);

    // Just to make sure we can still make simple blocks.
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    const Amount BLOCKSUBSIDY = 100 * COIN;
    const Amount LOWFEE = CENT;
    const Amount HIGHFEE = COIN;
    const Amount HIGHERFEE = 4 * COIN;

    // block size > limit
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript();
    // 18 * (520char + DROP) + OP_1 = 9433 bytes
    std::vector<uint8_t> vchData(520);
    for (unsigned int i = 0; i < 18; ++i) {
        tx.vin[0].scriptSig << vchData << OP_DROP;
    }

    tx.vin[0].scriptSig << OP_1;
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 2);
    tx.vout.resize(1);
    tx.vout[0].nValue = BLOCKSUBSIDY;
    for (unsigned int i = 0; i < 128; ++i) {
        tx.vout[0].nValue -= LOWFEE;
        const TxId txid = tx.GetId();
        // Only first tx spends coinbase.
        bool spendsCoinbase = i == 0;
        g_mempool.addUnchecked(entry.Fee(LOWFEE)
                                   .Time(GetTime())
                                   .SpendsCoinbase(spendsCoinbase)
                                   .FromTx(tx));
        tx.vin[0].prevout = COutPoint(txid, 0);
    }

    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    auto g_mempool_reset = [](){
        g_mempool.clear();
        g_Minter->ToMempool(::ChainActive().Tip());
    };

    g_mempool_reset();

    // Orphan in mempool, template creation fails.
    g_mempool.addUnchecked(entry.Fee(LOWFEE).Time(GetTime()).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));

    g_mempool_reset();

    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 2);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript();
    assert(g_Minter->SignPayFromMinter(*txFirst[1],tx,0));
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    g_mempool_reset();

    // Child with higher priority than parent.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 2);
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript();
    TxId txid = tx.GetId();
    assert(g_Minter->SignPayFromMinter(*txFirst[1],tx,0));
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript() << OP_1; // this works when scriptPubKey=CScript()
    tx.vin.resize(2);
    tx.vin[1].prevout = COutPoint(txFirst[2]->GetId(), 2);
    // First txn output + fresh coinbase - new txn fee.
    tx.vout[0].nValue = tx.vout[0].nValue + BLOCKSUBSIDY - HIGHERFEE;
    tx.vout[0].scriptPubKey = CScript();
    txid = tx.GetId();
    assert(g_Minter->SignPayFromMinter(*txFirst[2],tx,1));
    g_mempool.addUnchecked(
        entry.Fee(HIGHERFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    g_mempool_reset();

    // Coinbase in mempool, template creation fails.
    tx.vin.resize(1);
    tx.vin[0].prevout = COutPoint();
    tx.vin[0].scriptSig = CScript()<<OP_0<<OP_1<<OP_1<<OP_1<<OP_1; //else bad-txns-undersize
    tx.vout[0].nValue = Amount::zero();
    txid = tx.GetId();
    // Give it a fee so it'll get mined.
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw bad-tx-coinbase
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-tx-coinbase"));

    g_mempool_reset();

    // Double spend txn pair in mempool, template creation fails.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 2);
    tx.vin[0].scriptSig = CScript()<<OP_1<<OP_1<<OP_1<<OP_1<<OP_1; //else bad-txns-undersize
    tx.vout[0].nValue = BLOCKSUBSIDY - HIGHFEE;//Amount::zero();//BLOCKSUBSIDY - HIGHFEE;//else bad-txns-in-belowout
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vout[0].scriptPubKey = CScript() << OP_2;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("bad-txns-inputs-missingorspent"));

    g_mempool_reset();

    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = Amount::zero(); //BLOCKSUBSIDY - LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(script));
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript()
                          << std::vector<uint8_t>(script.begin(), script.end());
    tx.vout[0].nValue = Amount::zero(); //-= LOWFEE;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw blk-bad-inputs
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("blk-bad-inputs"));

    g_mempool_reset();

    // Subsidy changing.
    int nHeight = ::ChainActive().Height();
    // Create an actual 209999-long block chain (without valid blocks).
    while (::ChainActive().Tip()->nHeight < 209999) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }
    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    // Extend to a 210000-long block chain.
    while (::ChainActive().Tip()->nHeight < 210000) {
        CBlockIndex *prev = ::ChainActive().Tip();
        CBlockIndex *next = new CBlockIndex();
        next->phashBlock = new BlockHash(InsecureRand256());
        pcoinsTip->SetBestBlock(next->GetBlockHash());
        next->pprev = prev;
        next->nHeight = prev->nHeight + 1;
        next->BuildSkip();
        ::ChainActive().SetTip(next);
    }

    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));

    g_Minter->ToMempool(::ChainActive().Tip());
    // Invalid p2sh txn in mempool, template creation fails
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript() << OP_1;
    tx.vout[0].nValue = Amount::zero(); //BLOCKSUBSIDY - LOWFEE;
    script = CScript() << OP_0;
    tx.vout[0].scriptPubKey = GetScriptForDestination(CScriptID(script));
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));
    tx.vin[0].prevout = COutPoint(txid, 0);
    tx.vin[0].scriptSig = CScript()
                          << std::vector<uint8_t>(script.begin(), script.end());
    tx.vout[0].nValue = Amount::zero(); //-= LOWFEE;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(LOWFEE).Time(GetTime()).SpendsCoinbase(false).FromTx(tx));
    // Should throw blk-bad-inputs
    BOOST_CHECK_EXCEPTION(
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey),
        std::runtime_error, HasReason("not-enough-minters"));

    g_mempool_reset();

    // Delete the dummy blocks again.
    while (::ChainActive().Tip()->nHeight > nHeight) {
        CBlockIndex *del = ::ChainActive().Tip();
        ::ChainActive().SetTip(del->pprev);
        pcoinsTip->SetBestBlock(del->pprev->GetBlockHash());
        delete del->phashBlock;
        delete del;
    }

    // non-final txs in mempool
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);
    uint32_t flags = LOCKTIME_VERIFY_SEQUENCE | LOCKTIME_MEDIAN_TIME_PAST;
    // height map
    std::vector<int> prevheights;

    // Relative height locked.
    tx.nVersion = 2;
    tx.vin.resize(1);
    prevheights.resize(1);
    // Only 1 transaction.
    tx.vin[0].prevout = COutPoint(txFirst[0]->GetId(), 0);
    tx.vin[0].scriptSig = CScript()<<OP_1<<OP_1<<OP_1<<OP_1<<OP_1; //else bad-txns-undersize
    // txFirst[0] is the 2nd block
    tx.vin[0].nSequence = ::ChainActive().Tip()->nHeight + 1;
    prevheights[0] = baseheight + 1;
    tx.vout.resize(1);
    tx.vout[0].nValue = Amount::zero();//BLOCKSUBSIDY - HIGHFEE;
    tx.vout[0].scriptPubKey = CScript() << OP_1;
    tx.nLockTime = 0;
    txid = tx.GetId();
    g_mempool.addUnchecked(
        entry.Fee(HIGHFEE).Time(GetTime()).SpendsCoinbase(true).FromTx(tx));

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    // Sequence locks pass on 2nd block.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, &prevheights,
                      *CreateBlockIndex(::ChainActive().Tip()->nHeight + 2)));

    // Relative time locked.
    tx.vin[0].prevout = COutPoint(txFirst[1]->GetId(), 2);
    // txFirst[1] is the 3rd block.
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG |
                          (((::ChainActive().Tip()->GetMedianTimePast() + 1 -
                             ::ChainActive()[1]->GetMedianTimePast()) >>
                            CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) +
                           1);
    prevheights[0] = baseheight + 2;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Trick the MedianTimePast.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime += 512;
    }
    // Sequence locks pass 512 seconds later.
    BOOST_CHECK(
        SequenceLocks(CTransaction(tx), flags, &prevheights,
                      *CreateBlockIndex(::ChainActive().Tip()->nHeight + 1)));
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Undo tricked MTP.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime -= 512;
    }

    // Absolute height locked.
    tx.vin[0].prevout = COutPoint(txFirst[2]->GetId(), 0);
    tx.vin[0].nSequence = CTxIn::SEQUENCE_FINAL - 1;
    prevheights[0] = baseheight + 3;
    tx.nLockTime = ::ChainActive().Tip()->nHeight + 1;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes on 2nd block.
        CValidationState state;
        int64_t nMedianTimePast = ::ChainActive().Tip()->GetMedianTimePast();
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 2,
            nMedianTimePast, nMedianTimePast));
    }

    // Absolute time locked.
    tx.vin[0].prevout = COutPoint(txFirst[3]->GetId(), 0);
    tx.nLockTime = ::ChainActive().Tip()->GetMedianTimePast();
    prevheights.resize(1);
    prevheights[0] = baseheight + 4;
    txid = tx.GetId();
    g_mempool.addUnchecked(entry.Time(GetTime()).FromTx(tx));

    {
        // Locktime fails.
        CValidationState state;
        BOOST_CHECK(!ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-nonfinal");
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));

    {
        // Locktime passes 1 second later.
        CValidationState state;
        int64_t nMedianTimePast =
            ::ChainActive().Tip()->GetMedianTimePast() + 1;
        BOOST_CHECK(ContextualCheckTransaction(
            params, CTransaction(tx), state, ::ChainActive().Tip()->nHeight + 1,
            nMedianTimePast, nMedianTimePast));
    }

    // mempool-dependent transactions (not added)
    tx.vin[0].prevout = COutPoint(txid, 0);
    prevheights[0] = ::ChainActive().Tip()->nHeight + 1;
    tx.nLockTime = 0;
    tx.vin[0].nSequence = 0;

    {
        // Locktime passes.
        CValidationState state;
        BOOST_CHECK(ContextualCheckTransactionForCurrentBlock(
            params, CTransaction(tx), state, flags));
    }

    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
    // Sequence locks pass.
    BOOST_CHECK(TestSequenceLocks(CTransaction(tx), flags));
    tx.vin[0].nSequence = CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
    // Sequence locks fail.
    BOOST_CHECK(!TestSequenceLocks(CTransaction(tx), flags));

    pblocktemplate =
        AssemblerForTest(chainparams, g_mempool).CreateNewBlock(scriptPubKey);
    BOOST_CHECK(pblocktemplate);

    // None of the of the absolute height/time locked tx should have made it
    // into the template because we still check IsFinalTx in CreateNewBlock, but
    // relative locked txs will if inconsistently added to g_mempool. For now
    // these will still generate a valid template until BIP68 soft fork.
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 3UL);
    // However if we advance height by 1 and time by 512, all of them should be
    // mined.
    for (int i = 0; i < CBlockIndex::nMedianTimeSpan; i++) {
        // Trick the MedianTimePast.
        ::ChainActive()
            .Tip()
            ->GetAncestor(::ChainActive().Tip()->nHeight - i)
            ->nTime += 512;
    }
    ::ChainActive().Tip()->nHeight++;
    SetMockTime(::ChainActive().Tip()->GetMedianTimePast() + 1);

    BOOST_CHECK(pblocktemplate = AssemblerForTest(chainparams, g_mempool)
                                     .CreateNewBlock(scriptPubKey));
    BOOST_CHECK_EQUAL(pblocktemplate->block.vtx.size(), 5UL);

    ::ChainActive().Tip()->nHeight--;
    SetMockTime(0);

    g_mempool_reset();

    TestPackageSelection(chainparams, scriptPubKey, txFirst);

    fCheckpointsEnabled = true;

    // > NOMINTER_START_TIME => count counterNoMinter
    dma_nominter_tests(NOMINTER_START_TIME + 1, scriptPubKey);
    // < NOMINTER_START_TIME => reset counterNoMinter each CreateNewBlock
    dma_nominter_tests(1, scriptPubKey);
    // < X times => counts after NOMINTER_START_TIME
    dma_nominter_tests(1, scriptPubKey, NOMINTER_START_TIME+MAX_COUNTER_NOMINTER);
    // > X times => count after NOMINTER_START_TIME
    dma_nominter_tests(1, scriptPubKey, NOMINTER_START_TIME+MAX_COUNTER_NOMINTER+1);
    } //relase cs_main

    // check that Minter::CheckCoinbase is called 13673563
    dma_wrong_dma_in_coinbase(scriptPubKey);
}

void CheckBlockMaxSize(Config &config, uint64_t size, uint64_t expected) {
    BOOST_CHECK(config.SetGeneratedBlockSize(size));

    BlockAssembler ba(config, g_mempool);
    BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), expected);
}

BOOST_AUTO_TEST_CASE(BlockAssembler_construction) {
    GlobalConfig config;

    // check that generated block size can never exceed excessive block size
    {
        BOOST_CHECK_LE(config.GetGeneratedBlockSize(), config.GetExcessiveBlockSize());
        const size_t prevVal = config.GetGeneratedBlockSize(),
                     badVal = config.GetExcessiveBlockSize() + 1;
        BOOST_CHECK_NE(prevVal, badVal); // ensure not equal for thoroughness
        // try and set generated block size beyond the excessive block size (should fail)
        BOOST_CHECK(!config.SetGeneratedBlockSize(badVal));
        // check that the failure really did not set the value
        BOOST_CHECK_EQUAL(config.GetGeneratedBlockSize(), prevVal);
    }

    // We are working on a fake chain and need to protect ourselves.
    LOCK(cs_main);

    // Test around historical 1MB (plus one byte because that's mandatory)
    config.SetExcessiveBlockSize(ONE_MEGABYTE + 1);
    CheckBlockMaxSize(config, 0, 1000);
    CheckBlockMaxSize(config, 1000, 1000);
    CheckBlockMaxSize(config, 1001, 1001);
    CheckBlockMaxSize(config, 12345, 12345);

    CheckBlockMaxSize(config, ONE_MEGABYTE - 1001, ONE_MEGABYTE - 1001);
    CheckBlockMaxSize(config, ONE_MEGABYTE - 1000, ONE_MEGABYTE - 1000);
    CheckBlockMaxSize(config, ONE_MEGABYTE - 999, ONE_MEGABYTE - 999);
    CheckBlockMaxSize(config, ONE_MEGABYTE, ONE_MEGABYTE - 999);

    // Test around default cap
    config.SetExcessiveBlockSize(DEFAULT_EXCESSIVE_BLOCK_SIZE);

    // Now we can use the default max block size.
    CheckBlockMaxSize(config, DEFAULT_EXCESSIVE_BLOCK_SIZE - 1001,
                      DEFAULT_EXCESSIVE_BLOCK_SIZE - 1001);
    CheckBlockMaxSize(config, DEFAULT_EXCESSIVE_BLOCK_SIZE - 1000,
                      DEFAULT_EXCESSIVE_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, DEFAULT_EXCESSIVE_BLOCK_SIZE - 999,
                      DEFAULT_EXCESSIVE_BLOCK_SIZE - 1000);
    CheckBlockMaxSize(config, DEFAULT_EXCESSIVE_BLOCK_SIZE,
                      DEFAULT_EXCESSIVE_BLOCK_SIZE - 1000);

    // NB: If the generated block size parameter is not specified, the config object just defaults it to the excessive
    // block size. But in that case the BlockAssembler ends up unconditionally reserving 1000 bytes of space for the
    // coinbase tx.
    constexpr size_t hardCodedCoinbaseReserved = 1000;
    {
        GlobalConfig freshConfig;
        BlockAssembler ba(freshConfig, g_mempool);
        BOOST_CHECK_EQUAL(ba.GetMaxGeneratedBlockSize(), freshConfig.GetExcessiveBlockSize() - hardCodedCoinbaseReserved);

        // next, ensure that invariants are maintained -- setting excessiveblocksize should pull down generatedblocksize
        const auto prevVal = freshConfig.GetGeneratedBlockSize();
        BOOST_CHECK(freshConfig.SetExcessiveBlockSize(prevVal / 2));
        BOOST_CHECK_EQUAL(freshConfig.GetExcessiveBlockSize(), freshConfig.GetGeneratedBlockSize());
        BOOST_CHECK_LT(freshConfig.GetGeneratedBlockSize(), prevVal);
        BlockAssembler ba2(freshConfig, g_mempool);
        BOOST_CHECK_EQUAL(ba2.GetMaxGeneratedBlockSize(), freshConfig.GetExcessiveBlockSize() - hardCodedCoinbaseReserved);
    }
}

BOOST_AUTO_TEST_CASE(TestCBlockTemplateEntry) {
    CTransactionRef txRef = MakeTransactionRef();
    CBlockTemplateEntry txEntry(txRef, 1 * SATOSHI, 10);
    BOOST_CHECK_MESSAGE(txEntry.tx == txRef, "Transactions did not match");
    BOOST_CHECK_EQUAL(txEntry.fees, 1 * SATOSHI);
    BOOST_CHECK_EQUAL(txEntry.sigChecks, 10);
}

BOOST_AUTO_TEST_SUITE_END()
