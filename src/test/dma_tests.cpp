// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <util/system.h>
#include <util/strencodings.h>
#include <uint256.h>
#include <pubkey.h>
#include <script/scriptcache.h>
#include <script/sigcache.h>
#include <miner.h>
#include <pow.h>
#include <validation.h>
#include <wallet/wallet.h>

#include <dma.h>

#include <test/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <memory>

#ifdef DMA_TESTING // assures defined else compile error
static uint8_t dmaData[] {
     0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
     , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0
};
static std::vector<std::string> mintingKeys;
#endif

class DMATestSetup : public TestChain100Setup {
public:
    DMATestSetup() : TestChain100Setup() {
        m_wallet  = std::make_shared<CWallet>(
                Params(), *m_chain, WalletLocation(),
                WalletDatabase::CreateMock());
        SelectParams(CBaseChainParams::ZENIQ);
        Minter::Exit();
        bool fFirstRun;
        m_wallet->LoadWallet(fFirstRun);
        RegisterValidationInterface(m_wallet.get());
        AddWallet(m_wallet);
        mintingKeys.clear();
        for (size_t i = 0; i < sizeof(dmaData); i += sizeof(uint160)) {
            CKey privTest;
            privTest.MakeNewKey(true);
            auto b = privTest.GetPubKey().GetID().begin();
            std::reverse_copy(b, b + sizeof(CKeyID), dmaData+i);
            mintingKeys.push_back(EncodeSecret(privTest));
        }
        g_Minter = Minter::Create(mintingKeys, dmaData, dmaData + sizeof(dmaData));
    }
    ~DMATestSetup() {
        UnregisterValidationInterface(m_wallet.get());
    }
    std::unique_ptr<interfaces::Chain> m_chain = interfaces::MakeChain();
    std::shared_ptr<CWallet> m_wallet;
};

BOOST_FIXTURE_TEST_SUITE(dma_tests, DMATestSetup)

BOOST_AUTO_TEST_CASE(DMAIndexTest) {
    Minter::Exit();
    BOOST_CHECK(g_Minter == nullptr);
    std::vector<std::string> wrongMintersHere{
        "M9qqUGNW9v1SoAB5LYNT151XRwyuY5hsGB9paXjoX9jKStBevcMz"};
    g_Minter = Minter::Create(wrongMintersHere, dmaData, dmaData + sizeof(dmaData));
    BOOST_CHECK(g_Minter == nullptr);

    int i = 0;
    for (auto pk : mintingKeys) {
        Minter::Exit();
        BOOST_CHECK(g_Minter == nullptr);
        std::vector<std::string> mintersHere = {pk};
        g_Minter = Minter::Create(mintersHere, dmaData, dmaData + sizeof(dmaData));
        BOOST_CHECK(g_Minter != nullptr);
        auto mk = MinterKey(pk,std::string(),*g_Minter);
        BOOST_CHECK(mk.index == i);
        ++i;
    }
}

BOOST_AUTO_TEST_CASE(RemoveDMATest) {
    // Parent transaction with three children, and three grand-children:
    CMutableTransaction txParent;
    txParent.vin.resize(1);
    txParent.vin[0].scriptSig = CScript() << OP_11;
    txParent.vout.resize(3);
    for (int i = 0; i < 3; i++) {
        txParent.vout[i].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txParent.vout[i].nValue = 33000 * SATOSHI;
    }
    CMutableTransaction txChild[3];
    for (int i = 0; i < 3; i++) {
        txChild[i].vin.resize(1);
        txChild[i].vin[0].scriptSig = CScript() << OP_11;
        txChild[i].vin[0].prevout = COutPoint(txParent.GetId(), i);
        txChild[i].vout.resize(1);
        txChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txChild[i].vout[0].nValue = 11000 * SATOSHI;
    }
    CMutableTransaction txGrandChild[3];
    for (int i = 0; i < 3; i++) {
        txGrandChild[i].vin.resize(1);
        txGrandChild[i].vin[0].scriptSig = CScript() << OP_11;
        txGrandChild[i].vin[0].prevout = COutPoint(txChild[i].GetId(), 0);
        txGrandChild[i].vout.resize(1);
        txGrandChild[i].vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
        txGrandChild[i].vout[0].nValue = 11000 * SATOSHI;
    }

    LOCK2(cs_main, g_mempool.cs);

    // N_MINTER_TX_RELAY=3 in bool, older ones removed
    unsigned int poolSize = g_mempool.size(); // 3
    BOOST_CHECK_EQUAL(poolSize, N_MINTER_TX_RELAY);
    // previous RemoveOld() was before m_chain.SetTip()
    // which increased height by 1, so this removes 1 more
    g_Minter->RemoveOld();
    --poolSize;
    g_mempool.removeRecursive(CTransaction(txParent));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize);

    // During CreateAndProcessBlock there was one in minters,
    // from MinterForTest
    // Now there are all from mintingKeys
    g_Minter->ToMempool(::ChainActive().Tip());
    size_t mintingkeysize = mintingKeys.size();
    unsigned int dma_total = mintingkeysize*N_MINTER_TX_RELAY+poolSize;
    BOOST_CHECK_EQUAL(g_mempool.size(), dma_total);
    //removes nothing because height did not changes
    g_Minter->RemoveOld();
    BOOST_CHECK_EQUAL(g_mempool.size(), dma_total);

    // removal of other transactions does not interfere with DMA
    // Just the parent:
    TestMemPoolEntryHelper entry;
    g_mempool.addUnchecked(entry.FromTx(txParent));
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txParent));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize - 1);

    // Parent, children, grandchildren:
    g_mempool.addUnchecked(entry.FromTx(txParent));
    for (int i = 0; i < 3; i++) {
        g_mempool.addUnchecked(entry.FromTx(txChild[i]));
        g_mempool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }
    // Remove Child[0], GrandChild[0] should be removed:
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txChild[0]));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize - 2);
    // ... make sure grandchild and child are gone:
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txGrandChild[0]));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize);
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txChild[0]));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize);
    // Remove parent, all children/grandchildren should go:
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txParent));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize - 5);

    // Add children and grandchildren, but NOT the parent (simulate the parent
    // being in a block)
    for (int i = 0; i < 3; i++) {
        g_mempool.addUnchecked(entry.FromTx(txChild[i]));
        g_mempool.addUnchecked(entry.FromTx(txGrandChild[i]));
    }

    // Now remove the parent, as might happen if a block-re-org occurs but the
    // parent cannot be put into the mempool (maybe because it is non-standard):
    poolSize = g_mempool.size();
    g_mempool.removeRecursive(CTransaction(txParent));
    BOOST_CHECK_EQUAL(g_mempool.size(), poolSize - 6);

    BOOST_CHECK_EQUAL(g_mempool.size(), dma_total);

    // repeatedly adding will REJECT_DUPLICATE locally,
    // but relay for other nodes
    for (int repeat=0; repeat<10; ++repeat) {
        g_Minter->ToMempool(::ChainActive().Tip());
    }

    BOOST_CHECK_EQUAL(g_mempool.size(), dma_total);
}


BOOST_AUTO_TEST_SUITE_END()
