// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2018-2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for block-chain checkpoints
//

#include <checkpoints.h>

#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/validation.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>
#include <miner.h>
#include <dma.h>
#include <consensus/merkle.h>
#include <pow.h>

#include <test/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <memory>

BOOST_FIXTURE_TEST_SUITE(checkpoints_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(sanity) {
    const auto params = CreateChainParams(CBaseChainParams::ZENIQ);
    const CCheckpointData &checkpoints = params->Checkpoints();
    BlockHash p11 = BlockHash::fromHex(
        "0000002f3bebf24a0c9cb510cfead38f250bd6cf12e232cb9a86dfc8631fe43f");
    BlockHash p333 = BlockHash::fromHex(
        "0000000f503458e8632e4189686f98666071a7efec085abb7a87f5619e3f6810");
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 11, p11));
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 333, p333));

    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckBlock(checkpoints, 11, p333));
    BOOST_CHECK(!Checkpoints::CheckBlock(checkpoints, 333, p11));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 11 + 1, p333));
    BOOST_CHECK(Checkpoints::CheckBlock(checkpoints, 333 + 1, p11));
}

BOOST_AUTO_TEST_CASE(ban_fork_at_genesis_block) {
    DummyConfig config;

    // Sanity check that a checkpoint exists at the genesis block
    auto &checkpoints = config.GetChainParams().Checkpoints().mapCheckpoints;
    assert(checkpoints.find(0) != checkpoints.end());

    // Another precomputed genesis block (with differing nTime) should conflict
    // with the regnet genesis block checkpoint and not be accepted or stored
    // in memory.
    CBlockHeader header =
        CreateGenesisBlock(1296688603, 2, 0x207fffff, 1, 50 * COIN);

    // Header should not be accepted
    CValidationState state;
    CBlockHeader invalid;
    const CBlockIndex *pindex = nullptr;
    BOOST_CHECK(
        !ProcessNewBlockHeaders(config, {header}, state, &pindex, &invalid));
    BOOST_CHECK(state.IsInvalid());
    BOOST_CHECK(pindex == nullptr);
    BOOST_CHECK(invalid.GetHash() == header.GetHash());

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(header.GetHash()) == nullptr);
    }
}

class ChainParamsWithCheckpoints : public CChainParams {
public:
    ChainParamsWithCheckpoints(const CChainParams &chainParams,
                               CCheckpointData &checkpoints)
        : CChainParams(chainParams) {
        checkpointData = checkpoints;
    }
};

class ConfigWithTestCheckpoints : public DummyConfig {
public:
    ConfigWithTestCheckpoints() : DummyConfig(createChainParams()) {}

    static std::unique_ptr<CChainParams> createChainParams() {
        CCheckpointData checkpoints = {
           /* .mapCheckpoints = */ {

        {2, BlockHash::fromHex("0000002467f7a9aa476f91e54743b9d8a5e016c85b534b54990a8ad52ad42c26")},
        }};
        const auto mainParams = CreateChainParams(CBaseChainParams::ZENIQ);
        return std::make_unique<ChainParamsWithCheckpoints>(*mainParams,
                                                            checkpoints);
    }
};

/**
 * This test has 4 precomputed blocks mined ontop of the genesis block:
 *  G ---> A ---> AA (checkpointed)
 *   \       \
 *    \--> B  \-> AB
 * After the node has accepted only A and AA, these rejects should occur:
 *  * B should be rejected for forking prior to an accepted checkpoint
 *  * AB should be rejected for forking at an accepted checkpoint
 */
BOOST_AUTO_TEST_CASE(ban_fork_prior_to_and_at_checkpoints) {
    ConfigWithTestCheckpoints config;

    CBlockHeader invalid;
    const CBlockIndex *pindex = nullptr;

    // Start with genesis block
    CBlockHeader headerG = config.GetChainParams().GenesisBlock();
    BOOST_CHECK(headerG.GetHash() ==
        uint256S("000000069ce255960540dc393edbf3bb4ba195d24ebd07e32694f80d3d2206ff"));

    {
        CValidationState state;
        BOOST_CHECK(ProcessNewBlockHeaders(config, {headerG}, state, &pindex,
                                           &invalid));
        pindex = nullptr;
    }

    /*
    // this code created the hex for the block headers
    size_t i = 0;
    CScript scriptPubKey =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    static CFeeRate blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE_PER_KB);
    static BlockAssembler::Options options;
    options.blockMinFeeRate = blockMinFeeRate;
    auto chainparams = config.GetChainParams();
    auto params = chainparams.GetConsensus();
    auto starttime = ::ChainActive().Tip()->GetMedianTimePast() + 1;
    auto createHeaderStream = [&](BlockHash hashPrevBlock){
        if (params.IsZenitNet()) {
            g_Minter->ToMempool(::ChainActive().Tip());
        }
        pblocktemplate = BlockAssembler(chainparams, g_mempool, options).
            CreateNewBlock(scriptPubKey);
        CBlock *pblock = &pblocktemplate->block;
        {
            LOCK(cs_main);
            pblock->nVersion = ComputeBlockVersion(::ChainActive().Tip(),params);
            pblock->nTime = starttime+i+1;
            pblock->hashPrevBlock = hashPrevBlock;
            CMutableTransaction txCoinbase(*pblock->vtx[0]);
            txCoinbase.nVersion = 1;
            txCoinbase.vin[0].scriptSig = CScript() << (i+1); //BIP34Height
            txCoinbase.vout.resize(1);
            txCoinbase.vout[0].scriptPubKey = CScript();
            uint64_t coinbaseSize = ::GetSerializeSize(txCoinbase, PROTOCOL_VERSION);
            if (coinbaseSize < MIN_TX_SIZE) {
                txCoinbase.vin[0].scriptSig << std::vector<uint8_t>(MIN_TX_SIZE - coinbaseSize - 1);
            }
            if (params.IsZenitNet()) {
                pblock->EncodeMinterCount(txCoinbase.vout.size());
            }
            pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            while (!CheckProofOfWork(pblock->GetHash(), pblock->nBits, params)){
                ++pblock->nNonce;
            }
        }
        ProcessNewBlock(config, std::make_shared<const CBlock>(*pblock), true, nullptr);
        ++i;
        CBlockHeader header = pblock->GetBlockHeader();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << header;
        std::string hex = HexStr(ss.begin(),ss.end());
        return CDataStream(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
    };
    */

    CBlockHeader headerA, headerB, headerAA, headerAB;
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);

    //stream = createHeaderStream(headerG.GetHash());
    stream = CDataStream(
        ParseHex(
"01000020ff06223d0df89426e307bd4ed295a14bbbf3db3e39dc40059655e29c060000005e5ef8b39c17d2a8d05a28917f60e0095dd424cc8a531e1a0963b8c11268914b029d405effff001e733a5200"
        ),
        SER_NETWORK, PROTOCOL_VERSION);

    stream >> headerA;
    BOOST_CHECK(headerA.GetHash() ==
        uint256S("0000001ce930bdf6655905e6aee7e98e99fe4c25d64ba9b1a8718afc4074a224"));
    BOOST_CHECK(headerA.hashPrevBlock == headerG.GetHash());

    //stream = createHeaderStream(headerA.GetHash());
    stream = CDataStream(
        ParseHex(
"0100002024a27440fc8a71a8b1a94bd6254cfe998ee9e7aee6055965f6bd30e91c000000970d8020ded90820f5af584e0ff4e41f3a18e6036b23629aee8ceafc5e9ec62b039d405effff001e4f466701"
            ),
        SER_NETWORK, PROTOCOL_VERSION);

    stream >> headerAA;
    BOOST_CHECK(headerAA.GetHash() ==
            uint256S("0000002467f7a9aa476f91e54743b9d8a5e016c85b534b54990a8ad52ad42c26"));
    BOOST_CHECK(headerAA.hashPrevBlock == headerA.GetHash());

    //stream = createHeaderStream(headerG.GetHash());
    stream = CDataStream(
        ParseHex(
"01000020ff06223d0df89426e307bd4ed295a14bbbf3db3e39dc40059655e29c06000000e00627dd684a53a6b5f532a44103cae9a8d796666debcb2ef333dde9512d02c4049d405effff001eb8638d00"
            ),
        SER_NETWORK, PROTOCOL_VERSION);

    stream >> headerB;
    BOOST_CHECK(headerB.hashPrevBlock == headerG.GetHash());

    //stream = createHeaderStream(headerA.GetHash());
    stream = CDataStream(
        ParseHex(
"0100002024a27440fc8a71a8b1a94bd6254cfe998ee9e7aee6055965f6bd30e91c000000297c101bbde37a02c0fc41503737fdbcec65af2046ea8cf677c7d9edbcfd8e3e059d405effff001ed05d2700"
            ),
        SER_NETWORK, PROTOCOL_VERSION);

    stream >> headerAB;
    BOOST_CHECK(headerAB.hashPrevBlock == headerA.GetHash());

    // Headers A and AA should be accepted
    {
        CValidationState state;
        BOOST_CHECK(ProcessNewBlockHeaders(config, {headerA}, state, &pindex,
                                           &invalid));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
        BOOST_CHECK(invalid.IsNull());
    }

    {
        CValidationState state;
        BOOST_CHECK(ProcessNewBlockHeaders(config, {headerAA}, state, &pindex,
                                           &invalid));
        BOOST_CHECK(state.IsValid());
        BOOST_CHECK(pindex != nullptr);
        pindex = nullptr;
        BOOST_CHECK(invalid.IsNull());
    }

    // Header B should be rejected
    {
        CValidationState state;
        BOOST_CHECK(!ProcessNewBlockHeaders(config, {headerB}, state, &pindex,
                                            &invalid));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectCode() == REJECT_CHECKPOINT);
        BOOST_CHECK(state.GetRejectReason() == "bad-fork-prior-to-checkpoint");
        BOOST_CHECK(pindex == nullptr);
        BOOST_CHECK(invalid.GetHash() == headerB.GetHash());
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(headerB.GetHash()) == nullptr);
    }

    // Header AB should be rejected
    {
        CValidationState state;
        BOOST_CHECK(!ProcessNewBlockHeaders(config, {headerAB}, state, &pindex,
                                            &invalid));
        BOOST_CHECK(state.IsInvalid());
        BOOST_CHECK(state.GetRejectCode() == REJECT_CHECKPOINT);
        BOOST_CHECK(state.GetRejectReason() == "checkpoint mismatch");
        BOOST_CHECK(pindex == nullptr);
        BOOST_CHECK(invalid.GetHash() == headerAB.GetHash());
    }

    // Sanity check to ensure header was not saved in memory
    {
        LOCK(cs_main);
        BOOST_CHECK(LookupBlockIndex(headerAB.GetHash()) == nullptr);
    }
}

BOOST_AUTO_TEST_SUITE_END()
