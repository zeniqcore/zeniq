// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsconstants.h>
#include <chainparamsseeds.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <netbase.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <util/system.h>

#include <cassert>
#include <cstring>
#include <memory>
#include <stdexcept>

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << ScriptInt::fromIntUnchecked(486604799)
                  << CScriptNum::fromIntUnchecked(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                          int32_t nVersion, const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}


static CBlock CreateGenesisBlockZeniq(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = // genesis_scriptSig: content irrelevant, but fixed by block hash
            CScript() << CScriptNum::fromIntUnchecked(0)
                      << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                              (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

CBlock CreateGenesisBlockZeniq(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                          int32_t nVersion, const Amount genesisReward) {
    const char *pszTimestamp =
            "Monti: A seamless fiat and crypto ecosystem";
            //goes into genesis_scriptSig and thus no Monti->Zeniq rebranding possible here.
    const CScript genesisOutputScript =
            CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                                  "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                                  "de5c384df7ba0b8d578a4c702b6bf11d5f")
                      << OP_CHECKSIG;

    return CreateGenesisBlockZeniq(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

class CZeniqParams : public CChainParams {
public:
    CZeniqParams() {
        strNetworkID = CBaseChainParams::ZENIQ;

        consensus.powLimit = uint256S(
                "000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nASERTHalfLife = {{12 * 60 * 60, 3 * 60 * 60}};
        consensus.nMinimumChainWork =
            ChainParamsConstants::ZENIQ_MINIMUM_CHAIN_WORK;
        consensus.defaultAssumeValid =
            ChainParamsConstants::ZENIQ_DEFAULT_ASSUME_VALID;
        consensus.axionActivationTime = 1601185936;
        consensus.nDefaultExcessiveBlockSize = DEFAULT_EXCESSIVE_BLOCK_SIZE;
        consensus.nDefaultGeneratedBlockSize = 8 * ONE_MEGABYTE;
        assert(consensus.nDefaultGeneratedBlockSize <= consensus.nDefaultExcessiveBlockSize);
        consensus.asertAnchorParams = Consensus::Params::ASERTAnchor{
            33000,        // anchor block height
            0x1d032f6c ,  // anchor block nBits
            1600975120,   // anchor block previous block timestamp
        };
        diskMagic[0] = 0xf9;
        diskMagic[1] = 0xbe;
        diskMagic[2] = 0xb4;
        diskMagic[3] = 0xd9;
        netMagic[0] = 0xf9;
        netMagic[1] = 0xb3;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xd9;
        nDefaultPort = 18581;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 3;
        m_assumed_chain_state_size = 1;
        genesis = CreateGenesisBlockZeniq(1581292800, 56261201, 0x1e00ffff, 1,
                                     100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("000000069ce255960540dc393edbf3bb4ba195d24ebd07e32694f80d3d2206ff"));
        assert(genesis.hashMerkleRoot ==
               uint256S("f94a7c7cd417bef9d8b77f99efad0753face18c7bda2047363d61bc573420a37"));
        vSeeds.emplace_back("45.77.140.167");
        vSeeds.emplace_back("116.203.76.246");
        vSeeds.emplace_back("5.161.41.244");
        vSeeds.emplace_back("5.161.52.108");
        vSeeds.emplace_back("5.161.57.87");
        vSeeds.emplace_back("5.161.61.129");
        vSeeds.emplace_back("65.21.110.22");
        vSeeds.emplace_back("65.108.89.1");
        vSeeds.emplace_back("65.21.154.185");
        vSeeds.emplace_back("65.21.157.239");
        vSeeds.emplace_back("49.12.216.92");
        vSeeds.emplace_back("65.108.160.38");
        vSeeds.emplace_back("65.108.160.39");
        vSeeds.emplace_back("207.148.95.162");
        vSeeds.emplace_back("158.247.207.167");
        vSeeds.emplace_back("139.180.211.85");
        vSeeds.emplace_back("209.250.241.154");
        vSeeds.emplace_back("45.32.144.143");
        vSeeds.emplace_back("155.138.134.56");
        vSeeds.emplace_back("149.28.175.111");
        vSeeds.emplace_back("216.238.103.102");
        vSeeds.emplace_back("149.28.212.141");
        vSeeds.emplace_back("216.238.79.131");
        base58Prefixes[PUBKEY_ADDRESS] = {0x6e};
        base58Prefixes[SCRIPT_ADDRESS] = {0x6f};
        base58Prefixes[SECRET_KEY] = {0x88};
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xb2, 0x1e};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xad, 0xe4};
        cashaddrPrefix = "zeniq";
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        checkpointData = {
                .mapCheckpoints = {
                        {11,    BlockHash::fromHex("0000002f3bebf24a0c9cb510cfead38f250bd6cf12e232cb9a86dfc8631fe43f")},
                        {333,   BlockHash::fromHex("0000000f503458e8632e4189686f98666071a7efec085abb7a87f5619e3f6810")},
                        {7444,  BlockHash::fromHex("00000005d33cf53bbacca61fde4f1550e18ead749d31091654ca46d991368e52")},
                        {12222, BlockHash::fromHex("0000000053531cb1c58aee7e58f9282600663cc76d236135c80a53538075104f")},
                        {20000, BlockHash::fromHex("00000011d9d6d7b2abe2c23d80cedeaecfa22b1b2bd85d372fd4c022aecb2de9")},
                        {25555, BlockHash::fromHex("000000040b407ecff9584e29db5d0671afc55a760a8edd9ba0e9e6efb2dad1ba")},
                        {30000, BlockHash::fromHex("00000005ab404fbedc2b0ea4a5da17ac670b133a3df055bc71081d4f14a206ad")},
                        {33333, BlockHash::fromHex("00000002838d13299060e25c897c3f83c589f4f02759bd977d7c3dd6cfbb93ef")},
                        {33399, BlockHash::fromHex("00000004054dcee184b79243f26c344dd17ca71c2f426dc6cc32c17647d4d8ab")},
                        {35555, BlockHash::fromHex("00000000190734e511887147bffa22498474cd50047b044cf100d667a7c1a0d3")},
                        {40000, BlockHash::fromHex("0000000231a2d6f14fdbd6b99b700625dc0061fb5b2eb38fa3a2bf9100f5f002")},
                        {45555, BlockHash::fromHex("00000000cf67138c1bad5cdc22080444f28c6da6241568c186155654194664c1")},
                        {50000, BlockHash::fromHex("000000010cd52ab933ff4b77fe007750e0528dd3bc59e1967a6104f38173fe3b")},
                        {54444, BlockHash::fromHex("000000017ab11bc421515c7c2c6aa1d0e43c8b995e70906b5385382459a2ef0d")},
                }};
        chainTxData = ChainTxData{
                1613838853,
                54444,
                1.0 / 600};
    }
};

class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = CBaseChainParams::REGTEST;
        consensus.nSubsidyHalvingInterval = 150;
        // always enforce P2SH BIP16 on regtest
        consensus.BIP16Height = 0;
        // BIP34 has not activated on regtest (far in the future so block v1 are
        // not rejected in tests)
        consensus.BIP34Height = 100000000;
        consensus.BIP34Hash = BlockHash();
        // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP65Height = 1351;
        // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251;
        // CSV activated on regtest (Used in rpc activation tests)
        consensus.CSVHeight = 576;
        consensus.powLimit = uint256S(
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // two weeks
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;

        // The half life for the ASERT DAA. For every (nASERTHalfLife) seconds behind schedule the blockchain gets,
        // difficulty is cut in half. Doubled if blocks are ahead of schedule.
        // Two days. Note regtest has no DAA checks, so this unused parameter is here merely for completeness.
        consensus.nASERTHalfLife = {{2 * 24 * 60 * 60, 2 * 24 * 60 * 60}};

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are
        // valid.
        consensus.defaultAssumeValid = BlockHash();

        // UAHF is always enabled on regtest.
        consensus.uahfHeight = 0;

        // November 13, 2017 hard fork is always on on regtest.
        consensus.daaHeight = 0;

        // November 15, 2018 hard fork is always on on regtest.
        consensus.magneticAnomalyHeight = 0;

        // November 15, 2019 protocol upgrade
        consensus.gravitonHeight = 0;

        // May 15, 2020 12:00:00 UTC protocol upgrade
        consensus.phononHeight = 0;

        // Nov 15, 2020 12:00:00 UTC protocol upgrade
        consensus.axionActivationTime = 1605441600;

        // Default limit for block size (in bytes)
        consensus.nDefaultExcessiveBlockSize = DEFAULT_EXCESSIVE_BLOCK_SIZE;

        // Chain-specific default for mining block size (in bytes) (configurable with -blockmaxsize)
        consensus.nDefaultGeneratedBlockSize = 8 * ONE_MEGABYTE;

        assert(consensus.nDefaultGeneratedBlockSize <= consensus.nDefaultExcessiveBlockSize);

        diskMagic[0] = 0xfa;
        diskMagic[1] = 0xbf;
        diskMagic[2] = 0xb5;
        diskMagic[3] = 0xda;
        netMagic[0] = 0xda;
        netMagic[1] = 0xb5;
        netMagic[2] = 0xbf;
        netMagic[3] = 0xfa;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock ==
               uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b"
                        "1a11466e2206"));
        assert(genesis.hashMerkleRoot ==
               uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab212"
                        "7b7afdeda33b"));

        //! Regtest mode doesn't have any fixed seeds.
        vFixedSeeds.clear();
        //! Regtest mode doesn't have any DNS seeds.
        vSeeds.clear();

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;

        checkpointData = {
            /* .mapCheckpoints = */ {
                {0, BlockHash::fromHex("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb4"
                                       "36012afca590b1a11466e2206")},
            }};

        chainTxData = ChainTxData{0, 0, 0};

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<uint8_t>(1, 111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<uint8_t>(1, 196);
        base58Prefixes[SECRET_KEY] = std::vector<uint8_t>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
        cashaddrPrefix = "bchreg";
    }
};


static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string &chain) {

    if (chain == CBaseChainParams::ZENIQ) {
        return std::make_unique<CZeniqParams>();
    }

    if (chain == CBaseChainParams::REGTEST) {
        return std::make_unique<CRegTestParams>();
    }

    throw std::runtime_error(
        strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string &network) {
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

SeedSpec6::SeedSpec6(const char *pszHostPort)
{
    const CService service = LookupNumeric(pszHostPort, 0);
    if (!service.IsValid() || service.GetPort() == 0)
        throw std::invalid_argument(strprintf("Unable to parse numeric-IP:port pair: %s", pszHostPort));
    if (!service.IsRoutable())
        throw std::invalid_argument(strprintf("Not routable: %s", pszHostPort));
    *this = SeedSpec6(service);
}
