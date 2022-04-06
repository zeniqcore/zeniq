// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <primitives/blockhash.h>
#include <uint256.h>

#include <limits>
#include <optional>

#include <array>

namespace Consensus {

#define ZENIQOPALITEHEIGHT 101010

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    BlockHash hashGenesisBlock;
    int nSubsidyHalvingInterval = 210000;

    // Zeniq: adoptation height 1 = for all blocks

    /** Block height at which BIP16 becomes active */
    int BIP16Height = 1;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height = 1;
    BlockHash BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height = 1;
    /** Block height at which BIP66 becomes active */
    int BIP66Height = 1;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight = 1;
    /** Block height at which UAHF kicks in */
    int uahfHeight = 1;
    /** Block height at which the new DAA becomes active */
    int daaHeight = 1;
    /** Block height at which the magnetic anomaly activation becomes active */
    int magneticAnomalyHeight = 111; // due to TestPackageSelection, but for Zeniq = for all blocks
    /** Block height at which the graviton activation becomes active */
    int gravitonHeight = ZENIQOPALITEHEIGHT;
    /** Block height at which the phonon activation becomes active */
    int phononHeight = ZENIQOPALITEHEIGHT;

    /** Zeniq Heights */
    int ZeniqDarkGravityWaveHeight = 3300;
    int ZeniqASERTIntro = 33333; //with respect to 33000 in consensus.asertAnchorParams
    int ZeniqASERTActive = 33399; //with respect to 33000 in consensus.asertAnchorParams
    int ZeniqCheck25Height = 55055;
    int ZeniqCheckMinterDuplicates = 70705;
    int ZeniqMinterCountInVersionHeight = 80000;
    int ZeniqOpaliteHeight = ZENIQOPALITEHEIGHT;

    bool IsZenitNet() const {return BIP66Height == 1;} 

    /** Unix time used for MTP activation of 15 Nov 2020 12:00:00 UTC upgrade */
    int axionActivationTime;

    /** Unix time used for MTP activation, yet unplanned */
    int64_t upgrade8ActivationTime = 4125496720;

    /** Default blocksize limit -- can be overridden with the -excessiveblocksize= command-line switch */
    uint64_t nDefaultExcessiveBlockSize;

    /**
     * Chain-specific default for -blockmaxsize, which controls the maximum size of blocks that the
     * mining code will create.
     */
    uint64_t nDefaultGeneratedBlockSize;


    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    std::array<int64_t,2> nASERTHalfLife;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const {
        return nPowTargetTimespan / nPowTargetSpacing;
    }
    uint256 nMinimumChainWork;
    BlockHash defaultAssumeValid;

    /** Used by the ASERT DAA activated after Nov. 15, 2020 */
    struct ASERTAnchor {
        int nHeight;
        uint32_t nBits;
        int64_t nPrevBlockTime;
    };

    /** For chains with a checkpoint after the ASERT anchor block, this is always defined */
    std::optional<ASERTAnchor> asertAnchorParams;

};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
