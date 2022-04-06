#ifndef BITCOIN_CHAINPARAMSCONSTANTS_H
#define BITCOIN_CHAINPARAMSCONSTANTS_H
/**
 * Chain params constants for each tracked chain.
 * @generated by contrib/devtools/chainparams/generate_chainparams_constants.py
 */

#include <primitives/blockhash.h>
#include <uint256.h>

namespace ChainParamsConstants {
    const BlockHash ZENIQ_DEFAULT_ASSUME_VALID = BlockHash::fromHex("000000000000000000e7f24c197edd6de599d77fc837f630b6f4c6259dfeb4dd");
    const uint256 ZENIQ_MINIMUM_CHAIN_WORK = uint256S("0000000000000000000000000000000000000000000000000000000000000000");
} // namespace ChainParamsConstants

#endif // BITCOIN_CHAINPARAMSCONSTANTS_H
