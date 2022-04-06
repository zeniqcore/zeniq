#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Script to generate list of chainparams constants (ie. assumevalid and
minimum chainwork).

This script expects a text file for each chain in the directory that is passed
as an argument:

    chainparams_zeniq.txt

These files must consist of lines in the format

    <assumevalid hash>
    <minimum chainwork>

The outputted constants should be pasted into `src/chainparamsconstants.h`.
'''

import sys
import os


def process_constants(indir, file_name):
    with open(os.path.join(indir, file_name), 'r', encoding="utf8") as f:
        constants = f.readlines()

    # Ensure only two lines are read from the file.
    assert(len(constants) == 2)

    return [line.rstrip() for line in constants]


def main():
    if len(sys.argv) != 2:
        print('Usage: {} <dir_with_chainparams_txt>'.format(
            sys.argv[0]), file=sys.stderr)
        sys.exit(1)

    indir = sys.argv[1]

    print('''\
#ifndef BITCOIN_CHAINPARAMSCONSTANTS_H
#define BITCOIN_CHAINPARAMSCONSTANTS_H
/**
 * Chain params constants for each tracked chain.
 * @{} by contrib/devtools/chainparams/generate_chainparams_constants.py
 */

#include <primitives/blockhash.h>
#include <uint256.h>

namespace ChainParamsConstants {{
    const BlockHash ZENIQ_DEFAULT_ASSUME_VALID = BlockHash::fromHex("{}");
    const uint256 ZENIQ_MINIMUM_CHAIN_WORK = uint256S("{}");
}} // namespace ChainParamsConstants

#endif // BITCOIN_CHAINPARAMSCONSTANTS_H\
'''.format(
        # 'generated' is split out so this file is not identified as generated.
        "generated",
        *process_constants(indir, 'chainparams_zeniq.txt'))
    )


if __name__ == '__main__':
    main()
