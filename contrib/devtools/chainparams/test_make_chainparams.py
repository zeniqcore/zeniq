#!/usr/bin/env python3
# Copyright (c) 2019 The Bitcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import unittest

from make_chainparams import main as GenerateChainParams


class MockRPC:
    def __init__(self, test, chain, numBlocks,
                 expectedBlock, blockHash, chainWork):
        self.test = test
        self.chain = chain
        self.numBlocks = numBlocks
        self.expectedBlock = expectedBlock
        self.blockHash = blockHash
        self.chainWork = chainWork

    def getblockchaininfo(self):
        return {
            "chain": self.chain,
            "blocks": self.numBlocks,
            "headers": self.numBlocks,
            "bestblockhash": "00000000387806a4fedf0ad5fb1eeb498050552f91eff464638ebb58df302580",
            "difficulty": 2.95050069115428,
            "mediantime": 1641995977,
            "verificationprogress": 0.9999834997517191,
            "initialblockdownload": False,
            "chainwork": self.chainWork,
            "size_on_disk": 2402320972,
            "pruned": False,
        }

    def getblockhash(self, block):
        # Tests should always request the right block height. Even though a
        # real node will rarely raise an exception for this call, we are
        # more strict during testing.
        self.test.assertEqual(block, self.expectedBlock, "Called 'getblockhash {}' when expected was 'getblockhash {}'".format(
            block, self.expectedBlock))
        return self.blockHash

    def getblockheader(self, blockHash):
        # Make sure to raise an exception in the same way a real node would
        # when calling 'getblockheader' on a block hash that is not part of
        # the chain.
        self.test.assertEqual(blockHash, self.blockHash, "Called 'getblockheader {}' when expected was 'getblockheader {}'".format(
            blockHash, self.blockHash))
        return {
            "hash": blockHash,
            "confirmations": 2003,
            "height": 99429,
            "version": 536872053,
            "versionHex": "20000475",
            "merkleroot": "68ede51918226dece9f3eefecca6011020983cdb6b6585d0bfeb770ef13f94bc",
            "time": 1640821954,
            "mediantime": 1640818715,
            "nonce": 33672781,
            "bits": "1d0171ab",
            "difficulty": 0.6925027738151847,
            "chainwork": "0000000000000000000000000000000000000000000000000050388771652242",
            "nTx": 1,
            "previousblockhash": "0000000054a90f9db046d99f3ad4173db85d7b5ed1556b9a45e543dae7c8f26a",
            "nextblockhash": "00000000df8cea220f562a6fbadea732274a125ec1ff6508fcace41376efa33b"
        }


class MockFailRPC(MockRPC):
    # Provides a fail counter to fail after the Nth RPC command

    def __init__(self, test, chain, numBlocks, expectedBlock,
                 blockHash, chainWork, failCounter):
        super().__init__(test, chain, numBlocks, expectedBlock, blockHash, chainWork)
        self.failCounter = failCounter

    def checkFailCounter(self):
        self.failCounter -= 1
        if self.failCounter < 0:
            raise Exception("""error code: -99
                error message:
                mock error""")

    def getblockchaininfo(self):
        self.checkFailCounter()
        return super().getblockchaininfo()

    def getblockhash(self, block):
        self.checkFailCounter()
        return super().getblockhash(block)

    def getblockheader(self, blockHash):
        self.checkFailCounter()
        return super().getblockheader(blockHash)


def CheckMockFailure(test, args, errorMessage='error code: -99'):
    with test.assertRaises(Exception) as context:
        GenerateChainParams(args)
    test.assertIn(errorMessage, str(context.exception))


class GenerateChainParamsTests(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.blockHash1 = '000000011b9511a5efea95d15371360bf8217fbe0300362092e70b28f0cf677c'
        self.chainWork1 = '00000000000000000000000000000000000000000000000000722ac94ee64333'

    def test_happy_path_zeniqnet(self):
        mockRPC = MockRPC(test=self, chain='zeniq', numBlocks=101431,
                          expectedBlock=101421, blockHash=self.blockHash1, chainWork=self.chainWork1)
        args = {
            'rpc': mockRPC,
            'block': None,
        }
        self.assertEqual(GenerateChainParams(args), "{}\n{}".format(
                         "000000011b9511a5efea95d15371360bf8217fbe0300362092e70b28f0cf677c",
                         "00000000000000000000000000000000000000000000000000722ac94ee64333"))


unittest.main()
