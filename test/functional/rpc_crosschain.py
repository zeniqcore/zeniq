#!/usr/bin/env python3
"""
This test checks the crosschain feature.

test/functional/test_runner.py rpc_crosschain

import sys,os.path
sys.path.append(os.path.dirname(__file__))

"""

import struct
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    ToHex,
)

from test_framework.script import CScript, OP_RETURN, OP_FALSE, OP_VERIFY
from test_framework.util import satoshi_round, assert_raises_rpc_error

class CrosschainTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-whitelist=127.0.0.1',
                            '-acceptnonstdtxn=1']]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.relayfee = node.getnetworkinfo()["relayfee"]

        agentdata = b'agentID_agentdata'
        crosschain = b'crss'

        # spend to crosschain
        utxos = node.listunspent()
        assert(len(utxos) > 0)
        utxo = utxos[0]
        value = int(satoshi_round((utxo["amount"] - self.relayfee)) * COIN)
        data = crosschain.hex() + struct.pack('<Q', value).hex() + agentdata.hex()
        tx_crt = node.createrawtransaction(
            inputs=[{"txid":utxo["txid"], "vout":utxo["vout"]}],
            outputs=[{"data": data}])
        print(tx_crt)

        tx_signed = node.signrawtransactionwithwallet(tx_crt)["hex"]
        txid = node.sendrawtransaction(tx_signed)
        assert(txid in set(node.getrawmempool()))

        # generate a new block to include the crosschain tx
        node.generate(1)

        # query the crosschain tx
        raws = CScript([OP_FALSE, OP_VERIFY, OP_RETURN, agentdata])
        raw = raws.hex()

        found = node.scantxoutset(action="start", scanobjects=["raw(" + raw + ")"])
        assert(found['success'])
        assert(found['unspents'][0]['scriptPubKey'] == raw)

        blockquery = node.crosschain(first=1, last=2499)
        assert(len(blockquery))
        assert(blockquery['cc'][0]['height']>0)

        blockquery = node.crosschain(first=1, last=2599)
        # > 2500 does not fail because not so many blocks in the test chain
        assert(len(blockquery)>0)

        #self.log.info('crosschain: {}'.format(blockquery))

if __name__ == '__main__':
    CrosschainTest().main()
