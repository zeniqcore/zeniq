#!/usr/bin/env python3
"""
Assuming parallel directories

zeniq-core_build $ZCB
smartzeniq {moeingads  moeingdb  moeingevm  zeniq-smart-chain}

Usage:

cd ../zeniq-core_build
test/functional/test_runner.py rpc_crosschain_with_smartnode
# let it run for at least 10 minutes

Analyze
smartnodes.log
ccrpc applying TransferInfo

"""

import struct
import time
import os.path
import logging
import subprocess
import os
import sys
import threading

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
from test_framework.util import satoshi_round, assert_raises_rpc_error, get_datadir_path

def output_reader(proc, file):
    while True:
        byte = proc.stdout.read(1)
        if byte:
            sys.stdout.buffer.write(byte)
            sys.stdout.flush()
            file.buffer.write(byte)
        else:
            break


class CrosschainWithSmartTest(BitcoinTestFramework):

    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [[
            '-whitelist=127.0.0.1',
            '-acceptnonstdtxn=1'
        ]]

    def setup_chain(self):
        super().setup_chain() # generates 200 blocks

        with open(os.path.join(get_datadir_path(self.options.tmpdir, 0), "zeniq.conf"), 'a', encoding='utf8') as f:
            f.write('rpcbind=0.0.0.0\n')
            f.write('rpcallowip=127.0.0.1\n')
            f.write('rpcallowip=172.17.0.0/16\n')
            f.write('rpcallowip=172.18.0.0/16\n')
            f.write('rpcallowip=192.168.0.0/16\n')
            f.write('rpcuser=zeniq\n')
            f.write('rpcpassword=zeniq123\n')

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        self.relayfee = node.getnetworkinfo()["relayfee"]

        df = os.path.dirname(__file__)
        testnetenv = os.environ.copy()
        testnetenv['ZENIQRPCPORT'] = str(node.rpc_port).encode()
        with subprocess.Popen(["/bin/bash", "./testnettest.sh"
           ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=testnetenv,
           cwd = df + "/../../../smartzeniq/zeniq-smart-chain"
              ) as smartnodes, open('smartnodes.log', 'w') as smartlog:
            t = threading.Thread(target=output_reader, args=(smartnodes, smartlog))
            t.start()

            slp = 4
            time.sleep(10*slp)
            crosschain = b'crss'
            for i in range(10):
                agentdata = str(i).encode()
                # spend to crosschain
                utxos = node.listunspent()
                assert(len(utxos) > 0)
                utxo = utxos[0]
                value = int(satoshi_round((utxo["amount"] - self.relayfee)) * COIN)
                data = crosschain.hex() + struct.pack('<Q', value).hex() + agentdata.hex()
                tx_crt = node.createrawtransaction(
                    inputs=[{"txid":utxo["txid"], "vout":utxo["vout"]}],
                    outputs=[{"data": data}])
                tx_signed = node.signrawtransactionwithwallet(tx_crt)["hex"]
                txid = node.sendrawtransaction(tx_signed)
                assert(txid in set(node.getrawmempool()))
                # generate a new block to include the crosschain tx
                node.generate(1)
                time.sleep(slp)

            t.join()


if __name__ == '__main__':
    CrosschainWithSmartTest().main()
