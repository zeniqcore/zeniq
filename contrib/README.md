Repository Tools
---------------------

### [Developer tools](devtools/) ###
Specific tools for developers working on this repository.
Contains the script `github-merge.py` for merging GitHub pull requests securely and signing them using GPG.

### [Linearize](linearize/) ###
Construct a linear, no-fork, best version of the blockchain.

### [Qos](qos/) ###

A Linux bash script that will set up traffic control (tc) to limit the outgoing bandwidth for connections to the Bitcoin network. This means one can have an always-on bitcoind instance running, and another local bitcoind/bitcoin-qt instance which connects to this node and receives blocks from it.

### [Seeds](seeds/) ###
Utility to generate the pnSeed[] array that is compiled into the client.


Test and Verify Tools 
---------------------

### [TestGen](testgen/) ###
Utilities to generate test vectors for the data-driven Bitcoin tests.
