# DMA (Distributed Minting Architecture)

Zeniq's main feature is the distributed minting architecture (DMA).
This distinguishes between minters and miners:

- **Minter** refers to a node possessing a minter key
  that entitles it to a predetermined reward
  requested via a DMA transaction.
- **Miner** refers the block mining node,
  which produces blocks containing transactions.
  DMA transactions are placed into the first block transaction,
  the coinbase,
  but only a fraction of them.

The *Zeniq code* is a fork of Bitcoin Cash Node.

The *Zeniq chain* has its own genesis block and consensus,
and is **not** a fork of the Bitcoin Cash Chain.
In the sources, the chain parameters of
`zeniqd, zeniq-cli, zeniq-qt, zeniq-tx, zeniq-seeder`
can be found in `CZeniqParams`.


## Commandline

```
zeniqd -minting <private minter key[:destination]>
```

- use case for the minter:

  This node only contributes DMA transactions.
  The minter key must fit to one of the hardcoded public minter keys.


```
zeniqd -gen
```

- use case for the miner:
  This node starts only mining and does not contribute DMA transactions.


## Minter key

Not only the miner gets a reward,
but a random subset of network nodes is also rewarded (MinterBucket, bucket),
among them mostly non-mining nodes.
Only nodes in the current bucket send DMA transactions (`IsDMA()`)
to be included in the coinbase of the next block.

The bucket is determined by comparing the first 7 bits
of a node hash with the hashPrevBlock.
The node hash contains the node's minter key ID:
`MinterHash(keyID,height,hashPrevBlock)`.
This selects about 1/128th of the nodes.

The minter `scriptPubKey`s start from `vout[2]`
in the coinbase transaction of the block.
All nodes verify that the keyID of minter `scriptPubKey`s
belong to the bucket for the current height/tip.
The public `keyID` can be recovered
from a signature and a messages (`RecoverCompact()`).
The signatures used for the verification are in
`vout[1]` of the coinbase transaction:
`MinterHash(scriptPubKey,height,hashPrevBlock)`.

The private minter key is needed to create the signatures
for the DMA transactions to be distributed via mempool
and landing in `vout[1].scriptPubKey` of the coinbase.

The block's coinbase `vout[0].scriptPubKey` on the other hand
comes from the node wallet
and is not one of the minter keys.
The block miner does not need to be part of the bucket it mines for.

A DMA transaction's vout has

- `vout[0]`: scriptPubKey
- `vout[1]`: signature

From the DMA transactions for the current height
the coinbase's vout is constructed:

- `vout[0]`: miner's `scriptPubKey` (from local wallet)
- `vout[1]`: `OP_RETURN` + list of signatures (from DMA transactions) 0th-3rd vout, ...
- `vout[2]`: `scriptPubKey` from one of DMA transactions out of the current bucket
- ...

Every node forwards DMA transaction for its own height
as well as the heights before and after.

DMA transactions below `height-1` are removed from mempool
at every connection of a block.

## Block Reward

**Miner**

`SubsidyMiner`:
The miner gets 1 Coin for every DMA transaction it incorporates
but not more than 3 percent of all minter reward together.

`Fee`: The miner gets also half of the fee.
The other half is burned.
DMA transaction do not contribute to fee.

The consensus does not connect blocks with miner reward
greater than `fee/2+SubsidyMiner`.

**Minter**

`SubsidyMinter`:
The minter reward is for members of the network with a minter key.
The minter reward depends on the height and
the index in the hard-coded list of public minter keys (`dmadata.inc`).
A node cannot change the order of the minter keys,
because other nodes check the reward and thus need the same order
of the same keys.
The minter reward is payed about every 128th block,
but possibly less often,
as a miner might choose not to include less rewarding DMA transactions
if traffic is so high to produce fee/2 more worthy per kB.


