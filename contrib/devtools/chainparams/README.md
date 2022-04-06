# Chainparams Constants

Utilities to generate chainparams constants that are compiled into the client
(see [src/chainparamsconstants.h](/src/chainparamsconstants.h).

The chainparams constants are fetched from zeniqd, dumped to intermediate
files, and then compiled into [src/chainparamsconstants.h](/src/chainparamsconstants.h).
If you're running zeniqd locally, the following instructions will work
out-of-the-box:

## Zeniq net

zeniqd
python3 make_chainparams.py > chainparams_zeniq.txt

## Build C++ Header File
```
python3 generate_chainparams_constants.py . > ../../../src/chainparamsconstants.h
```

## Testing

Updating these constants should be reviewed carefully, with a
reindex-chainstate, checkpoints=0, and assumevalid=0 to catch any defect that
causes rejection of blocks in the past history.
