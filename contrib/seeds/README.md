# Seeds

Utility to generate the seeds.txt list that is compiled into the client
(see [src/chainparamsseeds.h](/src/chainparamsseeds.h) and other utilities in [contrib/seeds](/contrib/seeds)).

Be sure to update `PATTERN_AGENT` in `makeseeds.py` to include the current version,
and remove old versions as necessary (at a minimum when GetDesireableServiceFlags
changes its default return value, as those are the services which seeds are added
to addrman with).

The seeds compiled into the release are created from the `dnsseed.dump` output file of a
[Zeniq Seeder](/src/seeder) that has been running for at least 30 days. The scripts
below assume that the `dnsseed.dump` file from the zeniqnet seeder has been copied to
`seeds_zeniq.txt`, etc.

```
python3 makeseeds.py < seeds_zeniq.txt > nodes_zeniq.txt
python3 generate-seeds.py . > ../../src/chainparamsseeds.h
```

## Dependencies

Ubuntu:

```
sudo apt-get install python3-dnspython
```

## Testing user agent pattern modifications

A sample 'dnsseed.dump.test' has been provided, which contains some patterns
to test against. It should be adapted when changes are made.

To check that the emitted patterns match only those you want, you can run
the commands below.
You may need to temporarily disable ASN limiting, ensure that the uptime and
service bits in your test entries would pass the filters in `makeseeds.py`.

```
$ cp dnsseed.dump.test seeds_zeniq.txt
$ python3 makeseeds.py < seeds_zeniq.txt  | while read s; do grep -F "$s"
seeds_zeniq.txt ; done
```
