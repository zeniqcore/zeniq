# UniValue

## Summary

A universal value class, with JSON encoding and decoding.
UniValue is an abstract data type that may be a null, boolean, string,
number, array container, or a key/value dictionary container, nested to
an arbitrary depth.
This class is aligned with the JSON standard, [RFC
8259](https://tools.ietf.org/html/rfc8259).

UniValue was originally created by [Jeff Garzik](https://github.com/jgarzik/univalue/)
and is used in node software for many bitcoin-based cryptocurrencies.
Unlike the [Bitcoin Core fork](https://github.com/bitcoin-core/univalue/),
UniValue here contains large changes that improve *code quality* and *performance*.
The UniValue API deviates from the original UniValue API where necessary.

The UniValue library and call sites can be changed simultaneously, allowing rapid iterations.

## License

UniValue is released under the terms of the MIT license. See
[COPYING](COPYING) for more information or see
<https://opensource.org/licenses/MIT>.

## Build instructions

### Build

UniValue is fully integrated in the build system.
The library is built automatically while building the node.

Command to build and run tests in the build system:

```
ninja check-univalue
```

### Stand-alone build

UniValue is a standard GNU
[autotools](https://www.gnu.org/software/automake/manual/html_node/Autotools-Introduction.html)
project. Build and install instructions are available in the `INSTALL`
file provided with GNU autotools.

Commands to build the library stand-alone:

```
./autogen.sh
./configure
make
```

UniValue requires C++17 or later.
