#!/usr/bin/env bash

: '
Clone

   git clone https://github.com/zeniqcore/zeniq.git
   cd zeniq
   git lfs install
   git lfs pull

Build with this script using ninja into ../${PWD##*/}_build.

  ./build_zeniq.sh
  ./build_zeniq.sh std
  ./build_zeniq.sh node

To run tests:

  ./build_zeniq.sh debug
  ./build_zeniq.sh coverage

Then go to destdir and run several times

  ninja check

Or specific tests, e.g.

   ../${PWD##*/}_build
   alias ztst="ninja src/test/test_bitcoin && src/test/test_bitcoin --log_level=message --run_test="
   alias zctst="ninja src/test/test_bitcoin && cgdb --args src/test/test_bitcoin --log_level=message --run_test="
   ztst validation_tests
   # see src/test/CMakeLists.txt

-DENABLE_BIP70=OFF
 because undefined reference to symbol _ZN4absl12lts_2023012512log_internal17MakeCheckOpStringIllEEPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEET_T0_PKc

'

export CMAKE_EXPORT_COMPILE_COMMANDS=ON
srcdir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
destdir="${srcdir%/*}/${srcdir##*/}_build"


rm -rf $destdir
mkdir -p $destdir
cd $destdir

if [ "$1" == "debug" ]; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON -DENABLE_BIP70=OFF $srcdir
elif [ "$1" == "coverage" ]; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON -DENABLE_COVERAGE=ON -DENABLE_BIP70=OFF $srcdir
elif [ "$1" == "std" ] ; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_BITCOIN_QT=OFF -DENABLE_BIP70=OFF $srcdir
elif [ "$1" == "node" ] ; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_BITCOIN_QT=OFF -DENABLE_BIP70=OFF $srcdir
else
   cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON -DENABLE_BIP70=OFF $srcdir
fi
if [ -e $destdir/compile_commands.json ]; then
   cp $destdir/compile_commands.json $srcdir
fi

cd $destdir/native
ninja

if [ "$1" == "debug" ] ; then
   ninja check
fi

if [ "$1" == "coverage" ] ; then
   ninja check-all
fi

