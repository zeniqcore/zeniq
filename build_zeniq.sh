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
  ./build_zeniq.sh debug

Then go to destdir and run several times

  ninja check

Or specific tests, e.g.

   ../${PWD##*/}_build
   alias ztst="ninja src/test/test_bitcoin && src/test/test_bitcoin --log_level=message --run_test="
   alias zctst="ninja src/test/test_bitcoin && cgdb --args src/test/test_bitcoin --log_level=message --run_test="
   ztst validation_tests
   # see src/test/CMakeLists.txt
'

export CMAKE_EXPORT_COMPILE_COMMANDS=ON
srcdir=$PWD
destdir="${PWD%/*}/${PWD##*/}_build"
mkdir -p $destdir
cd $destdir
if [ "$1" == "debug" ]; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON $srcdir
elif [ "$1" == "coverage" ]; then
   cmake -GNinja -DCMAKE_BUILD_TYPE=Debug -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON -DENABLE_COVERAGE=ON $srcdir
elif [ "$1" == "std" ] ; then
   cmake -GNinja $srcdir
elif [ "$1" == "node" ] ; then
   cmake -GNinja $srcdir
else
   cmake -GNinja -DBUILD_BITCOIN_WALLET=ON -DBUILD_BITCOIN_QT=ON -DBUILD_BITCOIN_ZMQ=ON -DENABLE_QRCODE=ON -DENABLE_UPNP=ON $srcdir
fi
if [ -e $destdir/compile_commands.json ]; then
   cp $destdir/compile_commands.json $srcdir
fi
ninja
#ninja check
