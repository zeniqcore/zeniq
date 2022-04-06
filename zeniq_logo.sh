#!/usr/bin/env bash

: '
Build png from svg sources.
'

if ! type convert; then
   echo "needs ImageMagick convert"
   exit 1
fi

TMP=`mktemp -d`
function cleanup {
  rm -rf "$TMP"
}
trap cleanup EXIT

Z="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
S1="$Z/src/qt/res/src/bitcoin_splash.svg"
S2="$Z/src/qt/res/src/bitcoin.svg"
S3="$Z/src/qt/res/src/bitcoin_noletters.svg"
S4="$Z/doc/images/logo.svg"
I1="$Z/share/pixmaps/bitcoin.ico"
I2="$Z/src/qt/res/icons/bitcoin.ico"
I3="$Z/src/qt/res/icons/bitcoin_testnet.ico"
P1=$Z/src/qt/res/icons/bitcoin_noletters_testnet.png
P2=$Z/doc/bitcoin_logo_doxygen.png
P3=$Z/src/qt/res/icons/bitcoin_noletters.png
P4=$Z/src/qt/res/icons/bitcoin_splash.png
P5=$Z/share/pixmaps/bitcoin256.png
P6=$Z/share/pixmaps/bitcoin128.png
P7=$Z/share/pixmaps/bitcoin64.png
P8=$Z/share/pixmaps/bitcoin32.png
P9=$Z/share/pixmaps/bitcoin16.png
PA=$Z/src/qt/res/icons/bitcoin.png
cd ${TMP}
convert -density 256x256 -background transparent ${S3} -define icon:auto-resize -colors 256 S3.ico
yes | cp S3.ico ${I1}
yes | cp S3.ico ${I2}
yes | cp S3.ico ${I3}
convert -density 256x256 -background transparent ${S3} -resize 256x256 -colors 256 S3.png
yes | cp S3.png ${P1}
yes | cp S3.png ${P3}
yes | cp S3.png ${P5}
convert -density 256x256 -background transparent ${S3} -colors 256 -resize 128x128 S128.png
convert -density 256x256 -background transparent ${S3} -colors 256 -resize 64x64   S64.png
convert -density 256x256 -background transparent ${S3} -colors 256 -resize 32x32   S32.png
convert -density 256x256 -background transparent ${S3} -colors 256 -resize 16x16   S16.png
yes | cp S128.png ${P6}
yes | cp S64.png ${P7}
yes | cp S32.png ${P8}
yes | cp S16.png ${P9}
convert -density 256x256 -background transparent ${S2} -resize 55x55 -colors 256 S2.png
yes | cp S2.png ${P2}
convert -background transparent ${S1} -resize 1024x1024 -colors 256 splash.png
yes | cp splash.png ${P4}
convert -background transparent ${S3} -resize 1024x1024 -colors 256 bc.png
yes | cp bc.png ${PA}
cd $Z/share/pixmaps
convert bitcoin256.png bitcoin256.xpm
convert bitcoin128.png bitcoin128.xpm
convert bitcoin64.png bitcoin64.xpm
convert bitcoin32.png bitcoin32.xpm
convert bitcoin16.png bitcoin16.xpm
