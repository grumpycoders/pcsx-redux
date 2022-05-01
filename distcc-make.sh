#!/bin/sh

# This is for my own build environment, so it won't be much useful for anyone else.

export DISTCC_NO_REWRITE_CROSS=1
export DISTCC_HOSTS=10.12.1.2/60,lzo
export CC="distcc clang-14"
export CXX="distcc clang++-14"
export LD=clang++-14

export JOBS=60

make -j $JOBS $@
