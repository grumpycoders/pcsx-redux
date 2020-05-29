#!/bin/bash

ROOT=$(dirname $0)/../../..
cd $ROOT
ROOT=$(pwd)
cd src/mips/openbios

$ROOT/dockermake.sh all -j4
