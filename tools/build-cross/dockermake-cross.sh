#!/bin/sh

ROOT=$(dirname $0)
CWD=$(pwd)
cd $ROOT
ROOT=$(pwd)
cd $CWD
#TEMPORARY
docker build -t aarch64cross tools/build-cross/
docker run --rm --env-file ${ROOT}/cross-env.list -i -w/project${CWD#$ROOT} -v "${ROOT}:/project" -u `id -u`:`id -g` aarch64cross make --makefile=Makefile-cross-aa64 $@