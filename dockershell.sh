#!/bin/sh

ROOT=$(dirname $0)
CWD=$(pwd)
cd $ROOT
ROOT=$(pwd)
cd $CWD

docker pull ghcr.io/grumpycoders/pcsx-redux-build:latest
docker run --rm --env-file ${ROOT}/env.list -t -i -w/project${CWD#$ROOT} -v "${ROOT}:/project" -u `id -u`:`id -g` --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined ghcr.io/grumpycoders/pcsx-redux-build:latest bash -l
