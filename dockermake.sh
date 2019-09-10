#!/bin/sh

ROOT=$(dirname $0)

docker pull grumpycoders/pcsx-redux-build:latest
docker run --rm --env-file ${ROOT}/env.list -t -i -v "${PWD}:/project" -u `id -u`:`id -g` grumpycoders/pcsx-redux-build:latest make $@
