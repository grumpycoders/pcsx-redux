#!/bin/sh

docker pull grumpycoders/pcsx-redux-build:latest
docker run --rm --env-file env.list -t -i -v "${PWD}:/project" -u `id -u`:`id -g` grumpycoders/pcsx-redux-build:latest make $@
