#!/usr/bin/env bash

set -e

PACKAGES="capstone curl ffmpeg freetype libuv pkg-config sdl3 zlib"

brew install ${PACKAGES}
