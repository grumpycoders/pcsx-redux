#!/usr/bin/env bash

set -e

PACKAGES="ffmpeg freetype glfw libuv pkg-config zlib"

brew install ${PACKAGES}
