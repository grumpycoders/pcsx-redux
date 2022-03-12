#!/usr/bin/env bash

set -e

PACKAGES="capstone curl ffmpeg freetype glfw libuv pkg-config zlib"

brew install ${PACKAGES}
