#!/usr/bin/env bash

set -e

PACKAGES="capstone ffmpeg freetype glfw libuv pkg-config zlib"

brew install ${PACKAGES}
