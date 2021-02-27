#!/usr/bin/env bash

set -e

PACKAGES="ffmpeg freetype glfw libuv pkg-config sdl2 zlib"

brew install ${PACKAGES}
