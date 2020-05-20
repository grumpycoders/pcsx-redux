#!/usr/bin/env bash

set -e

PACKAGES="sdl2 ffmpeg sdl2 libuv zlib glfw"

brew install ${PACKAGES}