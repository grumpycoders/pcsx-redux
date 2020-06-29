#!/usr/bin/env bash

set -e

PACKAGES="pkg-config sdl2 ffmpeg sdl2 libuv zlib glfw luajit"

brew install ${PACKAGES}
