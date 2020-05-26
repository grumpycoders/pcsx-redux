#!/bin/bash
CURRENT_PATH=$(PWD)
PROJECT_PATH=$(realpath "$CURRENT_PATH"/../../..)
CURRENT_RELATIVE_PATH=$(realpath --relative-to="$PROJECT_PATH" "$CURRENT_PATH")

docker run -it --rm -v "$PROJECT_PATH:/project" grumpycoders/pcsx-redux-build:latest make -C "$CURRENT_RELATIVE_PATH" deepclean all -j4

