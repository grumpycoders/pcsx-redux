#!/bin/sh
set -e

if [ $# -gt 0 ]; then
    CLANGF_SRC=`realpath -e "$1"`
    if [ ! -f "$1" ]; then
        echo "$1: no such file or directory" >&2
        exit 1
    fi
fi

cd $(dirname $0)/../..

CLANGF_DEST=src/.clang-format

rm -f "$CLANGF_DEST"

if [ -z "$CLANGF_SRC" ]; then
    CLANGF_SRC="src/.clang-format-commit"
fi

cp "$CLANGF_SRC" "$CLANGF_DEST"

echo "Using \"$CLANGF_SRC\"..."

docker build -t code-format tools/code-format
docker run --rm=true -v "$(pwd)":/repository --user "$(id -u):$(id -g)" -t code-format
