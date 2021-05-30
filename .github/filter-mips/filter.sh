#!/bin/sh

set -e

ROOT=$(dirname $0)
CWD=$(pwd)
cd $ROOT
ROOT=$(pwd)
cd $CWD

git filter-branch -f --tree-filter 'find third_party -not -name uC-sdk -exec git rm -f {} \; || true' --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter 'mkdir -p src/mips ; git mv third_party src/mips ; mv .gitmodules src/mips ; mv docker* src/mips || true' --tag-name-filter cat --prune-empty
git filter-branch -f --subdirectory-filter src/mips --prune-empty
git filter-branch -f --tree-filter "cp ${ROOT}/README-filtered.md README.md" --tag-name-filter cat
git filter-branch -f --tree-filter "find . -name Makefile -exec sed 's|\.\./\.\./\.\./third_party/uC-sdk/|../third_party/uC-sdk/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "sed 's|src/mips/third_party/uC-sdk|third_party/uC-sdk|' -i .gitmodules" --tag-name-filter cat --prune-empty
