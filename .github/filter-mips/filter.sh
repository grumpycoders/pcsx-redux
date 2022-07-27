#!/bin/sh

set -e

ROOT=$(dirname $0)
CWD=$(pwd)
cd $ROOT
ROOT=$(pwd)
cd $CWD

# Need to delete submodules actively.
# Done in two passes for speed.
git filter-branch -f --tree-filter 'find third_party -depth -not -name uC-sdk -and -not -path third_party/EABase -and -not -path third_party/EABase/\* -and -not -path third_party/EASTL -and -not -path third_party/EASTL/\* -delete || true' --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter 'find third_party -depth -not -name uC-sdk -and -not -path third_party/EABase -and -not -path third_party/EABase/\* -and -not -path third_party/EASTL -and -not -path third_party/EASTL/\* -exec git rm -f {} \; || true' --tag-name-filter cat --prune-empty

# Shuffle files around.
git filter-branch -f --tree-filter 'mkdir -p src/mips ; git mv third_party src/mips ; mv .gitmodules src/mips ; mv docker* src/mips || true' --tag-name-filter cat --prune-empty

# Do the actual cutting of the history.
git filter-branch -f --subdirectory-filter src/mips --prune-empty

# Inject our new README.md
git filter-branch -f --tree-filter "cp ${ROOT}/README-filtered.md README.md" --tag-name-filter cat

# Adjust paths for uC-sdk.
git filter-branch -f --tree-filter "find . -name Makefile -exec sed 's|\.\./\.\./\.\./third_party/uC-sdk/|../third_party/uC-sdk/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "find . -name '*.mk' -exec sed 's|\.\./\.\./\.\./third_party/uC-sdk/|../third_party/uC-sdk/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "sed 's|src/mips/third_party/uC-sdk|third_party/uC-sdk|' -i .gitmodules" --tag-name-filter cat --prune-empty

# Adjust paths for the EASTL
git filter-branch -f --tree-filter "find . -name Makefile -exec sed 's|\.\./\.\./\.\./third_party/EABase/|../third_party/EABase/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "find . -name Makefile -exec sed 's|\.\./\.\./\.\./third_party/EASTL/|../third_party/EASTL/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "find . -name '*.mk' -exec sed 's|\.\./\.\./\.\./third_party/EABase/|../third_party/EABase/|' -i {} \;" --tag-name-filter cat --prune-empty
git filter-branch -f --tree-filter "find . -name '*.mk' -exec sed 's|\.\./\.\./\.\./third_party/EASTL/|../third_party/EASTL/|' -i {} \;" --tag-name-filter cat --prune-empty
