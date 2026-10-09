#!/bin/bash
# Retry submodule fetches with exponential backoff, and fetch xmake-psx from its GitHub mirror
# since codeberg rate-limits CI clones (HTTP 429) and goes down (HTTP 504).

set -u

attempts=${SUBMODULE_RETRY_ATTEMPTS:-6}
delay=${SUBMODULE_RETRY_DELAY:-15}

export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=url.https://github.com/pcsx-redux/xmake-psx.git.insteadOf
export GIT_CONFIG_VALUE_0=https://codeberg.org/malucart/xmake-psx.git

if [ -n "${CI:-}" ] && ! git config --global --get-all safe.directory 2>/dev/null | grep -qxF "$PWD"; then
    git config --global --add safe.directory "$PWD"
fi

for attempt in $(seq 1 "$attempts"); do
    if git submodule sync --recursive && git submodule update --init --recursive; then
        exit 0
    fi
    echo "Submodule update failed (attempt $attempt/$attempts)" >&2
    if [ "$attempt" -lt "$attempts" ]; then
        echo "Retrying in ${delay}s..." >&2
        sleep "$delay"
        delay=$((delay * 2))
    fi
done

echo "Submodule update failed after $attempts attempts" >&2
exit 1
