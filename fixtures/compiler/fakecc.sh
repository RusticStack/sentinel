#!/bin/sh
# fakecc — a minimal stand-in for a compiler that owns its cache's
# invalidation (K06). It is not a real compiler: for each input file it
# emits `<cache-dir>/<basename>.<sha256>.o`, reusing the artifact when it
# already exists and "compiling" (copying the input bytes) when it does
# not.
#
# The content key inside the artifact name is what a real tool does with
# its own cache — ccache's result keys, rustc's incremental fingerprints,
# go's build IDs. Sentinel restores the namespace wholesale and stays
# ignorant of per-input freshness; the tool decides, so a hit can never
# serve a stale input's output.
#
# usage: fakecc.sh <cache-dir> <input>...
# stdout: one line per input — `reused <name>` or `built <name>` — so a
# test can count which inputs were rebuilt after an edit. Artifacts are
# never deleted: stale entries accumulate in the namespace like a real
# compiler cache's, bounded by the store's reclamation, not by the tool.
set -eu

cache_dir=$1
shift
mkdir -p "$cache_dir"

for input in "$@"; do
    name=${input##*/}
    digest=$(sha256sum "$input" | cut -d ' ' -f 1)
    out="$cache_dir/$name.$digest.o"
    if [ -f "$out" ]; then
        echo "reused $name"
    else
        cp "$input" "$out"
        echo "built $name"
    fi
done
