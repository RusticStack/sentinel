#!/usr/bin/env bash
# Checks lane: enqueue-to-delivery latency of a run's queued checks, real Store, Lane and GithubChecks against a fake GitHub endpoint on loopback.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/checks-lane-bench DIR=/srv/bench/checks-lane bench/checks-lane.sh [bench args]
# DIR must sit on the file system under test (the bench's store lives there).
# Appends one stamped record to OUT (default bench/checks-lane.jsonl).
# The measured binary is the example built from SENTINEL_SRC: cargo build --release -p sentinel-checks --example checks-lane-bench
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init
BIN="${SENTINEL_BIN:?set SENTINEL_BIN to the checks-lane-bench binary built from SENTINEL_SRC}"
DIR="${DIR:?set DIR to a directory on the file system under test}"
OUT="${OUT:-$(dirname "${BASH_SOURCE[0]}")/checks-lane.jsonl}"
STAMP_SED="$(stamp_sed)"
"$BIN" --dir "$DIR" "$@" | sed "s/^{/{$STAMP_SED,/" >> "$OUT"
echo "record appended to $OUT" >&2
