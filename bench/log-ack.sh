#!/usr/bin/env bash
# Log-ack batching: cost of one fdatasync per burst of frames against one per frame, through the real LogStore.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/log-ack-bench DIR=/srv/bench/log-ack bench/log-ack.sh [bench args]
# DIR must sit on the file system under test. Appends one stamped record to OUT (default bench/log-ack.jsonl).
# The measured binary is the example built from SENTINEL_SRC: cargo build --release -p sentinel-store --example log-ack-bench
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init
BIN="${SENTINEL_BIN:?set SENTINEL_BIN to the log-ack-bench binary built from SENTINEL_SRC}"
DIR="${DIR:?set DIR to a directory on the file system under test}"
OUT="${OUT:-$(dirname "${BASH_SOURCE[0]}")/log-ack.jsonl}"
STAMP_SED="$(stamp_sed)"
"$BIN" --dir "$DIR" "$@" | sed "s/^{/{$STAMP_SED,/" >> "$OUT"
echo "record appended to $OUT" >&2
