#!/usr/bin/env bash
# Backup verification rehash cost at configurable object counts, through backup::verify, beside a bare BLAKE3 read of the same files.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/backup-rehash-bench DIR=/srv/bench/backup-rehash bench/backup-rehash.sh [bench args]
# DIR must sit on the file system under test; the bench removes what it creates there.
# Appends one stamped record to OUT (default bench/backup-rehash.jsonl).
# The measured binary is the example built from SENTINEL_SRC: cargo build --release -p sentinel-store --example backup-rehash-bench
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init
BIN="${SENTINEL_BIN:?set SENTINEL_BIN to the backup-rehash-bench binary built from SENTINEL_SRC}"
DIR="${DIR:?set DIR to a directory on the file system under test}"
OUT="${OUT:-$(dirname "${BASH_SOURCE[0]}")/backup-rehash.jsonl}"
STAMP_SED="$(stamp_sed)"
"$BIN" --dir "$DIR" "$@" | sed "s/^{/{$STAMP_SED,/" >> "$OUT"
echo "record appended to $OUT" >&2
