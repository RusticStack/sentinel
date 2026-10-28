#!/usr/bin/env bash
# S3 hashing and signing: SHA-256, MD5, the one-walk body_hashes and Signature V4 signing cost at several payload sizes (no network).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/s3-hash-bench bench/s3-hash.sh [bench args]
# Pure CPU: run it on a quiet host; the record's host block names the CPU.
# Appends one stamped record to OUT (default bench/s3-hash.jsonl).
# The measured binary is the example built from SENTINEL_SRC: cargo build --release -p sentinel-s3 --example s3-hash-bench
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init
BIN="${SENTINEL_BIN:?set SENTINEL_BIN to the s3-hash-bench binary built from SENTINEL_SRC}"
OUT="${OUT:-$(dirname "${BASH_SOURCE[0]}")/s3-hash.jsonl}"
STAMP_SED="$(stamp_sed)"
"$BIN" "$@" | sed "s/^{/{$STAMP_SED,/" >> "$OUT"
echo "record appended to $OUT" >&2
