#!/usr/bin/env bash
# Backup verification rehash cost at configurable object counts, through backup::verify, beside a bare BLAKE3 read of the same files.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/backup-rehash-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/backup-rehash bench/backup-rehash.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/backup-rehash.json: the contract fixes the arguments, the case
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the
# build and host and appends the record to bench/backup-rehash.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke`
# is the tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-store --example backup-rehash-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/backup-rehash.json" -- "$@"
