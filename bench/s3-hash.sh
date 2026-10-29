#!/usr/bin/env bash
# S3 hashing and signing: SHA-256, MD5, the one-walk body_hashes and Signature V4 signing cost at several payload sizes (no network). Pure CPU.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/s3-hash-bench SENTINEL_BENCH_HOST_LABEL=<label> bench/s3-hash.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/s3-hash.json: the contract fixes the arguments, the case
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the
# build and host and appends the record to bench/s3-hash.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke`
# is the tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-s3 --example s3-hash-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/s3-hash.json" -- "$@"
