#!/usr/bin/env bash
# Digest-first artifact transfer: link bytes and elapsed time of a repeated artifact published with bodies against
# one published from digests the tenant already holds, through a real worker link and the real controller on loopback.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/digest-transfer-bench SENTINEL_BENCH_HOST_LABEL=<label> \
#     DIR=/var/tmp/digest-transfer bench/digest-transfer.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/digest-transfer.json: the contract fixes the arguments,
# the ABBA case order and the record; the runner takes the shared verification lock, refuses a host that is not
# quiet, stamps the build and host and appends the record to bench/digest-transfer.jsonl (OUT overrides).
#   bench/micro-run.sh bench/contracts/micro/digest-transfer.json --smoke   tiny-parameter harness check
# The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-worker --example digest-transfer-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/digest-transfer.json" -- "$@"
