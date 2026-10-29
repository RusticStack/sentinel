#!/usr/bin/env bash
# Log-ack batching: cost of one fdatasync per burst of frames against one per frame, through the real LogStore.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/log-ack-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/log-ack bench/log-ack.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/log-ack.json: the contract fixes the arguments, the case
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the
# build and host and appends the record to bench/log-ack.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke`
# is the tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-store --example log-ack-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/log-ack.json" -- "$@"
