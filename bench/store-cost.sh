#!/usr/bin/env bash
# Store maintenance cost: the batched retention re-apply, the WAL checkpoint under readers holding snapshots, and the free-capacity read beside a long attempt history (docs/benchmarking.md).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/store-cost-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/store-cost bench/store-cost.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/store-cost.json: the contract fixes the arguments, the operation
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the build
# and host and appends the record to bench/store-cost.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke` is the
# tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-store --example store-cost-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/store-cost.json" -- "$@"
