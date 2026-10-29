#!/usr/bin/env bash
# Cost of the die-with-parent hook on a helper spawn (PR_SET_PDEATHSIG, so a fork instead of posix_spawn) from parents of 0, 64 and 512 MiB resident (docs/executor.md).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/spawn-cost-bench SENTINEL_BENCH_HOST_LABEL=<label> bench/spawn-cost.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/spawn-cost.json: the contract fixes the arguments, the case
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the build
# and host and appends the record to bench/spawn-cost.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke` is the
# tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-git --example spawn-cost-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/spawn-cost.json" -- "$@"
