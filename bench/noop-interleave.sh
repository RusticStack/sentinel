#!/usr/bin/env bash
# The no-op floor: process spawn (and, with --interleave podman, container start and teardown) with no user work (docs/benchmarking.md).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/sentinel-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/noop bench/noop-interleave.sh [-- extra sentinel-bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/noop-interleave.json: the contract fixes the arguments and the
# record; the runner takes the shared verification lock and refuses a host that is not quiet. sentinel-bench stamps its own
# build and host, so the runner leaves them alone. `bench/micro-run.sh <contract> --smoke` is the tiny-parameter harness check.
# The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/noop-interleave.json" -- "$@"
