#!/usr/bin/env bash
# Checks lane: enqueue-to-delivery latency of a run's queued checks, real Store, Lane and GithubChecks against a fake GitHub endpoint on loopback.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/checks-lane-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/checks-lane bench/checks-lane.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/checks-lane.json: the contract fixes the arguments, the case
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the
# build and host and appends the record to bench/checks-lane.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke`
# is the tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-checks --example checks-lane-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/checks-lane.json" -- "$@"
