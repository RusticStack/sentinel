#!/usr/bin/env bash
# Artifact download: a whole-artifact archive (tar and zip) and one entry, served by the real API route from a real
# store on loopback, with time to first byte and total time per response.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/archive-download-bench SENTINEL_BENCH_HOST_LABEL=<label> \
#     DIR=/var/tmp/archive-download bench/archive-download.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/archive-download.json: the contract fixes the arguments,
# the ABBA case order and the record; the runner takes the shared verification lock, refuses a host that is not
# quiet, stamps the build and host and appends the record to bench/archive-download.jsonl (OUT overrides).
#   bench/micro-run.sh bench/contracts/micro/archive-download.json --smoke   tiny-parameter harness check
# The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-api --example archive-download-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/archive-download.json" -- "$@"
