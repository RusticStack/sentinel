#!/usr/bin/env bash
# Streaming artifact publication: the tail of one attempt after a step's end when the artifact publishes behind that
# step against the same attempt when it publishes at finalization, measured through a real worker link and the real
# controller on loopback.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/step-publication-bench SENTINEL_BENCH_HOST_LABEL=<label> \
#     DIR=/var/tmp/step-publication bench/step-publication.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/step-publication.json: the contract fixes the arguments,
# the ABBA case order and the record; the runner takes the shared verification lock, refuses a host that is not
# quiet, stamps the build and host and appends the record to bench/step-publication.jsonl (OUT overrides).
#   bench/micro-run.sh bench/contracts/micro/step-publication.json --smoke   tiny-parameter harness check
# The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-worker --example step-publication-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/step-publication.json" -- "$@"
