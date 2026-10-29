#!/usr/bin/env bash
# Cost of Argon2id hash and verify, session validation, the login outcomes and API-credential validation and issuance (docs/local-authentication.md, docs/api-credentials.md).
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/auth-cost-bench SENTINEL_BENCH_HOST_LABEL=<label> DIR=/var/tmp/auth-cost bench/auth-cost.sh [extra bench args]
# Runs through bench/micro-run.sh and bench/contracts/micro/auth-cost.json: the contract fixes the arguments, the operation
# order and the record; the runner takes the shared verification lock, refuses a host that is not quiet, stamps the build
# and host and appends the record to bench/auth-cost.jsonl (OUT overrides). `bench/micro-run.sh <contract> --smoke` is the
# tiny-parameter harness check. The measured binary is built from SENTINEL_SRC:
#   cargo build --release --locked -p sentinel-store --example auth-cost-bench
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$here/micro-run.sh" "$here/contracts/micro/auth-cost.json" -- "$@"
