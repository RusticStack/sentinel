#!/usr/bin/env bash
# One entry point for every in-process micro bench: reads the bench's contract (bench/contracts/micro/<id>.json),
# takes the shared verification lock for a measured run, refuses a host that is not quiet, stamps and appends the
# records. See bench/micro_contract.py for the rules.
#   SENTINEL_SRC=/checkout SENTINEL_BIN=target/release/examples/<bench> SENTINEL_BENCH_HOST_LABEL=<label> \
#     DIR=/var/tmp/<scratch> bench/micro-run.sh bench/contracts/micro/<id>.json [-- extra bench args]
#   bench/micro-run.sh bench/contracts/micro/<id>.json --smoke      tiny parameters, any host, no lock, exit 75 = pending
set -euo pipefail
exec python3 "$(dirname "${BASH_SOURCE[0]}")/micro_contract.py" run "$@"
