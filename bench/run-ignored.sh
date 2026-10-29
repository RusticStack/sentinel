#!/usr/bin/env bash
# Runs one #[ignore] measurement test under a micro-contract and stamps what it prints (docs/benchmarking.md#ignored-measurement-tests).
#   bench/run-ignored.sh [--list-only] PACKAGE TEST_TARGET TEST_NAME
# The contracts q09-fleet-load, queue-explain, backup-drill, remote-cost and tailcat-live name it as their script harness:
#   bench/micro-run.sh bench/contracts/micro/<id>.json            (measured: lock, quiet host, stamped record)
#   bench/micro-run.sh bench/contracts/micro/<id>.json --smoke    (lists the test; runs nothing)
# The test's environment (SENTINEL_DRILL_DIR, SENTINEL_REMOTE_COST_DIR, SENTINEL_TAILCAT_LIVE, ...) is the caller's; see the test file.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$here/run_ignored.py" "$@"
