#!/usr/bin/env bash
# M06: microVM start to first user process and to guest ready, cold and restored, on a KVM host (crates/sentinel-worker/tests/microvm.rs).
#   SENTINEL_SRC=/checkout SENTINEL_BENCH_HOST_LABEL=<label> bench/micro-run.sh bench/contracts/micro/m06-start.json -- [--samples N]
# The contract names this script as its harness: the runner takes the shared verification lock, refuses a busy host, stamps
# the build and host and appends the records to bench/m06-start.jsonl. This script runs the test once with
# SENTINEL_MICROVM_TESTS=1 (its opt-in to a test that boots VMs) and SENTINEL_MICROVM_BENCH=<samples> (200 by default),
# collects the two lines the test writes (cold, then restore, back to back) and prints them. The test needs the
# [microvm] setup of the worker (SENTINEL_MICROVM_KERNEL, ... as docs/microvm.md describes); a host without KVM or
# without that setup skips, and this script then exits 75, pending: a skipped test measured nothing.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="${SENTINEL_SRC:-$(cd "$here/.." && pwd)}"
samples=200
while [ $# -gt 0 ]; do
  case "$1" in
    --samples) samples="${2:?--samples needs a value}"; shift 2 ;;
    *) echo "m06-start: unknown argument $1" >&2; exit 2 ;;
  esac
done
case "$samples" in ''|*[!0-9]*|0) echo "m06-start: --samples must be a positive number" >&2; exit 2 ;; esac
work="$(mktemp -d "${TMPDIR:-/var/tmp}/m06-start.XXXXXX")"
trap 'rm -rf "$work"' EXIT
rc=0
(
  cd "$src"
  SENTINEL_MICROVM_TESTS=1 SENTINEL_MICROVM_BENCH="$samples" SENTINEL_MICROVM_BENCH_OUT="$work/records" \
    cargo test --release --locked -p sentinel-worker --test microvm -- --exact --nocapture \
    the_cold_and_restored_start_to_first_process_distributions
) >"$work/stdout" 2>"$work/stderr" || rc=$?
cat "$work/stderr" >&2
[ "$rc" -eq 0 ] || exit "$rc"
if grep -qi '^skipped' "$work/stderr"; then echo "m06-start: the test skipped itself, so it measured nothing" >&2; exit 75; fi
grep -q 'test result: ok\. 1 passed; 0 failed' "$work/stdout" "$work/stderr" || { echo "m06-start: the test did not run exactly once" >&2; exit 2; }
[ -s "$work/records" ] || { echo "m06-start: the test wrote no records" >&2; exit 2; }
[ "$(grep -c '^{' "$work/records")" -eq 2 ] || { echo "m06-start: expected one cold and one restore record" >&2; exit 2; }
grep '^{' "$work/records"
