#!/usr/bin/env bash
# The harness smoke: every bench harness, once, at tiny parameters, on a Linux verification host. Nothing it writes is a measurement.
#   bench/smoke.sh [--quick]
#     1. every Python unit test under bench/ (--quick leaves out the two slow ones, the B05 matrix and the B09 rehearsal);
#     2. the Q13 fleet driver's self-test;
#     3. `bench/micro-run.sh <contract> --smoke` for every contract in bench/contracts/micro/ whose binary is built.
# Each line says PASS, SKIP(no binary), SKIP(pending: the host is busy, or a measurement holds the lock) or FAIL. Pending and
# missing binaries are counted apart from passes and never turn the run red; a FAIL does (exit 1). A smoke run takes no
# lock and no quiet host, writes only under /var/tmp, and its records say "smoke": true. Local development stops at fmt and
# lint (CLAUDE.md, "Where tests run"): run this on the Linux verification host, from a disposable checkout.
# Environment: SENTINEL_SRC (default: this checkout), SENTINEL_BIN is not used (each contract's binary comes from
# CARGO_TARGET_DIR or ./target), SENTINEL_BENCH_HOST_LABEL (default smoke-host), SMOKE_CONTRACTS (default
# bench/contracts/micro), SMOKE_COMPILE=1 (also smoke the contracts that compile a test binary: the ignored measurement tests and M06) and
# SMOKE_SKIP_PY=1 (skip steps 1 and 2; the smoke script's own test uses it).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
quick=0
case "${1:-}" in --quick) quick=1 ;; "") ;; *) echo "usage: bench/smoke.sh [--quick]" >&2; exit 2 ;; esac
export SENTINEL_SRC="${SENTINEL_SRC:-$repo}" SENTINEL_BENCH_HOST_LABEL="${SENTINEL_BENCH_HOST_LABEL:-smoke-host}"
contracts="${SMOKE_CONTRACTS:-$here/contracts/micro}"
pass=0 pending=0 nobin=0 fail=0
report() { # status name
  case "$1" in
    PASS) pass=$((pass + 1)) ;;
    pending) pending=$((pending + 1)) ;;
    nobin) nobin=$((nobin + 1)) ;;
    *) fail=$((fail + 1)) ;;
  esac
}

if [ "${SMOKE_SKIP_PY:-0}" != 1 ]; then
  skip=()
  if [ "$quick" = 1 ]; then skip=(test_b05_matrix.py test_b09_rehearsal.py); fi
  mods=()
  for f in "$here"/test_*.py; do
    base="$(basename "$f")"
    case " ${skip[*]:-} " in *" $base "*) echo "SKIP(--quick) $base"; continue ;; esac
    mods+=("bench.${base%.py}")
  done
  if (cd "$repo" && python3 -m unittest "${mods[@]}") >"${TMPDIR:-/var/tmp}/smoke-unit.$$" 2>&1; then
    echo "PASS python unit tests (${#mods[@]} files)"; report PASS
  else
    tail -40 "${TMPDIR:-/var/tmp}/smoke-unit.$$"; echo "FAIL python unit tests"; report FAIL
  fi
  rm -f "${TMPDIR:-/var/tmp}/smoke-unit.$$"
  if (cd "$repo" && python3 bench/q13-fleet.py selftest) >/dev/null 2>&1; then
    echo "PASS q13 fleet self-test"; report PASS
  else
    echo "FAIL q13 fleet self-test"; report FAIL
  fi
fi

for c in "$contracts"/*.json; do
  [ -e "$c" ] || continue
  name="$(basename "$c" .json)"
  if [ "${SMOKE_COMPILE:-0}" != 1 ] && grep -q '"build": "cargo test' "$c"; then
    echo "SKIP(compiles a test binary; set SMOKE_COMPILE=1) $name"; report nobin; continue
  fi
  err="$(mktemp "${TMPDIR:-/var/tmp}/smoke-err.XXXXXX")"
  bash "$here/micro-run.sh" "$c" --smoke >/dev/null 2>"$err"
  rc=$?
  case "$rc" in
    0) echo "PASS $name"; report PASS ;;
    75) echo "SKIP(pending) $name: $(head -1 "$err")"; report pending ;;
    2) if grep -q "the bench binary is missing" "$err"; then echo "SKIP(no binary) $name"; report nobin
       else tail -5 "$err"; echo "FAIL $name (rc=2)"; report FAIL; fi ;;
    *) tail -5 "$err"; echo "FAIL $name (rc=$rc)"; report FAIL ;;
  esac
  rm -f "$err"
done

echo "smoke: $pass passed, $((pending + nobin)) skipped ($pending pending, $nobin without a binary), $fail failed"
[ "$fail" -eq 0 ]
