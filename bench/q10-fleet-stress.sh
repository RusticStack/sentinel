#!/usr/bin/env bash
# Stress-runs the placement fleet suites and records every run, with the assertion of every test that failed.
# The fleet binaries measure real TLS sessions and `.config/nextest.toml` orders them one test at a time, so
# what a run sees of scheduling is what the dispatcher sees: beside SPIN busy loops the controller's session
# threads are descheduled between frames the way they are when another suite shares the host.
#   SENTINEL_SRC=/checkout SENTINEL_BENCH_HOST_LABEL=<label> SPIN=2 ITER=20 bench/q10-fleet-stress.sh
# The host label is anonymized (`SENTINEL_BENCH_HOST_LABEL`); bench/stamp.sh stamps the build and host, and one
# record per run is appended to bench/q10-fleet-stress.jsonl. PHASE names the tree under test (`before`, `after`).
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/stamp.sh"
stamp_init || exit 1
: "${SENTINEL_BENCH_HOST_LABEL:?set SENTINEL_BENCH_HOST_LABEL to an anonymized host label}"
src="${SENTINEL_SRC:?set SENTINEL_SRC to the checkout under test}"
iter=${ITER:-20}
spin=${SPIN:-0}
phase=${PHASE:-after}
out="${OUT:-$here/q10-fleet-stress.jsonl}"
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done; }
trap cleanup EXIT
for _ in $(seq 1 "$spin"); do (while :; do :; done) & pids+=($!); done
for i in $(seq 1 "$iter"); do
  log="$(mktemp "${TMPDIR:-/tmp}/q10-stress.XXXXXX")"
  start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  ( cd "$src" && CARGO_INCREMENTAL=0 cargo nextest run --locked --no-fail-fast \
      --failure-output immediate -p sentinel-link --test fleet --test fleet_sessions ) >"$log" 2>&1
  rc=$?
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$i" "$rc" "$start" "$end" "$log" "$out" "$phase" "$spin" "$STAMP_BODY" <<'RECORD'
import json, re, sys
it, rc, start, end, log, out, phase, spin, stamp = sys.argv[1:]
lines = open(log, errors="replace").read().splitlines()
summary = re.search(r"(\d+) tests run: (\d+) passed(?:, (\d+) failed)?(?:, (\d+) skipped)?",
                    "\n".join(lines))
pat = re.compile(r"\s*FAIL \[\s*[0-9.]+s\] \(\s*\d+/\d+\) (.+)$")
failed = sorted({m.group(1).strip() for m in (pat.match(l) for l in lines) if m})
# nextest prints a failing test's own output inline; a panic names the file and line of the assertion.
assertions = []
for at, line in enumerate(lines):
    if "panicked at " in line:
        assertions.append({"at": line.split("panicked at ", 1)[1].rstrip(":"),
                           "lines": [l.strip() for l in lines[at + 1:at + 6] if l.strip()]})
record = {
    "schema": "sentinel-bench/fleet-stress/1",
    "phase": phase,
    "iteration": int(it),
    "spinners": int(spin),
    "test": {
        "package": "sentinel-link",
        "binaries": ["fleet", "fleet_sessions"],
        "exit": int(rc),
        "run": int(summary.group(1)) if summary else None,
        "passed": int(summary.group(2)) if summary else None,
        "failed": int(summary.group(3) or 0) if summary else None,
        "skipped": int(summary.group(4) or 0) if summary else None,
    },
    "failed_tests": failed,
    "assertions": assertions,
    "conditions": {"start": start, "end": end},
}
record.update(json.loads("{" + stamp + "}"))
with open(out, "a") as f:
    f.write(json.dumps(record, separators=(",", ":")) + "\n")
print(f"{phase} {it}: exit {rc} " + (", ".join(failed) or "clean"))
RECORD
  if [ "$rc" = 0 ]; then rm -f "$log"; else
    kept="${KEEP_FAILED_DIR:-$HOME/.capy/work/q10}/fleet-stress-$phase-$i.log"
    mkdir -p "$(dirname "$kept")" && cp "$log" "$kept" && rm -f "$log"
    echo "kept $kept"
  fi
done
