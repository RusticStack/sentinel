#!/usr/bin/env bash
# Release qualification (V05): one command that runs every qualification stage against a checkout
# (and, for the install stages, the release packages built from it) and writes a single pass/fail
# record. The stages are the existing verification binaries and scripts grouped by the question a
# release must answer; nothing here weakens or replaces them. See docs/qualification.md.
#
#   scripts/qualify/qualify.sh --src <checkout> --out <record-dir> [options]
#
#   --src DIR          the checkout under test (default: this script's repository)
#   --out DIR          where the record and per-stage logs go (must be empty or absent)
#   --server-pkg DIR   an extracted server package (enables the unit and local-mode install stages)
#   --worker-pkg DIR   an extracted worker package (same)
#   --dist DIR         the `package.sh assemble` output (enables the manifest stage)
#   --only a,b,c       run only these stage ids (the record is then INCOMPLETE, never PASS)
#   --list             print the stage ids and exit
#   --max-cpu-pressure N   postpone when /proc/pressure/cpu avg10 is above N (default 25)
#
# Run it on a verification host, from a disposable checkout (under /var/tmp or /tmp), as an
# unprivileged account with rootless Podman for the executor stages. It refuses a path under
# /srv/sentinel, touches no production service or data, and writes only below --out and the
# checkout's target directory (CARGO_TARGET_DIR, default <checkout>/target). Exit status:
# 0 PASS (every stage ran and passed), 1 FAIL (a stage failed), 3 INCOMPLETE (a stage was skipped
# for a missing prerequisite or not selected), 4 POSTPONED (the host is loaded; nothing ran). A
# skipped stage names its missing prerequisite in the record; a skip is never counted as a pass.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd); out=; server_pkg=; worker_pkg=; dist=; only=; max_pressure=25; list=0
while [ $# -gt 0 ]; do
  case $1 in
    --src) src=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --server-pkg) server_pkg=$2; shift 2 ;;
    --worker-pkg) worker_pkg=$2; shift 2 ;;
    --dist) dist=$2; shift 2 ;;
    --only) only=$2; shift 2 ;;
    --max-cpu-pressure) max_pressure=$2; shift 2 ;;
    --list) list=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

STAGE_IDS="manifest install-units local-mode upgrade recovery revocation worker-loss secrets caches diagnostics egress compat"
if [ "$list" = 1 ]; then printf '%s\n' $STAGE_IDS; exit 0; fi

[ -n "$out" ] || { echo "--out is required" >&2; exit 2; }
src=$(cd "$src" 2>/dev/null && pwd) || { echo "--src is not a directory" >&2; exit 2; }
case $src in /srv/sentinel|/srv/sentinel/*) echo "refusing to qualify inside /srv/sentinel" >&2; exit 2 ;; esac
[ -f "$src/Cargo.toml" ] && [ -f "$src/CLAUDE.md" ] || { echo "$src is not a Sentinel checkout" >&2; exit 2; }
mkdir -p "$out" || exit 2
out=$(cd "$out" && pwd)
case $out in /srv/sentinel|/srv/sentinel/*) echo "refusing to write inside /srv/sentinel" >&2; exit 2 ;; esac
[ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 2; }
if [ -n "$only" ]; then
  for s in ${only//,/ }; do case " $STAGE_IDS " in *" $s "*) ;; *) echo "unknown stage: $s" >&2; exit 2 ;; esac; done
fi
mkdir -p "$out/logs" "$out/scratch"
rec=$out/stages.jsonl; : >"$rec"

pressure=0
if [ -r /proc/pressure/cpu ]; then
  pressure=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' /proc/pressure/cpu | head -1)
  if awk -v p="${pressure:-0}" -v m="$max_pressure" 'BEGIN{exit !(p+0 > m+0)}'; then
    echo "POSTPONED: cpu pressure avg10=$pressure is above $max_pressure; nothing ran" | tee "$out/verdict.txt"
    exit 4
  fi
fi

export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-6}
[ "$CARGO_BUILD_JOBS" -le 6 ] 2>/dev/null || export CARGO_BUILD_JOBS=6
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$src/target}
export TMPDIR=$out/scratch
polite=; command -v nice >/dev/null && polite="nice -n 19"; command -v ionice >/dev/null && polite="$polite ionice -c3"
lock=${SENTINEL_VERIFY_LOCK:-/var/tmp/sentinel-verify.lock}
locked=; command -v flock >/dev/null && locked="flock -x $lock"

# Rootless Podman available to this account (not root, answers `podman info`)?
podman_ok=0; podman_why=
if [ "$(id -u)" = 0 ]; then podman_why="running as root; rootless Podman needs an unprivileged account"
elif ! command -v podman >/dev/null; then podman_why="podman is not installed"
elif ! podman info >/dev/null 2>&1; then podman_why="podman info fails for $(id -un) (subordinate ids or runtime directory)"
else podman_ok=1; fi

results_ok=0; results_fail=0; results_skip=0

record() { # id status seconds note
  python3 - "$rec" "$1" "$2" "$3" "$4" "$out/logs/$1.log" <<'PY'
import json, sys
rec, sid, status, secs, note, log = sys.argv[1:7]
with open(rec, "a") as f:
    f.write(json.dumps({"stage": sid, "status": status, "seconds": int(secs), "note": note, "log": log}) + "\n")
PY
}

selected() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0 ;; esac; return 1; }

skip() { # id reason
  if ! selected "$1"; then record "$1" not-selected 0 "not in --only"; results_skip=$((results_skip + 1)); return; fi
  echo "SKIP  $1: $2"; record "$1" skipped 0 "$2"; results_skip=$((results_skip + 1))
}

# run_stage id skipcheck|plain command...  The command runs in the checkout, serialized on the
# host verification lock, and passes only with exit status 0 (and, when asked, no "skipped:" line:
# a test that returns early because its environment is missing must not count as a pass).
run_stage() {
  local id=$1 mode=$2; shift 2
  if ! selected "$id"; then record "$id" not-selected 0 "not in --only"; results_skip=$((results_skip + 1)); return; fi
  local log=$out/logs/$id.log t0 t1 rc
  t0=$(date +%s)
  ( cd "$src" && $locked $polite "$@" ) >"$log" 2>&1; rc=$?
  t1=$(date +%s)
  if [ $rc -eq 0 ] && [ "$mode" = skipcheck ] && grep -q 'skipped:' "$log"; then
    rc=99; echo "a test reported 'skipped:'; its environment was incomplete" >>"$log"
  fi
  if [ $rc -eq 0 ]; then echo "PASS  $id ($((t1 - t0)) s)"; record "$id" passed $((t1 - t0)) ""; results_ok=$((results_ok + 1))
  else echo "FAIL  $id (exit $rc, $((t1 - t0)) s) log: $log"; record "$id" failed $((t1 - t0)) "exit $rc"; results_fail=$((results_fail + 1)); fi
}

# Words, not a function: the stage commands run under flock and nice, which exec a program.
NX="cargo nextest run --locked --all-features --no-fail-fast"

echo "qualifying $(git -C "$src" rev-parse --short=12 HEAD 2>/dev/null) at $(date -u +%FT%TZ) kernel=$(uname -r) cpus=$(nproc) cpu_pressure_avg10=$pressure"

# --- install ---------------------------------------------------------------------------------
if [ -n "$dist" ]; then
  run_stage manifest plain sh -c "scripts/release/test-verify-manifest.sh && python3 scripts/release/verify-manifest.py '$dist'"
else skip manifest "no --dist (the package.sh assemble output)"; fi

if [ -n "$server_pkg" ] && [ -n "$worker_pkg" ] && [ "$(id -u)" != 0 ]; then
  run_stage install-units plain sh -c "scripts/release/check-server-unit.sh '$server_pkg/bin/sentinel' && scripts/release/check-worker-unit.sh '$worker_pkg/bin/sentinel'"
else skip install-units "needs --server-pkg, --worker-pkg and an unprivileged account"; fi

if [ -n "$server_pkg" ] && [ -n "$worker_pkg" ] && [ $podman_ok = 1 ] && command -v unshare >/dev/null && unshare -rn true 2>/dev/null; then
  # The check needs a network namespace holding only loopback; an unprivileged account gets one
  # with `unshare -rn` (the check's own header describes the root form).
  run_stage local-mode plain unshare -rn sh -c "ip link set lo up; exec bash scripts/release/check-local-mode.sh '$server_pkg' '$worker_pkg' '$out/scratch/local-mode'"
else skip local-mode "needs --server-pkg, --worker-pkg, rootless Podman (${podman_why:-available}) and unprivileged user namespaces (unshare -rn)"; fi

# --- state and recovery ----------------------------------------------------------------------
run_stage upgrade plain $NX -p sentinel-store --test upgrade --test authorization --test storage
run_stage recovery plain $NX -p sentinel-store --test backup --test backup_drill --test replicate -p sentinel-worker --test recovery --test crash_consistency

# --- tenancy and loss ------------------------------------------------------------------------
run_stage revocation plain $NX -p sentinel-store --test tenancy --test tenant_access --test tenancy_isolation --test cross_tenant --test local_auth --test oauth_service --test oauth_tokens -p sentinel-api --test tenant_isolation -p sentinel --test tenant_isolation -p sentinel-link --test fleet
run_stage worker-loss plain $NX -p sentinel-store --test dispatch --test execution --test fleet --test faults -p sentinel-link --test link --test hardening --test handoff --test duplicate

# --- secrets, caches, diagnostics ------------------------------------------------------------
if [ $podman_ok = 1 ]; then
  export SENTINEL_PODMAN_TESTS=1
  run_stage secrets skipcheck $NX --no-capture -p sentinel-store --test secrets --test secret_scopes --test secret_delivery -p sentinel-worker --test secret_isolation -p sentinel --test secrets_cli
  run_stage caches skipcheck $NX --no-capture -p sentinel-cache -p sentinel-worker --test compiler_cache --test k09
else
  skip secrets "needs rootless Podman: $podman_why"; skip caches "needs rootless Podman: $podman_why"
fi
run_stage diagnostics plain $NX -p sentinel-store --test logs --test log_search --test bounds --test retention --test store -p sentinel-worker --test log_throughput --test log_write_faults --test spool_space

# --- egress ----------------------------------------------------------------------------------
if [ $podman_ok = 1 ]; then
  run_stage egress skipcheck $NX --no-capture -p sentinel-worker --test podman --test executor_faults --test runtime_failures
else skip egress "needs rootless Podman: $podman_why"; fi

# --- compatibility ---------------------------------------------------------------------------
run_stage compat plain sh -c "$NX -p sentinel-api --test api --test oauth_core -p sentinel --test client --test cli --test commands --test examples -p sentinel-pipeline && bash scripts/check-doc-links.sh"

# --- record ----------------------------------------------------------------------------------
if [ $results_fail -gt 0 ]; then verdict=FAIL; code=1
elif [ $results_skip -gt 0 ]; then verdict=INCOMPLETE; code=3
else verdict=PASS; code=0; fi
python3 - "$out" "$src" "$verdict" "$pressure" <<'PY'
import json, subprocess, sys, datetime, platform
out, src, verdict, pressure = sys.argv[1:5]
def git(*a):
    try: return subprocess.run(["git", "-C", src, *a], capture_output=True, text=True, check=True).stdout.strip()
    except Exception: return ""
stages = [json.loads(l) for l in open(out + "/stages.jsonl")]
rec = {
    "format": "sentinel.qualification/1",
    "verdict": verdict,
    "commit": git("rev-parse", "HEAD"),
    "dirty": bool(git("status", "--porcelain")),
    "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "kernel": platform.release(), "machine": platform.machine(),
    "cpu_pressure_avg10": float(pressure or 0),
    "counts": {s: sum(1 for x in stages if x["status"] == s) for s in ("passed", "failed", "skipped", "not-selected")},
    "stages": stages,
}
json.dump(rec, open(out + "/qualification.json", "w"), indent=1)
PY
echo "$verdict passed=$results_ok failed=$results_fail skipped=$results_skip record: $out/qualification.json" | tee "$out/verdict.txt"
exit $code
