#!/usr/bin/env bash
# The Wave 1 verification gate (TODO.md), as one repeatable run per verification host. Each stage is
# a command TODO.md's Wave 1 names, run the way CLAUDE.md#where-tests-run requires, and the run
# leaves one record with a log per stage. Nothing here adds a check or weakens one. See
# docs/wave1-gate.md.
#
#   scripts/verify/wave1.sh --host reference-host|arm64-host|kvm-host --out <record-dir> [options]
#
#   --host LABEL       which host this is; the anonymized label is all the record says about it
#   --out DIR          where the record and the per-stage logs go (must be empty or absent)
#   --src DIR          the disposable checkout under test (default: this script's repository)
#   --only a,b,c       run only these stage ids (the record is then INCOMPLETE, never PASS)
#   --list             print the host's stage ids and exit
#   --plan             print each stage's command and what it needs; runs nothing, works anywhere
#   --detach           run in the background: log in <record-dir>.log, PID in <record-dir>.pid
#   --browser-runs N   how many times the browser suite runs (default 5)
#   --power-loss       also run power_cut_on_dm_flakey (root and dm-flakey; loop devices only)
#   --max-cpu-pressure N   a stage is recorded pending when /proc/pressure/cpu avg10 is above N (default 25)
#
# The host rules it follows: the checkout and the record live under /var/tmp (or /tmp), never under
# /srv/sentinel; every stage runs under `nice -n 19 ionice -c3` with CARGO_BUILD_JOBS at most 6 and
# under `flock -x -o` on the shared verification lock; CPU pressure is read before every stage and a
# loaded host leaves the stage pending instead of running it; nothing is installed, no service is
# stopped, restarted or reconfigured, and no process is stopped by pattern. A stage whose
# prerequisite is missing is skipped with the reason; a skip or a pending stage is never a pass.
# Exit status: 0 PASS, 1 FAIL, 2 usage or a refused path, 3 INCOMPLETE.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/../.." && pwd); out=; host=; only=; max_pressure=25; browser_runs=5; power_loss=0; phase=run; detach=0
args=("$@")
while [ $# -gt 0 ]; do
  case $1 in
    --host) host=${2:-}; shift 2 ;;
    --out) out=${2:-}; shift 2 ;;
    --src) src=${2:-}; shift 2 ;;
    --only) only=${2:-}; shift 2 ;;
    --max-cpu-pressure) max_pressure=${2:-}; shift 2 ;;
    --browser-runs) browser_runs=${2:-}; shift 2 ;;
    --power-loss) power_loss=1; shift ;;
    --list) phase=list; shift ;;
    --plan) phase=plan; shift ;;
    --detach) detach=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case $host in
  reference-host|kvm-host) want_machine=x86_64 ;;
  arm64-host) want_machine=aarch64 ;;
  *) echo "--host must be reference-host, arm64-host or kvm-host" >&2; exit 2 ;;
esac
case $browser_runs in ''|*[!0-9]*|0) echo "--browser-runs must be a positive number" >&2; exit 2 ;; esac

# Words, not functions: a stage's command runs under flock and nice, which exec a program.
NX="cargo nextest run --locked --all-features --no-fail-fast"
PODMAN_SUITES="-p sentinel-worker --test podman --test end_to_end --test images --test executor_faults --test prefetch --test slice --test secret_isolation --test recovery"
BROWSER="cargo test --locked --all-features -p sentinel-api --test web_browser -- --ignored --test-threads=1 --skip measure_the_web_interface --skip serve_the_fixture"

# What Wave 1 lists that no script can settle; the record carries it so a PASS never implies it.
NOT_AUTOMATED=(
  "V02: build the container and web images, podman compose --profile web up, podman healthcheck run, SIGTERM, the Quadlet dry run, and the web image's licence-inventory decision"
  "web/bench/web-bench.mjs once against a live sentinel-web"
  "refresh the generic Git timings in docs/generic-git-verification.md on the G08 fixtures"
  "RW05's members:read check (owner prerequisite X3)"
  "Forgejo over SSH and GitLab over HTTPS (G08a, owner prerequisite X7)"
  "fixing each failure at its cause, and ticking a Closes entry only where its own contract holds"
)

ids=()
selected() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0 ;; esac; return 1; }
pressure_now() {
  local f=${SENTINEL_PRESSURE_FILE:-/proc/pressure/cpu}
  [ -r "$f" ] && sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' "$f" | head -1
}
record() { # id status seconds note
  python3 - "$out/stages.jsonl" "$1" "$2" "$3" "$4" "$out/logs/$1.log" <<'PY'
import hashlib, json, os, sys
rec, sid, status, secs, note, log = sys.argv[1:7]
row = {"stage": sid, "status": status, "seconds": int(secs), "note": note}
if os.path.exists(log):
    with open(log, "rb") as f:
        row["log"], row["log_sha256"] = "logs/" + os.path.basename(log), hashlib.sha256(f.read()).hexdigest()
with open(rec, "a") as f:
    f.write(json.dumps(row) + "\n")
PY
}

# stage ID plain|skipcheck NEEDS WHY COMMAND...
# NEEDS says what the stage requires beyond the toolchain; WHY is empty when this host has it, and
# otherwise the reason the stage is skipped. `skipcheck` fails a stage whose log holds a `skipped:`
# line: a test that returns early because its environment is incomplete must not count as a pass.
stage() {
  local id=$1 mode=$2 needs=$3 why=$4; shift 4
  case $phase in
    list) ids+=("$id"); return ;;
    plan) selected "$id" || return 0
          printf '%s\n  run:   %s\n  needs: %s\n' "$id" "$*" "${needs:-the pinned toolchain}"; return ;;
  esac
  if ! selected "$id"; then record "$id" not-selected 0 "not in --only"; n_skip=$((n_skip + 1)); return; fi
  if [ -n "$why" ]; then echo "SKIP  $id: $why"; record "$id" skipped 0 "$why"; n_skip=$((n_skip + 1)); return; fi
  local p; p=$(pressure_now)
  if awk -v p="${p:-0}" -v m="$max_pressure" 'BEGIN{exit !(p+0 > m+0)}'; then
    echo "PEND  $id: cpu pressure avg10=$p is above $max_pressure"
    record "$id" pending 0 "cpu pressure avg10=$p is above $max_pressure; the host is loaded"; n_skip=$((n_skip + 1)); return
  fi
  local log=$out/logs/$id.log t0 t1 rc
  t0=$(date +%s)
  ( cd "$src" && $locked $polite "$@" ) >"$log" 2>&1; rc=$?
  t1=$(date +%s)
  if [ $rc -eq 0 ] && [ "$mode" = skipcheck ] && grep -q 'skipped:' "$log"; then
    rc=99; echo "a test reported 'skipped:'; its environment was incomplete" >>"$log"
  fi
  if [ $rc -eq 0 ]; then echo "PASS  $id ($((t1 - t0)) s)"; record "$id" passed $((t1 - t0)) ""; n_ok=$((n_ok + 1))
  else echo "FAIL  $id (exit $rc, $((t1 - t0)) s) log: $log"; record "$id" failed $((t1 - t0)) "exit $rc"; n_fail=$((n_fail + 1)); fi
}

stages() {
  local podman="rootless Podman as an unprivileged account"
  if [ "$host" != arm64-host ]; then
    # Run 1: the static checks and the full suites.
    stage static plain "" "" sh -c "cargo fmt-check && cargo lint && cargo lint-linux"
    stage licenses plain "cargo-deny" "$deny_why" cargo licenses
    stage test-linux plain "" "" cargo test-linux
    stage test-cli plain "" "" cargo test-cli
  fi
  case $host in
    reference-host)
      # Run 2, and the Podman part of run 6.
      stage podman skipcheck "$podman" "$podman_why" env SENTINEL_PODMAN_TESTS=1 $NX --no-capture $PODMAN_SUITES
      stage bootstrap skipcheck "$podman, the base images pulled" "$podman_why" \
        env SENTINEL_PODMAN_TESTS=1 cargo test --locked --all-features -p sentinel-api --test worker_bootstrap_script -- --ignored
      stage git-fixtures plain "$podman" "$podman_why" \
        sh -c "bash scripts/git-fixtures/run.sh exercise && $NX -p sentinel --test git_fixtures"
      # Run 4. The toolchain is aligned by root beforehand (bench/hosts/align-toolchain.sh); this run installs nothing.
      stage web plain "pnpm 12.15 (bench/hosts/align-toolchain.sh)" "$pnpm_why" \
        sh -c "pnpm -C web install && pnpm -C web typecheck && pnpm -C web build && pnpm -C web test:unit"
      stage browser plain "the web stage's build and a Chromium-family browser (SENTINEL_BROWSER when it is not on PATH)" "$pnpm_why" \
        sh -c "n=1; while [ \$n -le $browser_runs ]; do echo \"== browser run \$n of $browser_runs\"; $BROWSER || exit 1; n=\$((n + 1)); done"
      # Run 5.
      stage pending-suites plain "" "" $NX -p sentinel-mail --test lane --test resend \
        -p sentinel-store --test email_identity --test setup --test mfa --test sign_in \
        -p sentinel-api --test email --test setup --test account --test github_sign_in \
        -p sentinel --test setup_token --test mfa_admin
      # Run 6.
      stage power-cut skipcheck "--power-loss, root and dm-flakey" "$power_why" \
        env SENTINEL_POWER_LOSS_TESTS=1 $NX --no-capture -p sentinel-worker --test crash_consistency -E "test(power_cut_on_dm_flakey)"
      # The stage holds the verification lock, which the smoke would otherwise read as a measurement's.
      stage bench plain "python3" "" env SMOKE_COMPILE=1 SENTINEL_VERIFY_LOCK_HELD=1 bash bench/smoke.sh
      stage doc-links plain "" "" bash scripts/check-doc-links.sh
      ;;
    arm64-host)
      # Run 3.
      stage test-worker plain "" "" cargo test-worker
      stage podman skipcheck "$podman" "$podman_why" env SENTINEL_PODMAN_TESTS=1 $NX --no-capture $PODMAN_SUITES
      ;;
    kvm-host)
      # Not in Wave 1's Needs: the job suites once more under Firecracker, on the host that has KVM.
      stage microvm skipcheck "$podman, /dev/kvm, SENTINEL_FIRECRACKER, SENTINEL_GUEST_KERNEL and SENTINEL_GUEST_AGENT" "$microvm_why" \
        env SENTINEL_MICROVM_TESTS=1 SENTINEL_PODMAN_TESTS=1 $NX --no-capture -p sentinel-worker --test microvm --test end_to_end --test slice --test k09 --test secret_isolation
      ;;
  esac
}

deny_why=; podman_why=; pnpm_why=; power_why=; microvm_why=
if [ $phase != run ]; then
  [ $phase = plan ] && echo "# $host: nothing below was run"
  stages
  [ $phase = list ] && printf '%s\n' "${ids[@]}"
  exit 0
fi

# --- the run -----------------------------------------------------------------------------------
[ -n "$out" ] || { echo "--out is required" >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo "refusing: tests run on a Linux verification host, not on $(uname -s)" >&2; exit 2; }
if grep -qi microsoft /proc/version 2>/dev/null; then echo "refusing: tests never run in WSL" >&2; exit 2; fi
[ "$(uname -m)" = "$want_machine" ] || { echo "refusing: $host is $want_machine, this machine is $(uname -m)" >&2; exit 2; }
src=$(cd "$src" 2>/dev/null && pwd -P) || { echo "--src is not a directory" >&2; exit 2; }
[ -f "$src/Cargo.toml" ] && [ -f "$src/CLAUDE.md" ] || { echo "$src is not a Sentinel checkout" >&2; exit 2; }
case $src in /var/tmp/*|/tmp/*) ;; *) echo "refusing: $src is not a disposable checkout under /var/tmp" >&2; exit 2 ;; esac
mkdir -p "$out" || exit 2
out=$(cd "$out" && pwd -P)
case $out in /var/tmp/*|/tmp/*) ;; *) echo "refusing: the record directory $out is not under /var/tmp" >&2; exit 2 ;; esac
[ -z "$(ls -A "$out")" ] || { echo "$out is not empty" >&2; exit 2; }
phase=list; stages; phase=run
if [ -n "$only" ]; then
  for s in ${only//,/ }; do case " ${ids[*]} " in *" $s "*) ;; *) echo "unknown stage for $host: $s" >&2; exit 2 ;; esac; done
fi
for tool in git python3 cargo flock nice ionice; do
  command -v $tool >/dev/null || { echo "$tool is missing on this host" >&2; exit 2; }
done
cargo nextest --version >/dev/null 2>&1 || { echo "cargo-nextest is missing (bench/hosts/align-toolchain.sh)" >&2; exit 2; }

if [ $detach = 1 ]; then
  rmdir "$out"
  keep=(); for a in "${args[@]}"; do [ "$a" = --detach ] || keep+=("$a"); done
  setsid nohup "$0" "${keep[@]}" >"$out.log" 2>&1 </dev/null &
  echo $! >"$out.pid"
  echo "started: PID $! (stop it with kill $!), log $out.log, record $out"
  exit 0
fi

mkdir -p "$out/logs" "$out/scratch"
: >"$out/stages.jsonl"
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-6}
[ "$CARGO_BUILD_JOBS" -le 6 ] 2>/dev/null || export CARGO_BUILD_JOBS=6
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$src/target}
export TMPDIR=$out/scratch
if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then export XDG_RUNTIME_DIR=/run/user/$(id -u); fi
polite="nice -n 19 ionice -c3"
# -o: what a stage leaves behind (a VMM, a setsid'd worker, podman's conmon) must not inherit the
# lock descriptor and keep the host locked after the stage returns.
locked="flock -x -o ${SENTINEL_VERIFY_LOCK:-/var/tmp/sentinel-verify.lock}"

cargo deny --version >/dev/null 2>&1 || deny_why="cargo-deny is not installed"
if [ "$(id -u)" = 0 ]; then podman_why="running as root; rootless Podman needs an unprivileged account"
elif ! command -v podman >/dev/null; then podman_why="podman is not installed"
elif ! podman info >/dev/null 2>&1; then podman_why="podman info fails for this account (subordinate ids or runtime directory)"; fi
case $(pnpm --version 2>/dev/null) in 12.15.*) ;; *) pnpm_why="pnpm 12.15 is not on PATH; root runs bench/hosts/align-toolchain.sh first" ;; esac
if [ $power_loss = 0 ]; then power_why="not asked for (--power-loss)"
elif [ "$(id -u)" != 0 ]; then power_why="needs root for dm-flakey on a loop device"; fi
if [ "$host" = kvm-host ]; then
  microvm_why=$podman_why
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || microvm_why="this account cannot open /dev/kvm"
  for v in SENTINEL_FIRECRACKER SENTINEL_GUEST_KERNEL SENTINEL_GUEST_AGENT; do
    [ -e "${!v:-}" ] || microvm_why="$v does not name a file"
  done
fi

n_ok=0; n_fail=0; n_skip=0
start_pressure=$(pressure_now)
echo "wave 1 gate on $host: $(git -C "$src" rev-parse --short=12 HEAD 2>/dev/null) at $(date -u +%FT%TZ) kernel=$(uname -r) cpus=$(nproc) cpu_pressure_avg10=${start_pressure:-unreadable}"
stages

if [ $n_fail -gt 0 ]; then verdict=FAIL; code=1
elif [ $n_skip -gt 0 ]; then verdict=INCOMPLETE; code=3
else verdict=PASS; code=0; fi
python3 - "$out" "$src" "$verdict" "$host" "${start_pressure:-}" "${NOT_AUTOMATED[@]}" <<'PY'
import datetime, json, platform, subprocess, sys
out, src, verdict, host, pressure = sys.argv[1:6]
def git(*a):
    try: return subprocess.run(["git", "-C", src, *a], capture_output=True, text=True, check=True).stdout.strip()
    except Exception: return ""
def tool(*a):
    try: return subprocess.run(a, capture_output=True, text=True, check=True).stdout.splitlines()[0].strip()
    except Exception: return None
with open(out + "/stages.jsonl") as f:
    stages = [json.loads(l) for l in f]
rec = {
    "format": "sentinel.wave1-gate/1",
    "verdict": verdict,
    "host": host,
    "commit": git("rev-parse", "HEAD"),
    "dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
    "finished": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "kernel": platform.release(), "machine": platform.machine(),
    "toolchain": {"rustc": tool("rustc", "--version"), "nextest": tool("cargo", "nextest", "--version"),
                  "podman": tool("podman", "--version"), "pnpm": tool("pnpm", "--version")},
    "counts": {s: sum(1 for x in stages if x["status"] == s)
               for s in ("passed", "failed", "skipped", "pending", "not-selected")},
    "stages": stages,
    "not_automated": sys.argv[6:],
}
if pressure:
    rec["cpu_pressure_avg10_at_start"] = float(pressure)
with open(out + "/wave1.json", "w") as f:
    json.dump(rec, f, indent=1)
PY
rm -rf "$out/scratch"
echo "$verdict $host passed=$n_ok failed=$n_fail skipped-or-pending=$n_skip record: $out/wave1.json" | tee "$out/verdict.txt"
exit $code
