#!/usr/bin/env bash
# Measure candidate [profile.release] settings (V01): build time and binary
# size of the server-role binary per variant, then the runtime of the commands
# an operator waits on, interleaved across variants so drift in host load lands
# on every one of them. Writes one JSON line per variant.
#
#   scripts/release/measure-profile.sh build   [variant...]
#   scripts/release/measure-profile.sh run     [variant...] > record.jsonl
#
# Run `build` and then `run` on a verification host (docs/development.md), the
# build under `nice -n 19 ionice -c3` with CARGO_BUILD_JOBS limited, the timing
# run on a quiet host. Variants default to all of them.
#
#   BASE      directory holding one target dir per variant (default $TMPDIR/sentinel-profile)
#   ROUNDS    timing rounds per variant (default 40; startup uses ROUNDS/4)
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
base=${BASE:-${TMPDIR:-/tmp}/sentinel-profile}
rounds=${ROUNDS:-40}

# name:lto:codegen-units
all="default:false:16 thin:thin:16 thin-cgu1:thin:1 fat-cgu1:fat:1"
mode=${1:-}
[ -n "$mode" ] || die "usage: measure-profile.sh build|run [variant...]"
shift
want=${*:-$(for v in $all; do echo "${v%%:*}"; done)}
spec() { for v in $all; do [ "${v%%:*}" = "$1" ] && echo "$v" && return; done; die "unknown variant $1"; }

case "$mode" in
  build)
    mkdir -p "$base"
    for name in $want; do
      IFS=: read -r _ lto cgu <<<"$(spec "$name")"
      start=$(date +%s.%N)
      CARGO_TARGET_DIR="$base/$name" CARGO_PROFILE_RELEASE_LTO=$lto CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$cgu \
        cargo build --locked --release -p sentinel --features server --manifest-path "$root/Cargo.toml"
      end=$(date +%s.%N)
      awk -v n="$name" -v a="$start" -v b="$end" 'BEGIN { printf "%s %.1f\n", n, b - a }' >"$base/$name.build-seconds"
      echo "built $name in $(cat "$base/$name.build-seconds")"
    done
    ;;
  run)
    export BASE_DIR=$base ROUNDS=$rounds ROOT=$root WANT="$want" ALL="$all"
    exec python3 - <<'PY'
import json, os, platform, signal, statistics, subprocess, tempfile, time

base, root, rounds = os.environ["BASE_DIR"], os.environ["ROOT"], int(os.environ["ROUNDS"])
specs = {s.split(":")[0]: s.split(":") for s in os.environ["ALL"].split()}
names = os.environ["WANT"].split()
binary = {n: f"{base}/{n}/release/sentinel" for n in names}
fixture = f"{root}/fixtures/pipelines/valid/full.yml"

def pressure():
    with open("/proc/pressure/cpu") as f:
        return f.readline().split()[1:3]

def timed(argv):
    t = time.perf_counter_ns()
    subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    return time.perf_counter_ns() - t

def startup(path):
    # Spawn to the API listening, on a fresh data directory (migrations, identity generation).
    with tempfile.TemporaryDirectory() as d:
        cfg = f"{d}/server.toml"
        with open(cfg, "w") as f:
            f.write("listen = '127.0.0.1:0'\napi_listen = '127.0.0.1:0'\nlog_format = 'json'\n")
        t = time.perf_counter_ns()
        p = subprocess.Popen([path, "server", "--config", cfg, "--data-dir", f"{d}/data"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            for line in p.stderr:
                if '"api_listening"' in line:
                    return time.perf_counter_ns() - t
            raise SystemExit("server exited before api_listening")
        finally:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=30)

def summary(xs):
    xs = sorted(xs)
    return {"count": len(xs), "min_ns": xs[0], "median_ns": int(statistics.median(xs)),
            "p95_ns": xs[min(len(xs) - 1, -(-95 * len(xs) // 100) - 1)]}

for n in names:
    timed([binary[n], "pipeline", "validate", fixture])  # page cache and dynamic loader warm-up

samples = {n: {"validate": [], "explain": [], "startup": []} for n in names}
before = pressure()
for r in range(rounds):
    order = names if r % 2 == 0 else names[::-1]  # reversed every round: ABBA
    for n in order:
        samples[n]["validate"].append(timed([binary[n], "pipeline", "validate", fixture]))
        samples[n]["explain"].append(timed([binary[n], "pipeline", "explain", "--json", fixture]))
        if r % 4 == 0:
            samples[n]["startup"].append(startup(binary[n]))
after = pressure()

commit = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
dirty = bool(subprocess.run(["git", "-C", root, "status", "--porcelain", "--untracked-files=no"],
                            capture_output=True, text=True).stdout.strip())
cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), "")
for n in names:
    size = os.path.getsize(binary[n])
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["strip", "-s", "-o", f"{d}/s", binary[n]], check=True)
        stripped = os.path.getsize(f"{d}/s")
    secs = float(open(f"{base}/{n}.build-seconds").read().split()[1])
    print(json.dumps({
        "schema": "sentinel-release-profile/1", "variant": n,
        "profile": {"lto": specs[n][1], "codegen_units": int(specs[n][2])},
        "build": {"wall_s": secs, "package": "sentinel", "features": ["server"]},
        "size_bytes": size, "size_stripped_bytes": stripped,
        "runtime": {"pipeline_validate": summary(samples[n]["validate"]),
                    "pipeline_explain_json": summary(samples[n]["explain"]),
                    "server_start_to_api": summary(samples[n]["startup"])},
        "rounds": rounds,
        "host": {"kernel": platform.release(), "cpu_model": cpu, "cpus_online": os.cpu_count()},
        "conditions": {"cpu_pressure_some_avg10_avg60_before": before, "after": after},
        "source": {"git_commit": commit, "git_dirty": dirty},
    }, separators=(",", ":")))
PY
    ;;
  *) die "usage: measure-profile.sh build|run [variant...]" ;;
esac
