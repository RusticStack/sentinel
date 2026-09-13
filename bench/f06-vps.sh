#!/usr/bin/env bash
# F06 probe: isolated vs concurrent Lockwell test commands on the CI VPS sandbox.
set -uo pipefail
cd "$HOME/work/repo" || exit 1
OUT="$HOME/f06"; mkdir -p "$OUT"
SLICE=/sys/fs/cgroup/user.slice/user-1000.slice
packages="$(go list ./... | grep -v '/tests/integration$')"
export LOCKWELL_SDK_NODE_DIR="$HOME/work/lockwell-sdk-node" LOCKWELL_SDK_JAVA_DIR="$HOME/work/lockwell-sdk-java"
export GOCACHE="$OUT/gocache"; rm -rf "$GOCACHE"; mkdir -p "$GOCACHE"
TIMEBIN=""; [[ -x /usr/bin/time ]] && TIMEBIN=/usr/bin/time

cgstat() { awk '/^usage_usec|^nr_throttled|^throttled_usec/{printf "%s=%s ", $1, $2}' "$SLICE/cpu.stat"; }
loadavg() { cut -d' ' -f1-3 /proc/loadavg; }

# phase <name> <logfile> <cmd...>: wall ns, rusage (if GNU time), cgroup deltas, load
phase() {
  local name="$1" log="$2"; shift 2
  local before after t0 t1 rc rus
  before="$(cgstat)"; t0=$(date +%s%N)
  if [[ -n "$TIMEBIN" ]]; then
    $TIMEBIN -f "user_s=%U sys_s=%S maxrss_kib=%M" -o "$OUT/$name.rusage" "$@" > "$log" 2>&1; rc=$?
    rus="$(tail -1 "$OUT/$name.rusage")"
  else
    "$@" > "$log" 2>&1; rc=$?; rus="rusage=unavailable"
  fi
  t1=$(date +%s%N); after="$(cgstat)"
  echo "PHASE name=$name rc=$rc wall_ns=$((t1-t0)) $rus before[$before] after[$after] load=$(loadavg)" | tee -a "$OUT/phases.log"
}

echo "== env" | tee "$OUT/phases.log"
go version | tee -a "$OUT/phases.log"; git rev-parse HEAD | tee -a "$OUT/phases.log"
echo "packages=$(echo "$packages" | wc -l) nproc=$(nproc) cpu.max=$(cat $SLICE/cpu.max) memory.max=$(cat $SLICE/memory.max)" | tee -a "$OUT/phases.log"
uptime | tee -a "$OUT/phases.log"

phase moddownload "$OUT/moddownload.log" go mod download
phase unit_cold "$OUT/unit_cold.json" go test -count=1 -json $packages
phase unit_warm "$OUT/unit_warm.json" go test -count=1 -json $packages
phase unit_buildonly_warm "$OUT/unit_buildonly.json" go test -count=1 -run '^$' -json $packages
phase race_cold "$OUT/race_cold.json" go test -count=1 -race -json $packages
phase race_warm "$OUT/race_warm.json" go test -count=1 -race -json $packages

# Concurrent: unit + race warm at the same time, as the CI DAG runs them.
before="$(cgstat)"; t0=$(date +%s%N)
( t=$(date +%s%N); go test -count=1 -json $packages > "$OUT/conc_unit.json" 2>&1; echo "conc_unit rc=$? wall_ns=$(( $(date +%s%N) - t ))" >> "$OUT/conc.log" ) &
( t=$(date +%s%N); go test -count=1 -race -json $packages > "$OUT/conc_race.json" 2>&1; echo "conc_race rc=$? wall_ns=$(( $(date +%s%N) - t ))" >> "$OUT/conc.log" ) &
wait
t1=$(date +%s%N); after="$(cgstat)"
echo "PHASE name=concurrent_unit_race wall_ns=$((t1-t0)) before[$before] after[$after] load=$(loadavg)" | tee -a "$OUT/phases.log"
cat "$OUT/conc.log" | tee -a "$OUT/phases.log"

python3 - "$OUT" <<'PY' | tee -a "$OUT/phases.log"
import json,sys,os,collections
out=sys.argv[1]
for name in ["unit_warm","race_warm","conc_unit","conc_race"]:
    pk=collections.defaultdict(float); tests=[]
    for line in open(os.path.join(out,name+".json"),errors="replace"):
        try: e=json.loads(line)
        except Exception: continue
        if e.get("Action") in ("pass","fail","skip") and "Elapsed" in e:
            if "Test" in e: tests.append((e["Elapsed"],e["Package"],e["Test"]))
            else: pk[e["Package"]]=e["Elapsed"]
    top=sorted(pk.items(),key=lambda kv:-kv[1])[:10]
    print(f"== {name}: packages={len(pk)} sum_pkg_elapsed_s={sum(pk.values()):.0f} max_pkg_s={max(pk.values()) if pk else 0:.0f}")
    for p,s in top: print(f"   pkg {s:7.1f}s {p}")
    tests.sort(reverse=True)
    for s,p,t in tests[:10]: print(f"   test {s:7.1f}s {p} {t}")
PY
echo DONE_F06
