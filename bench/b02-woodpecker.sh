#!/usr/bin/env bash
# B02: the lockwell-ci contract's `unit` lane through Woodpecker's own
# executor (`woodpecker-cli exec`, Docker backend) on the bench user's
# rootless Podman socket, under the contract's caps. As the bench user,
# after bench/b01-setup.sh prepared ROOT:
#   bench/b02-woodpecker.sh CONTRACT ROOT WOODPECKER_CLI CONDITION SAMPLES WARMUP OUT
# Each run: wait for CPU pressure (avg60) under 2 %, run the contract's
# preparation for CONDITION (unmeasured), then time the whole exec, spawn to
# exit, with the monotonic clock. One JSON line per run is appended to OUT.
set -euo pipefail
CONTRACT=$1 ROOT=$(cd "$2" && pwd) CLI=$3 CONDITION=$4 SAMPLES=$5 WARMUP=$6 OUT=$7
LANE=unit
SOCK=unix:///run/user/$(id -u)/podman/podman.sock
PIPELINE="$ROOT/woodpecker-$LANE.yaml"

# The pipeline and the preparation, from the contract.
python3 - "$CONTRACT" "$ROOT" "$LANE" "$CONDITION" "$PIPELINE" "$ROOT/prepare.sh" <<'PY'
import json, sys
contract, root, lane_id, condition, pipeline, prepare = sys.argv[1:]
c = json.load(open(contract))
lane = next(l for l in c["lanes"] if l["id"] == lane_id)
def expand(text):
    text = text.replace("{root}", root)
    for s in c["sources"]:
        text = text.replace("{commit:%s}" % s["name"], s["commit"])
    return text
env = {k: expand(v) for k, v in {**c["environment"], **lane.get("env", {})}.items()}
src = root + "/" + c["sources"][0]["path"]
doc = {
    "skip_clone": True,
    "steps": [{
        "name": lane_id,
        "image": c["images"][lane["image"]],
        "volumes": [f"{root}:{root}"],
        "environment": env,
        "commands": [f"cd {src}", lane["run"]],
    }],
}
json.dump(doc, open(pipeline, "w"), indent=1)  # JSON is YAML
open(prepare, "w").write(expand(c["conditions"][condition]["prepare"]) + "\n")
PY

settle() {
  for _ in $(seq 1 60); do
    awk '/^some/ { split($3, a, "="); exit !(a[2] < 2) }' /proc/pressure/cpu && return 0
    sleep 10
  done
  echo "the host did not settle" >&2
  return 1
}

cpus=$(python3 -c "import json;print(json.load(open('$CONTRACT'))['allocation']['total']['cpus'])")
mem_bytes=$(( $(python3 -c "import json;print(json.load(open('$CONTRACT'))['allocation']['total']['memory'].rstrip('g'))") * 1024 * 1024 * 1024 ))
quota=$(( cpus * 100000 ))

total=$((WARMUP + SAMPLES))
for i in $(seq 1 "$total"); do
  settle
  pressure=$(awk '/^some/ { split($3, a, "="); print a[2] }' /proc/pressure/cpu)
  nonce=$(( $(date +%s%N) / 1000 ))
  sed "s/{sample_nonce}/$nonce/g" "$ROOT/prepare.sh" | sh >/dev/null
  start=$(date +%s%N)
  "$CLI" exec --backend-engine docker --backend-docker-host "$SOCK" \
    --repo-trusted-volumes \
    --backend-docker-limit-cpu-quota "$quota" \
    --backend-docker-limit-mem "$mem_bytes" \
    --backend-docker-limit-mem-swap "$mem_bytes" \
    "$PIPELINE" > "$ROOT/last-exec.log" 2>&1 || { echo "woodpecker exec failed, see $ROOT/last-exec.log" >&2; tail -20 "$ROOT/last-exec.log" >&2; exit 1; }
  end=$(date +%s%N)
  warm=$([ "$i" -le "$WARMUP" ] && echo true || echo false)
  printf '{"schema":"sentinel-bench/woodpecker-run/1","contract":{"id":"lockwell-ci","lane":"%s","condition":"%s","sha256":"%s"},"runtime":"woodpecker-exec-docker-on-rootless-podman","woodpecker":"%s","warmup":%s,"limits":{"cpu_quota":%d,"memory_bytes":%d,"memory_swap_bytes":%d},"cpu_pressure_avg60":%s,"elapsed_ns":%d}\n' \
    "$LANE" "$CONDITION" "$(sha256sum "$CONTRACT" | cut -c1-64)" "$("$CLI" --version | awk '{print $3}')" \
    "$warm" "$quota" "$mem_bytes" "$mem_bytes" "$pressure" "$((end - start))" >> "$OUT"
  echo "$CONDITION run $i: $(( (end - start) / 1000000 )) ms (warmup=$warm)"
done
