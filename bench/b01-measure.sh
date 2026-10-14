#!/usr/bin/env bash
set -euo pipefail
KIT=$1
OUT=$2
BENCH="$KIT/sentinel-bench"
CONTRACT="$KIT/contracts/lockwell-ci.json"
BUSYBOX=docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
cd "$HOME"
podman image exists "$BUSYBOX" || podman pull -q "$BUSYBOX" >/dev/null

# The runner refuses a contended start, and a lane leaves its own pressure behind: settle first.
settle() {
  for _ in $(seq 1 60); do
    awk '/^some/ { split($3, a, "="); exit !(a[2] < 2) }' /proc/pressure/cpu && return 0
    sleep 10
  done
  echo "the host did not settle under 2 % CPU pressure in 10 minutes" >&2
  return 1
}

noop() { "$BENCH" --workload noop --warm-state warm --label netcup-vps --output "$OUT" "$@"; }
settle
noop --runtime direct
for caps in "1 256m" "10 26g"; do
  set -- $caps
  noop --runtime scoped --cpus "$1" --memory "$2"
  noop --runtime podman --image "$BUSYBOX" --cpus "$1" --memory "$2"
done

lane() {
  settle
  local extra=()
  [ "$1" = scoped ] && extra=(--path-prepend "$HOME/b01-$1/toolchain/go/bin")
  "$BENCH" --contract "$CONTRACT" --lane "$2" --condition "$3" \
    --root "$HOME/b01-$1" --runtime "$1" "${extra[@]}" \
    --label netcup-vps --output "$OUT"
}
for condition in cold warm small-edit; do
  for runtime in scoped podman; do
    lane "$runtime" unit "$condition"
  done
done
echo "b01 done"
