#!/usr/bin/env bash
# B01: identical-isolation comparisons on the reference host, as the bench
# user, after bench/b01-setup.sh prepared b01-scoped and b01-podman.
#   bench/b01-measure.sh KIT OUT
# KIT holds sentinel-bench and contracts/; OUT is the JSONL file appended to.
#
# 1. The Part 01 no-op floor, extended: a direct process, then the same
#    process in a systemd scope and in a container under identical caps
#    (1 CPU / 256 MiB, then the contract's 10 CPUs / 26 GiB).
# 2. The contract's `unit` lane (Lockwell's ci.yml `test` unit step) cold,
#    warm and small-edit, scoped and in a container, each on its own root.
set -euo pipefail
KIT=$1
OUT=$2
BENCH="$KIT/sentinel-bench"
CONTRACT="$KIT/contracts/lockwell-ci.json"
BUSYBOX=docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
cd "$HOME"
podman image exists "$BUSYBOX" || podman pull -q "$BUSYBOX" >/dev/null

# The runner refuses a contended start (CPU pressure avg60 >= 5 %), and a
# lane leaves its own pressure behind: wait for the host to settle first.
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

lane() { # lane <runtime> <lane> <condition>
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
