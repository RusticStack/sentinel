#!/usr/bin/env bash
# K02 probe driver: per-file FICLONE reflink vs whole-tree btrfs snapshot vs
# explicit copy, on a loop-mounted btrfs image plus an ext4 baseline.
# Run as root inside WSL from the repo root:
#   PROBE=target/wsl/release/sentinel-probes bash bench/k02-cache-clone.sh
set -uo pipefail
PROBE="${PROBE:-$PWD/target/wsl/release/sentinel-probes}"
OUT="${OUT:-bench/k02-cache-clone.jsonl}"
IMG="${IMG:-/srv/k02/btrfs.img}"
MNT="${MNT:-/mnt/k02-btrfs}"
EXT4="${EXT4:-/root/k02-ext4}"
FILES="${FILES:-20000}"; BYTES="${BYTES:-16384}"
LARGE="${LARGE:-4}"; LARGE_BYTES="${LARGE_BYTES:-67108864}"

record() { sed "s/^{/{\"fs\":\"$1\",/" >> "$OUT"; }

mkdir -p "$(dirname "$IMG")" "$MNT" "$EXT4"
if ! mountpoint -q "$MNT"; then
  [ -f "$IMG" ] || truncate -s 8G "$IMG"
  mkfs.btrfs -f "$IMG" >/dev/null 2>&1 || { echo "mkfs.btrfs failed"; exit 1; }
  mount -o loop "$IMG" "$MNT" || exit 1
fi
df -T "$MNT" "$EXT4" | tail -2
: > "$OUT"

for fs in ext4 btrfs; do
  case "$fs" in ext4) base="$EXT4/work";; btrfs) base="$MNT/work";; esac
  rm -rf "$base"; mkdir -p "$base"
  src="$base/src"
  gen=(--dest "$src" --files "$FILES" --bytes-per-file "$BYTES"
       --large-files "$LARGE" --large-bytes "$LARGE_BYTES")
  # A snapshot source must be a subvolume; ext4 has no such thing.
  [ "$fs" = btrfs ] && gen+=(--subvolume)
  $PROBE generate "${gen[@]}" | record "$fs"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
  for mode in reflink copy snapshot; do
    dst="$base/dst-$mode"
    btrfs subvolume delete "$dst" >/dev/null 2>&1 || rm -rf "$dst"
    err="$base/err-$mode.txt"
    $PROBE clone --source "$src" --dest "$dst" --mode "$mode" --verify-read 2>"$err" \
      | record "$fs" \
      || echo "{\"fs\":\"$fs\",\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$err" | tr -d '\n"')\"}" >> "$OUT"
    sync
  done
done
echo "records: $(wc -l < "$OUT")"
