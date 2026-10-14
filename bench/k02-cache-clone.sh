#!/usr/bin/env bash
# K02 probe driver: per-file FICLONE reflink vs whole-tree btrfs snapshot vs
# explicit copy, on a loop-mounted btrfs image plus an ext4 baseline.
#
# Mode order must not decide the result: the first mode to read the source
# warms its page cache for every later one. So each mode runs in every round,
# the order is shuffled per round (shuf), the caches are dropped immediately
# before each mode, and every record names its round, position in the round
# and whether the drop succeeded (it needs root; "false" means that record's
# cache state is unknown). Compare modes across rounds, not within one.
#
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
ROUNDS="${ROUNDS:-5}"

record() { sed "s/^{/{\"fs\":\"$1\",/" >> "$OUT"; }
# Flush, then empty the page, dentry and inode caches; prints true or false.
drop_caches() { sync; if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then echo true; else echo false; fi; }
# Prefix a clone record with where it ran in the sequence.
placed() { sed "s/^{/{\"fs\":\"$1\",\"round\":$2,\"position\":$3,\"caches_dropped\":$4,/" >> "$OUT"; }

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
  for round in $(seq 1 "$ROUNDS"); do
    position=0
    for mode in $(printf '%s\n' reflink copy snapshot | shuf); do
      position=$((position + 1))
      dst="$base/dst-$mode"
      btrfs subvolume delete "$dst" >/dev/null 2>&1 || rm -rf "$dst"
      err="$base/err-$mode.txt"
      dropped=$(drop_caches)
      $PROBE clone --source "$src" --dest "$dst" --mode "$mode" --verify-read 2>"$err" \
        | placed "$fs" "$round" "$position" "$dropped" \
        || echo "{\"fs\":\"$fs\",\"round\":$round,\"position\":$position,\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$err" | tr -d '\n"')\"}" >> "$OUT"
      sync
    done
  done
done
echo "records: $(wc -l < "$OUT")"
