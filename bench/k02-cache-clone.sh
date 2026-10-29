#!/usr/bin/env bash
# Mode order must not decide the result: caches are dropped before each mode and modes are shuffled per round. Compare across rounds, not within one.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init || exit 1
shuffle_init
echo "shuffle seed $SHUF_SEED" >&2
STAMP_SED="$(stamp_sed)"
PROBE="${PROBE:-$PWD/target/wsl/release/sentinel-probes}"
OUT="${OUT:-bench/k02-cache-clone.jsonl}"
IMG="${IMG:-/srv/k02/btrfs.img}"
MNT="${MNT:-/mnt/k02-btrfs}"
EXT4="${EXT4:-/root/k02-ext4}"
FILES="${FILES:-20000}"; BYTES="${BYTES:-16384}"
LARGE="${LARGE:-4}"; LARGE_BYTES="${LARGE_BYTES:-67108864}"
ROUNDS="${ROUNDS:-5}"

record() { sed "s/^{/{\"fs\":\"$1\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_SED,/" >> "$OUT"; }
drop_caches() { sync; if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then echo true; else echo false; fi; }
placed() { sed "s/^{/{\"fs\":\"$1\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_SED,\"round\":$2,\"position\":$3,\"caches_dropped\":$4,/" >> "$OUT"; }

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
  # A snapshot source must be a subvolume, which ext4 cannot provide.
  [ "$fs" = btrfs ] && gen+=(--subvolume)
  $PROBE generate "${gen[@]}" | record "$fs"
  for round in $(seq 1 "$ROUNDS"); do
    position=0
    for mode in $(printf '%s\n' reflink copy snapshot | shuffle_lines "$SHUF_SEED/$fs/$round"); do
      position=$((position + 1))
      dst="$base/dst-$mode"
      btrfs subvolume delete "$dst" >/dev/null 2>&1 || rm -rf "$dst"
      err="$base/err-$mode.txt"
      dropped=$(drop_caches)
      $PROBE clone --source "$src" --dest "$dst" --mode "$mode" --verify-read 2>"$err" \
        | placed "$fs" "$round" "$position" "$dropped" \
        || echo "{\"fs\":\"$fs\",\"shuffle_seed\":\"$SHUF_SEED\",\"round\":$round,\"position\":$position,\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$err" | tr -d '\n"')\"}" >> "$OUT"
      sync
    done
  done
done
echo "records: $(wc -l < "$OUT")"
