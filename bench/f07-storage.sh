#!/usr/bin/env bash
# F07 probe driver: SQLite commit/dispatch and directory cloning on each filesystem.
# Expects the sentinel-probes release binary as $PROBE and mount points for ext4/xfs/btrfs.
#
# Clone modes run in every round in a shuffled order with the caches dropped
# before each (see bench/k02-cache-clone.sh): the first mode to read the
# source would otherwise warm it for the rest. Records carry round, position
# and whether the drop succeeded (it needs root).
set -uo pipefail
PROBE="${PROBE:-/root/sentinel-probes}"
OUT="${OUT:-/root/f07-storage.jsonl}"; : > "$OUT"
ROUNDS="${ROUNDS:-3}"
# WSL drops loop mounts when the VM idles; remount the fixtures created for F07.
for fs in xfs btrfs; do mountpoint -q /mnt/f07-$fs || mount -o loop /srv/f07/$fs.img /mnt/f07-$fs || exit 1; done
df -T /root /mnt/f07-xfs /mnt/f07-btrfs | tail -3
declare -A FS=([ext4]=/root/f07-ext4 [xfs]=/mnt/f07-xfs/f07 [btrfs]=/mnt/f07-btrfs/f07)
# Flush, then empty the page, dentry and inode caches; prints true or false.
drop_caches() { sync; if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then echo true; else echo false; fi; }

for fs in ext4 xfs btrfs; do
  base="${FS[$fs]}"; rm -rf "$base"; mkdir -p "$base"
  for sync in full normal; do
    $PROBE sqlite --path "$base/dispatch.sqlite" --synchronous "$sync" --jobs 2000 --backlog 100000 \
      | sed "s/^{/{\"fs\":\"$fs\",/" >> "$OUT"
  done
  $PROBE generate --dest "$base/src" --files 20000 --bytes-per-file 16384 | sed "s/^{/{\"fs\":\"$fs\",/" >> "$OUT"
  for round in $(seq 1 "$ROUNDS"); do
    position=0
    for mode in $(printf '%s\n' reflink copy fs-copy | shuf); do
      position=$((position + 1))
      rm -rf "$base/dst-$mode"
      dropped=$(drop_caches)
      $PROBE clone --source "$base/src" --dest "$base/dst-$mode" --mode "$mode" --verify-read 2>"$base/err-$mode.txt" \
        | sed "s/^{/{\"fs\":\"$fs\",\"round\":$round,\"position\":$position,\"caches_dropped\":$dropped,/" >> "$OUT" \
        || echo "{\"fs\":\"$fs\",\"round\":$round,\"position\":$position,\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$base/err-$mode.txt" | tr -d '\n"')\"}" >> "$OUT"
      sync
    done
  done
  du -sm "$base"/dst-* 2>/dev/null | tr '\n' ' '; echo " ($fs apparent du after clones)"
done
echo "records: $(wc -l < "$OUT")"
