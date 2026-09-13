#!/usr/bin/env bash
# F07 probe driver: SQLite commit/dispatch and directory cloning on each filesystem.
# Expects the sentinel-probes release binary as $PROBE and mount points for ext4/xfs/btrfs.
set -uo pipefail
PROBE="${PROBE:-/root/sentinel-probes}"
OUT="${OUT:-/root/f07-storage.jsonl}"; : > "$OUT"
# WSL drops loop mounts when the VM idles; remount the fixtures created for F07.
for fs in xfs btrfs; do mountpoint -q /mnt/f07-$fs || mount -o loop /srv/f07/$fs.img /mnt/f07-$fs || exit 1; done
df -T /root /mnt/f07-xfs /mnt/f07-btrfs | tail -3
declare -A FS=([ext4]=/root/f07-ext4 [xfs]=/mnt/f07-xfs/f07 [btrfs]=/mnt/f07-btrfs/f07)

for fs in ext4 xfs btrfs; do
  base="${FS[$fs]}"; rm -rf "$base"; mkdir -p "$base"
  for sync in full normal; do
    $PROBE sqlite --path "$base/dispatch.sqlite" --synchronous "$sync" --jobs 2000 --backlog 100000 \
      | sed "s/^{/{\"fs\":\"$fs\",/" >> "$OUT"
  done
  $PROBE generate --dest "$base/src" --files 20000 --bytes-per-file 16384 | sed "s/^{/{\"fs\":\"$fs\",/" >> "$OUT"
  sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null
  for mode in reflink copy fs-copy; do
    rm -rf "$base/dst-$mode"
    $PROBE clone --source "$base/src" --dest "$base/dst-$mode" --mode "$mode" --verify-read 2>"$base/err-$mode.txt" \
      | sed "s/^{/{\"fs\":\"$fs\",/" >> "$OUT" \
      || echo "{\"fs\":\"$fs\",\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$base/err-$mode.txt" | tr -d '\n"')\"}" >> "$OUT"
    sync
  done
  du -sm "$base"/dst-* 2>/dev/null | tr '\n' ' '; echo " ($fs apparent du after clones)"
done
echo "records: $(wc -l < "$OUT")"
