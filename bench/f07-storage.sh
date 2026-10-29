#!/usr/bin/env bash
# Caches are dropped before each clone and modes are shuffled per round: the first mode to read the source would warm it.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamp_init || exit 1
shuffle_init
echo "shuffle seed $SHUF_SEED" >&2
STAMP_SED="$(stamp_sed)"
PROBE="${PROBE:-/root/sentinel-probes}"
OUT="${OUT:-/root/f07-storage.jsonl}"; : > "$OUT"
ROUNDS="${ROUNDS:-3}"
# WSL drops loop mounts when the VM idles; remount the loop-mounted fixtures.
for fs in xfs btrfs; do mountpoint -q /mnt/f07-$fs || mount -o loop /srv/f07/$fs.img /mnt/f07-$fs || exit 1; done
df -T /root /mnt/f07-xfs /mnt/f07-btrfs | tail -3
declare -A FS=([ext4]=/root/f07-ext4 [xfs]=/mnt/f07-xfs/f07 [btrfs]=/mnt/f07-btrfs/f07)
drop_caches() { sync; if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then echo true; else echo false; fi; }

for fs in ext4 xfs btrfs; do
  base="${FS[$fs]}"; rm -rf "$base"; mkdir -p "$base"
  for sync in full normal; do
    $PROBE sqlite --path "$base/dispatch.sqlite" --synchronous "$sync" --jobs 2000 --backlog 100000 \
      | sed "s/^{/{\"fs\":\"$fs\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_SED,/" >> "$OUT"
  done
  $PROBE generate --dest "$base/src" --files 20000 --bytes-per-file 16384 | sed "s/^{/{\"fs\":\"$fs\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_SED,/" >> "$OUT"
  for round in $(seq 1 "$ROUNDS"); do
    position=0
    for mode in $(printf '%s\n' reflink copy fs-copy | shuffle_lines "$SHUF_SEED/$fs/$round"); do
      position=$((position + 1))
      rm -rf "$base/dst-$mode"
      dropped=$(drop_caches)
      $PROBE clone --source "$base/src" --dest "$base/dst-$mode" --mode "$mode" --verify-read 2>"$base/err-$mode.txt" \
        | sed "s/^{/{\"fs\":\"$fs\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_SED,\"round\":$round,\"position\":$position,\"caches_dropped\":$dropped,/" >> "$OUT" \
        || echo "{\"fs\":\"$fs\",\"shuffle_seed\":\"$SHUF_SEED\",$STAMP_BODY,\"round\":$round,\"position\":$position,\"probe\":\"clone/1\",\"mode\":\"$mode\",\"error\":\"$(head -c 120 "$base/err-$mode.txt" | tr -d '\n"\\')\"}" >> "$OUT"
      sync
    done
  done
  du -sm "$base"/dst-* 2>/dev/null | tr '\n' ' '; echo " ($fs apparent du after clones)"
done
echo "records: $(wc -l < "$OUT")"
