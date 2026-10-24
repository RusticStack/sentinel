#!/usr/bin/env bash
# $DIR must sit on the filesystem under test; FS is recorded from it.
set -euo pipefail
PROBE="${PROBE:-target/release/sentinel-probes}"
DIR="${DIR:-/tmp/c02}"
FS="${FS:-}"
OUT="${OUT:-c02-engines.jsonl}"
mkdir -p "$DIR"
[ -n "$FS" ] || FS="$(findmnt -no FSTYPE -T "$DIR")"
for _repeat in 1 2; do
  for sync in full normal; do
    rm -f "$DIR"/dispatch.sqlite*
    "$PROBE" sqlite --path "$DIR/dispatch.sqlite" --synchronous "$sync" --jobs 2000 --backlog 100000 \
      | sed "s/^{/{\"fs\":\"$FS\",\"engine\":\"sqlite\",/" >> "$OUT"
  done
  for durability in immediate eventual; do
    rm -f "$DIR/dispatch.redb"
    "$PROBE" redb --path "$DIR/dispatch.redb" --durability "$durability" --jobs 2000 --backlog 100000 \
      | sed "s/^{/{\"fs\":\"$FS\",/" >> "$OUT"
  done
done
echo "records: $(wc -l < "$OUT")"
