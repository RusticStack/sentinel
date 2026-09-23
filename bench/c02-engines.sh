#!/usr/bin/env bash
# C02 engine comparison driver: SQLite (FULL, NORMAL) and redb (immediate,
# eventual) on the same dispatch workload, two repeats, one JSON line each.
#
# Provenance note: bench/c02-engines.jsonl (2026-09-13) was produced by an
# uncommitted invocation; this script was written afterwards from that
# record's shape (line order, and the "fs" and SQLite "engine" fields that
# the probes do not emit themselves) so the procedure can be repeated. It
# does not reproduce those numbers, which are host-specific; append a new
# record rather than replacing the old one.
#
# Expects the sentinel-probes release binary as $PROBE and a scratch
# directory on the filesystem under test as $DIR.
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
