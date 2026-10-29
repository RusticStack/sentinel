#!/usr/bin/env bash
# Sourced by bench scripts that write records without going through sentinel-bench or a Python harness.
#   stamp_init        requires SENTINEL_SRC (checkout the measured build came from), optional SENTINEL_BIN;
#                     sets STAMP_BODY, the record fields `"build":{...},"host":{...}` (no braces around them).
#                     Needs SENTINEL_BENCH_HOST_LABEL (an anonymized label) and a readable commit and dirty state:
#                     bench/benchstamp.py refuses otherwise, before anything is measured.
#                     Tracked changes only decide `dirty`; untracked files are ignored.
#   stamp_sed         STAMP_BODY escaped for the replacement side of sed.
#   shuffle_init      sets SHUF_SEED from $SHUF_SEED or a fresh value; it is written into every record.
#   shuffle_lines S   shuffles stdin deterministically from the string S (same S, same input, same order).
#   smoke_guard OUT   for a tiny-parameter harness check: exits 2 when OUT is inside bench/ (a smoke record must never be
#                     committed as a baseline) and exits 75, "pending", when CPU pressure avg10 is above 25.
# Run directly it prints the stamp object: SENTINEL_SRC=. SENTINEL_BIN=target/release/sentinel bench/stamp.sh
_stamp_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

stamp_init() {
  : "${SENTINEL_SRC:?set SENTINEL_SRC to the checkout the measured build came from (and SENTINEL_BIN to its binary)}"
  local obj
  obj=$(python3 "$_stamp_dir/benchstamp.py" --source "$SENTINEL_SRC" ${SENTINEL_BIN:+--binary "$SENTINEL_BIN"}) || return 1
  STAMP_BODY="${obj#\{}"; STAMP_BODY="${STAMP_BODY%\}}"
}

stamp_sed() { printf '%s' "$STAMP_BODY" | sed -e 's/[\\/&]/\\&/g'; }

smoke_guard() {
  local out_dir p10
  out_dir="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)" || out_dir=
  case "$out_dir/" in "$(cd "$_stamp_dir" && pwd -P)/"*) echo "a smoke run never writes into bench/ ($1)" >&2; exit 2 ;; esac
  if [ -r "${SENTINEL_PRESSURE_FILE:-/proc/pressure/cpu}" ]; then
    p10=$(sed -n 's/^some .*avg10=\([0-9.]*\).*/\1/p' "${SENTINEL_PRESSURE_FILE:-/proc/pressure/cpu}" | head -1)
    if awk -v p="${p10:-0}" 'BEGIN{exit !(p+0 > 25)}'; then echo "pending: cpu pressure avg10=$p10; the host is busy" >&2; exit 75; fi
  fi
}

shuffle_init() { SHUF_SEED="${SHUF_SEED:-$(date +%s%N)-$$}"; }

shuffle_lines() {
  local seed="$1" i=0
  shuf --random-source=<(while [ "$i" -lt 64 ]; do printf '%s/%s' "$seed" "$i" | sha256sum; i=$((i + 1)); done)
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then stamp_init && printf '{%s}\n' "$STAMP_BODY"; fi
