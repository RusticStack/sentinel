#!/usr/bin/env bash
# Sourced by bench scripts that write records without going through sentinel-bench or a Python harness.
#   stamp_init        requires SENTINEL_SRC (checkout the measured build came from), optional SENTINEL_BIN;
#                     sets STAMP_BODY, the record fields `"build":{...},"host":{...}` (no braces around them).
#                     Tracked changes only decide `dirty`; untracked files are ignored.
#   stamp_sed         STAMP_BODY escaped for the replacement side of sed.
#   shuffle_init      sets SHUF_SEED from $SHUF_SEED or a fresh value; it is written into every record.
#   shuffle_lines S   shuffles stdin deterministically from the string S (same S, same input, same order).
# Run directly it prints the stamp object: SENTINEL_SRC=. SENTINEL_BIN=target/release/sentinel bench/stamp.sh
_stamp_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

stamp_init() {
  : "${SENTINEL_SRC:?set SENTINEL_SRC to the checkout the measured build came from (and SENTINEL_BIN to its binary)}"
  local obj
  obj=$(python3 "$_stamp_dir/b03-latency.py" --source "$SENTINEL_SRC" ${SENTINEL_BIN:+--binary "$SENTINEL_BIN"} --print-stamp) || return 1
  STAMP_BODY="${obj#\{}"; STAMP_BODY="${STAMP_BODY%\}}"
}

stamp_sed() { local s="$STAMP_BODY"; s="${s//\/\\}"; s="${s//&/\&}"; s="${s//\//\/}"; printf '%s' "$s"; }

shuffle_init() { SHUF_SEED="${SHUF_SEED:-$(date +%s%N)-$$}"; }

shuffle_lines() {
  local seed="$1" i=0
  shuf --random-source=<(while [ "$i" -lt 64 ]; do printf '%s/%s' "$seed" "$i" | sha256sum; i=$((i + 1)); done)
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then stamp_init && printf '{%s}\n' "$STAMP_BODY"; fi
