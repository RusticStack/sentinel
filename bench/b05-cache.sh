#!/usr/bin/env bash
# B05 cache-operation matrix on the verification VPS. Every cell holds the exclusive benchmark lock for its own run only.
#   b05-cache.sh synthetic <workdir> <label>    large trees, 10 GiB fixtures, concurrency (workdir picks the filesystem)
#   b05-cache.sh real <workdir> <label>         the real dependency/build trees left by b05-workloads.sh run
#   b05-cache.sh reflink-up <image> <mnt> <GiB> | reflink-down <mnt>   an XFS reflink loop filesystem
set -uo pipefail

ROOT="${ROOT:-/srv/sentinel-p14-b05}"
BIN="${BIN:-$ROOT/target/release/examples/b05-cache}"
OUT="${OUT:-$ROOT/bench/b05-cache.jsonl}"
LOCK=/srv/sentinel/runs/p14.lock
W="$ROOT/data/wl"
export B05_COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"
export B05_DIRTY="$([ -n "$(git -C "$ROOT" status --porcelain --untracked-files=no 2>/dev/null)" ] && echo true || echo false)"

log() { printf 'b05-cache %s %s\n' "$(date +%T)" "$*" >&2; }

cell() { # workdir label shape [driver flags...]
    local work="$1" label="$2" shape="$3"
    shift 3
    log "$label $shape"
    flock -x -o "$LOCK" ionice -c3 "$BIN" --work "$work/$shape" --shape "$shape" --label "$label" --out "$OUT" "$@" \
        || log "cell $label/$shape failed"
    rm -rf "${work:?}/$shape"
}

synthetic() {
    local work="$1" label="$2"
    mkdir -p "$work"
    cell "$work" "$label" mid-20k-8k --small 20000 --small-bytes 8192 --samples 30 --cold-samples 5 --dirty 0,1,10,50 \
        --modes lifecycle,concurrency --threads 1,2,4,8,12 --rounds 8
    cell "$work" "$label" tree-500k --small 500000 --small-bytes 1024 --samples 5 --cold-samples 3 --dirty 0,1,10
    cell "$work" "$label" mix-10g --small 98304 --small-bytes 30800 --big 8 --big-bytes 536870912 --samples 3 --cold-samples 2 --dirty 0,1,10
    cell "$work" "$label" big-10g --big 10 --big-bytes 1073741824 --samples 3 --cold-samples 2 --dirty 0,1,10
}

real() {
    local work="$1" label="$2" dir name
    mkdir -p "$work"
    for dir in "$W"/*/e/* "$W"/js/src/node_modules; do
        [ -d "$dir" ] || continue
        name="real-$(basename "$(dirname "$(dirname "$dir")")")-$(basename "$dir")"
        [ "$(basename "$dir")" = node_modules ] && name=real-js-node_modules
        cell "$work" "$label" "$name" --src "$dir" --samples 10 --cold-samples 3 --dirty 0,1,10
    done
}

reflink_up() {
    local img="$1" mnt="$2" gib="$3"
    truncate -s "${gib}G" "$img" && mkfs.xfs -q -m reflink=1 "$img" && mkdir -p "$mnt" && mount -o loop "$img" "$mnt" && df -hT "$mnt"
}

reflink_down() {
    umount "$1"
}

case "${1:-}" in
    synthetic) synthetic "$2" "$3" ;;
    real) real "$2" "$3" ;;
    reflink-up) reflink_up "$2" "$3" "$4" ;;
    reflink-down) reflink_down "$2" ;;
    *) echo "usage: $0 synthetic|real <workdir> <label> | reflink-up <image> <mnt> <GiB> | reflink-down <mnt>" >&2; exit 2 ;;
esac
