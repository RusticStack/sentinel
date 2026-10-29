#!/usr/bin/env bash
# B05 cache-operation matrix on the verification host. Every cell holds the exclusive benchmark lock for its own run only.
#   b05-cache.sh [--profile full|smoke] synthetic <workdir> <label>   large trees, 10 GiB fixtures, concurrency (workdir picks the filesystem)
#   b05-cache.sh [--profile full|smoke] real <workdir> <label>        the real dependency/build trees left by b05-workloads.sh run
#   b05-cache.sh reflink-up <image> <mnt> <GiB> | reflink-down <mnt>  an XFS reflink loop filesystem
# The cells run in an order shuffled from SHUF_SEED (a fresh seed when unset) for each of PASSES passes (default 1);
# every record carries shuffle_seed, position and pass, so the order is replayable and a cell's neighbours are known.
# The smoke profile runs the same matrix with tiny parameters (no quiet host, no network, no real toolchain; see
# docs/benchmarking.md#b05-matrix-and-its-smoke-profile): it takes no lock unless B05_TAKE_LOCK=1 (the verification
# helper already holds it), exits 75 (pending) when CPU pressure avg10 is above 25, marks every record "smoke":true
# and refuses an OUT inside bench/, so a smoke record cannot be committed as a baseline.
# A cell that fails is counted: the script exits 1 naming each failed shape, and no record is faked for it.
set -uo pipefail

PROFILE=full
if [ "${1:-}" = --profile ]; then PROFILE="${2:-}"; shift 2 || true; fi
case "$PROFILE" in full|smoke) ;; *) echo "b05-cache: --profile must be full or smoke" >&2; exit 2 ;; esac

ROOT="${ROOT:-/srv/sentinel-p14-b05}"
BIN="${BIN:-$ROOT/target/release/examples/b05-cache}"
OUT="${OUT:-$ROOT/bench/b05-cache.jsonl}"
# One lock for every benchmark and verification run on the host (qualify.sh takes the same file).
LOCK="${SENTINEL_VERIFY_LOCK:-/var/tmp/sentinel-verify.lock}"
W="${B05_DATA:-$ROOT/data}/wl"
PASSES="${PASSES:-1}"
FAILED=0
FAILED_SHAPES=

# Every record carries the build and host stamp of bench/stamp.sh: SENTINEL_SRC names the checkout the
# measured driver came from (the driver binary is hashed), SENTINEL_BENCH_HOST_LABEL names the host.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/stamp.sh"
stamped() {
    SENTINEL_BIN="${SENTINEL_BIN:-$BIN}" stamp_init || exit 2
    B05_STAMP="$STAMP_BODY"
    export B05_STAMP
}

log() { printf 'b05-cache %s %s\n' "$(date +%T)" "$*" >&2; }

# Smoke records prove the plumbing, not a number: never into bench/, never on a busy host.
[ "$PROFILE" = smoke ] && smoke_guard "$OUT"

lockrun() {
    if [ "$PROFILE" = smoke ] && [ "${B05_TAKE_LOCK:-}" != 1 ]; then "$@"; else flock -x -o "$LOCK" "$@"; fi
}

cell() { # workdir label shape position pass [driver flags...]
    local work="$1" label="$2" shape="$3" position="$4" pass="$5"
    shift 5
    local extra="\"shuffle_seed\":\"$SHUF_SEED\",\"position\":$position,\"pass\":$pass"
    [ "$PROFILE" = smoke ] && extra="$extra,\"smoke\":true"
    log "$label $shape (position $position, pass $pass)"
    local B05_STAMP="$STAMP_BODY,$extra"
    export B05_STAMP
    lockrun ionice -c3 "$BIN" --work "$work/$shape" --shape "$shape" --label "$label" --out "$OUT" "$@" </dev/null \
        || { log "cell $label/$shape failed"; FAILED=$((FAILED + 1)); FAILED_SHAPES="$FAILED_SHAPES $shape"; }
    rm -rf "${work:?}/$shape"
}

run_cells() { # workdir label kind -- reads "shape<TAB>flags" lines on stdin
    local work="$1" label="$2" kind="$3" pass shape flags position cells
    cells=$(cat)
    for pass in $(seq 1 "$PASSES"); do
        position=0
        while IFS=$'\t' read -r shape flags; do
            [ -n "$shape" ] || continue
            position=$((position + 1))
            # shellcheck disable=SC2086  # flags is a word list on purpose
            cell "$work" "$label" "$shape" "$position" "$pass" $flags
        done < <(printf '%s\n' "$cells" | shuffle_lines "$SHUF_SEED/$kind/$pass")
    done
}

synthetic_cells() {
    if [ "$PROFILE" = smoke ]; then
        printf '%s\t%s\n' \
            mid-20k-8k "--small 60 --small-bytes 512 --samples 2 --cold-samples 1 --dirty 0,10 --modes lifecycle,concurrency --threads 1,2 --rounds 2" \
            tree-500k "--small 200 --small-bytes 128 --samples 2 --cold-samples 1 --dirty 0,10" \
            mix-10g "--small 40 --small-bytes 1024 --big 2 --big-bytes 262144 --samples 2 --cold-samples 1 --dirty 0,10" \
            big-10g "--big 3 --big-bytes 262144 --samples 2 --cold-samples 1 --dirty 0,10"
    else
        printf '%s\t%s\n' \
            mid-20k-8k "--small 20000 --small-bytes 8192 --samples 30 --cold-samples 5 --dirty 0,1,10,50 --modes lifecycle,concurrency --threads 1,2,4,8,12 --rounds 8" \
            tree-500k "--small 500000 --small-bytes 1024 --samples 5 --cold-samples 3 --dirty 0,1,10" \
            mix-10g "--small 98304 --small-bytes 30800 --big 8 --big-bytes 536870912 --samples 3 --cold-samples 2 --dirty 0,1,10" \
            big-10g "--big 10 --big-bytes 1073741824 --samples 3 --cold-samples 2 --dirty 0,1,10"
    fi
}

synthetic() {
    local work="$1" label="$2"
    stamped
    shuffle_init
    log "shuffle seed $SHUF_SEED"
    mkdir -p "$work"
    run_cells "$work" "$label" synthetic < <(synthetic_cells)
}

real_cells() {
    local dir name
    for dir in "$W"/*/e/* "$W"/js/src/node_modules; do
        [ -d "$dir" ] || continue
        name="real-$(basename "$(dirname "$(dirname "$dir")")")-$(basename "$dir")"
        [ "$(basename "$dir")" = node_modules ] && name=real-js-node_modules
        if [ "$PROFILE" = smoke ]; then
            printf '%s\t--src %s --samples 2 --cold-samples 1 --dirty 0,10\n' "$name" "$dir"
        else
            printf '%s\t--src %s --samples 10 --cold-samples 3 --dirty 0,1,10\n' "$name" "$dir"
        fi
    done
}

real() {
    local work="$1" label="$2"
    stamped
    shuffle_init
    log "shuffle seed $SHUF_SEED"
    mkdir -p "$work"
    run_cells "$work" "$label" real < <(real_cells)
}

reflink_up() {
    local img="$1" mnt="$2" gib="$3"
    [ "$PROFILE" = smoke ] && { echo "b05-cache: reflink-up needs a real loop device; the smoke profile excludes it" >&2; exit 2; }
    truncate -s "${gib}G" "$img" && mkfs.xfs -q -m reflink=1 "$img" && mkdir -p "$mnt" && mount -o loop "$img" "$mnt" && df -hT "$mnt"
}

reflink_down() {
    [ "$PROFILE" = smoke ] && { echo "b05-cache: reflink-down needs a real loop device; the smoke profile excludes it" >&2; exit 2; }
    umount "$1"
}

case "${1:-}" in
    synthetic) synthetic "$2" "$3" ;;
    real) real "$2" "$3" ;;
    reflink-up) reflink_up "$2" "$3" "$4" ;;
    reflink-down) reflink_down "$2" ;;
    *) echo "usage: $0 [--profile full|smoke] synthetic|real <workdir> <label> | reflink-up <image> <mnt> <GiB> | reflink-down <mnt>" >&2; exit 2 ;;
esac
rc=$?
if [ "$FAILED" -gt 0 ]; then
    log "$FAILED cell(s) failed;$FAILED_SHAPES; the matrix is incomplete"
    exit 1
fi
exit "$rc"
