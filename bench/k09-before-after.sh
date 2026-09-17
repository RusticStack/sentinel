#!/usr/bin/env bash
# K09 before/after measurements (docs/benchmarking.md): two questions on
# one fixed host, answered by REAL attempts through the worker's own path
# via crates/sentinel-worker/examples/k07-recipes.rs — checkout,
# digest-pinned pull, cache restore, rootless Podman steps, publication.
#
#   1. no-op: the same trivial job without cache declarations
#      (noop-bare), with them on an empty store (noop-cache-cold) and
#      with them warm (noop-cache-warm) — what the cache path itself
#      costs a job that does nothing.
#   2. incremental build: the custom-tool recipe's small-source-edit
#      commit with no cache block (incremental-nocache), a wiped store
#      (incremental-cold) and a primed store (incremental-warm) — the
#      delta the cache buys real build work, and the delta it costs.
#
# Records land in $OUT as JSONL — a `meta` record first (host, kernel,
# filesystem, the WSL2 caveat), then one record per attempt exactly as
# the driver measured it. Nothing is simulated; a case that cannot run
# records `blocked` with the reason, never an invented number.
#
# Run inside WSL2 (rootless Podman) from the repo root:
#   bash bench/k09-before-after.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/fixtures/recipes"
PIPES="$ROOT/bench/k09"
WORK="${WORK:-/srv/k09}"
OUT="${OUT:-$ROOT/bench/k09-before-after.jsonl}"
DRIVER="${DRIVER:-$ROOT/target/wsl/release/examples/k07-recipes}"
LOGS="$WORK/logs"
SAMPLES="${SAMPLES:-7}"
IMG="docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"

mkdir -p "$WORK/prov" "$WORK/src" "$WORK/repos" "$WORK/worker" "$LOGS"

log() { printf 'k09 %s %s\n' "$(date +%T)" "$*" >&2; }

jstr() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

blocked() { # recipe case reason
    printf '{"recipe":%s,"case":%s,"status":"blocked","reason":%s}\n' \
        "$(jstr "$1")" "$(jstr "$2")" "$(jstr "$3")" >> "$OUT"
    log "blocked $1/$2: $3"
}

# Deterministic rep_<uuid> per recipe: cache scope is repo-bound, so all
# cases of a recipe must share one id across reruns.
repo_id() {
    python3 -c 'import hashlib,sys,uuid
b = bytearray(hashlib.sha256(sys.argv[1].encode()).digest()[:16])
b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
print("rep_" + str(uuid.UUID(bytes=bytes(b))))' "k09-$1"
}

meta_record() {
    python3 - "$WORK" <<'PY'
import json, platform, socket, subprocess, sys
work = sys.argv[1]
def sh(*args):
    try:
        return subprocess.run(args, capture_output=True, text=True).stdout.strip()
    except OSError:
        return ""
cpu = ""
for line in open("/proc/cpuinfo", errors="replace"):
    if line.startswith("model name"):
        cpu = line.split(":", 1)[1].strip()
        break
print(json.dumps({
    "record": "meta",
    "task": "k09",
    "host": {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "os": sh("lsb_release", "-ds").strip('"'),
        "cpu": cpu,
        "logical_cpus": __import__("os").cpu_count(),
        "podman": sh("podman", "version", "--format", "{{.Client.Version}}"),
        "workdir_fs": sh("df", "-T", work).split("\n")[-1].split()[1] if work else "",
        "caveat": "WSL2 development host — reference numbers, not a production qualification",
    },
}))
PY
}

# ---------------------------------------------------------------------
# Repos: a one-commit noop repo, and the custom-tool two-commit repo
# (base + edit-source overlay) with its checked-in package store.
# ---------------------------------------------------------------------

prov_custom_tool() { # $1 = shared dir
    mkdir -p "$1/pkgs" "$1/tools"
    cp "$ROOT/fixtures/compiler/fakecc.sh" "$1/tools/fakecc.sh" || return 1
    local spec n v d
    for spec in "liba 1.0.0" "libb 1.0.0" "libb 1.0.1"; do
        n="${spec%% *}"; v="${spec##* }"
        d="$(mktemp -d)"
        printf '%s %s\n' "$n" "$v" > "$d/lib.txt"
        tar -czf "$1/pkgs/$n-$v.pkg" -C "$d" lib.txt || return 1
        rm -rf "$d"
    done
}

git_at() { # dir, then args
    local d="$1"; shift
    git -C "$d" -c user.email=k09@example.com -c user.name=k09 "$@"
}

build_noop_repo() { # → echoes the sha
    local repo="$WORK/repos/noop"
    rm -rf "$repo"; mkdir -p "$repo"
    git_at "$repo" init -q -b main
    printf 'k09 noop\n' > "$repo/seed.txt"
    git_at "$repo" add -A
    git_at "$repo" commit -qm "k09 noop"
    git_at "$repo" rev-parse HEAD
}

# Base commit plus SAMPLES sequential small edits — each bumps
# lib_version, so every warm sample is a genuine "build after a small
# source edit": the store primed by the previous commit serves the
# unchanged input while the edited one compiles.
build_incremental_repo() { # → echoes "<base> <edit-1> ... <edit-N>"
    local repo="$WORK/repos/incremental" dest i
    rm -rf "$repo"; mkdir -p "$repo"
    git_at "$repo" init -q -b main
    dest="$WORK/src/incremental/base"
    rm -rf "$dest"; mkdir -p "$dest"
    cp -a "$FIX/custom-tool/tree/." "$dest/"
    (cd "$WORK/prov/custom-tool" && find . -mindepth 1 -maxdepth 1 ! -name .done -exec cp -a {} "$dest/" \;)
    cp -r "$dest/." "$repo/"
    git_at "$repo" add -A
    git_at "$repo" commit -qm "k09 incremental base"
    git_at "$repo" checkout -qb k09-src
    for i in $(seq "$SAMPLES"); do
        # The base tree's lib.c already returns 1 — the edits start at 2
        # so every commit is a real content change.
        printf 'int lib_version(void) { return %d; }\n' "$((i + 1))" > "$repo/src/lib.c"
        git_at "$repo" add -A
        git_at "$repo" commit -qm "k09 incremental edit-$i"
    done
    {
        git_at "$repo" rev-parse main
        for i in $(seq "$SAMPLES"); do
            git_at "$repo" rev-parse "k09-src~$((SAMPLES - i))"
        done
    } | tr '\n' ' '
    echo
}

run_case() { # recipe case pipeline sha
    local r="$1" c="$2" pipe="$3" sha="$4" rec
    rec="$("$DRIVER" \
        --pipeline "$pipe" --job build \
        --repo "$WORK/repos/$r" --sha "$sha" \
        --worker-dir "$WORK/worker/$r" \
        --image "$IMG" --repo-id "$(repo_id "$r")" \
        --recipe "$r" --case "$c" \
        --log-file "$LOGS/$r-$c.log" 2>"$LOGS/$r-$c.err")"
    if [ -n "$rec" ]; then
        printf '%s\n' "$rec" >> "$OUT"
        log "$r/$c: $(printf '%s' "$rec" | head -c 110)"
    else
        blocked "$r" "$c" "driver: $(tail -2 "$LOGS/$r-$c.err" 2>/dev/null | tr '\n' ' ' | head -c 140)"
    fi
}

: > "$OUT"
[ -x "$DRIVER" ] || { log "driver missing: $DRIVER — cargo build --release -p sentinel-worker --example k07-recipes"; exit 1; }
command -v python3 >/dev/null || { log "python3 required"; exit 1; }
command -v podman  >/dev/null || { log "podman required"; exit 1; }
meta_record >> "$OUT"

# --- 1. no-op: bare vs cold vs warm -----------------------------------

SHA_NOOP="$(build_noop_repo)"
[ -n "${SHA_NOOP:-}" ] || { log "noop repo failed"; exit 1; }
rm -rf "$WORK/worker/noop"
mkdir -p "$WORK/worker/noop"

for _ in $(seq "$SAMPLES"); do
    run_case noop noop-bare "$PIPES/noop-bare.yml" "$SHA_NOOP"
done
# The first declared run is the cold sample (absent → sealed); the rest
# are the warm steady state (hit → unchanged).
run_case noop noop-cache-cold "$PIPES/noop-cache.yml" "$SHA_NOOP"
for _ in $(seq "$SAMPLES"); do
    run_case noop noop-cache-warm "$PIPES/noop-cache.yml" "$SHA_NOOP"
done

# --- 2. incremental build: nocache vs cold vs warm ---------------------

if [ ! -f "$WORK/prov/custom-tool/.done" ]; then
    rm -rf "$WORK/prov/custom-tool"; mkdir -p "$WORK/prov/custom-tool"
    if prov_custom_tool "$WORK/prov/custom-tool" >> "$LOGS/prov.log" 2>&1; then
        touch "$WORK/prov/custom-tool/.done"
        log "provisioned custom-tool"
    else
        log "provisioning FAILED (see $LOGS/prov.log)"
        for c in incremental-nocache incremental-cold incremental-warm; do
            blocked incremental "$c" "provisioning failed (see prov.log)"
        done
        log "records: $(wc -l < "$OUT") -> $OUT"
        exit 0
    fi
fi

read -r -a SHAS <<< "$(build_incremental_repo)"
SHA_BASE="${SHAS[0]:-}"
SHA_EDIT="${SHAS[1]:-}"
if [ -z "$SHA_EDIT" ]; then
    for c in incremental-nocache incremental-cold incremental-warm; do
        blocked incremental "$c" "repo materialization failed"
    done
    log "records: $(wc -l < "$OUT") -> $OUT"
    exit 0
fi
log "incremental shas: base=${SHA_BASE:0:8} edits=${SHAS[*]:1}"
rm -rf "$WORK/worker/incremental"
mkdir -p "$WORK/worker/incremental"

# No cache block at all: a fresh small edit each sample, nothing
# persisted — the uncached incremental build.
for i in $(seq "$SAMPLES"); do
    run_case incremental incremental-nocache "$PIPES/incremental-nocache.yml" "${SHAS[$i]}"
done
# Cold store every sample: wipe the cache root, run the same new edit.
for i in $(seq "$SAMPLES"); do
    rm -rf "$WORK/worker/incremental/cache"
    run_case incremental incremental-cold "$FIX/custom-tool.yml" "${SHAS[$i]}"
done
# Warm store: prime with the BASE commit — the sealed namespace holds the
# old inputs' artifacts — then each sample is a fresh small edit:
# `deps.txt` is unchanged so every key still hits, and fakecc reuses the
# untouched input while the edited one compiles. That is the incremental
# build the cache buys.
rm -rf "$WORK/worker/incremental/cache"
run_case incremental incremental-prime "$FIX/custom-tool.yml" "$SHA_BASE"
for i in $(seq "$SAMPLES"); do
    run_case incremental incremental-warm "$FIX/custom-tool.yml" "${SHAS[$i]}"
done

log "records: $(wc -l < "$OUT") -> $OUT"
