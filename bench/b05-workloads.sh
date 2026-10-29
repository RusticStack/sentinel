#!/usr/bin/env bash
# B05: measured rebuild cost per toolchain, and the real cache trees the rebuild leaves behind.
# Runs on the verification VPS from a clone (ROOT). Every timed command takes the exclusive benchmark lock on its own,
# so the lock is never held across a download or a setup step.
#   b05-workloads.sh tools            install the toolchains under data/tools (network)
#   b05-workloads.sh locks            resolve lockfiles into data/locks (network); commit them under bench/b05-fixtures
#   b05-workloads.sh run <lang>...    cold / downloads-only / warm job timings, n=REPS each, leaving the warm trees
#   b05-workloads.sh clean            delete data/tools, data/wl, data/locks
# Languages: go rust js python java custom
# Languages are measured in an order shuffled from SHUF_SEED for each repetition; every record names shuffle_seed and
# the language's position. `--profile smoke` (first argument) is the harness check: B05_DATA and B05_TOOLS point it at a
# scratch tree and at stub toolchains (bench/fake/b05), it takes no lock unless B05_TAKE_LOCK=1, exits 75 on a busy
# host, marks records "smoke":true and refuses an OUT inside bench/ (docs/benchmarking.md#b05-matrix-and-its-smoke-profile).
set -uo pipefail

PROFILE=full
if [ "${1:-}" = --profile ]; then PROFILE="${2:-}"; shift 2 || true; fi
case "$PROFILE" in full|smoke) ;; *) echo "b05: --profile must be full or smoke" >&2; exit 2 ;; esac

ROOT="${ROOT:-/srv/sentinel-p14-b05}"
D="${B05_DATA:-$ROOT/data}"
T="${B05_TOOLS:-$D/tools}"
W="$D/wl"
FX="$ROOT/bench/b05-fixtures"
LOCKS="$D/locks"
OUT="${OUT:-$ROOT/bench/b05-rebuild.jsonl}"
# One lock for every benchmark and verification run on the host (qualify.sh takes the same file).
LOCK="${SENTINEL_VERIFY_LOCK:-/var/tmp/sentinel-verify.lock}"
REPS="${REPS:-3}"
CUSTOM_COUNT="${CUSTOM_COUNT:-4096}"
CUSTOM_BYTES="${CUSTOM_BYTES:-262144}"
export PATH="$HOME/.cargo/bin:$T/go/bin:$T/jdk/bin:$T/maven/bin:$PATH"
# Stub toolchains (bench/fake/b05) sit in $T/bin and win over anything installed.
[ -n "${B05_TOOLS:-}" ] && export PATH="$T/bin:$PATH"
export JAVA_HOME="$T/jdk"
FAILED=0
POS=0

log() { printf 'b05 %s %s\n' "$(date +%T)" "$*" >&2; }

# Every record carries the build and host stamp of bench/stamp.sh (SENTINEL_SRC names the checkout the
# measured build came from, SENTINEL_BENCH_HOST_LABEL the host); b05-timed.sh splices it into each line.
. "$(dirname "${BASH_SOURCE[0]}")/stamp.sh"
stamped() {
    [ -n "${B05_STAMP:-}" ] && return 0
    stamp_init || exit 2
    shuffle_init
    B05_STAMP="$STAMP_BODY"
    [ "$PROFILE" = smoke ] && B05_STAMP="$B05_STAMP,\"smoke\":true"
    export B05_STAMP
}

# A smoke run takes no lock unless B05_TAKE_LOCK=1: the verification helper that started it already holds it.
lockrun() {
    if [ "$PROFILE" = smoke ] && [ "${B05_TAKE_LOCK:-}" != 1 ]; then "$@"; else flock -x -o "$LOCK" "$@"; fi
}

[ "$PROFILE" = smoke ] && smoke_guard "$OUT"

fixture() { # lang file -> path of the committed file, else the generated one
    if [ -f "$FX/$1/$2" ]; then echo "$FX/$1/$2"; else echo "$LOCKS/$1/$2"; fi
}

tm() { # lang variant step rep -- command...
    local lang="$1" variant="$2" step="$3" rep="$4"
    shift 5
    mkdir -p "$W/logs"
    log "$lang $variant $step rep$rep"
    lockrun bash "$ROOT/bench/b05-timed.sh" "$OUT" \
        "\"workload\":\"$lang\",\"variant\":\"$variant\",\"step\":\"$step\",\"rep\":$rep,\"shuffle_seed\":\"$SHUF_SEED\",\"position\":$POS" \
        "$W/logs/$lang-$variant-$step-$rep.log" -- "$@"
}

tools() {
    if [ -n "${B05_TOOLS:-}" ]; then echo "b05: B05_TOOLS names stub toolchains; there is nothing to install" >&2; exit 2; fi
    mkdir -p "$T"
    if [ ! -x "$T/go/bin/go" ]; then
        ver="$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)"
        curl -fsSL "https://go.dev/dl/$ver.linux-amd64.tar.gz" | tar -xz -C "$T"
    fi
    if [ ! -x "$T/jdk/bin/java" ]; then
        mkdir -p "$T/jdk"
        curl -fsSL "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" | tar -xz -C "$T/jdk" --strip-components=1
    fi
    if [ ! -x "$T/maven/bin/mvn" ]; then
        mkdir -p "$T/maven"
        curl -fsSL "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz" | tar -xz -C "$T/maven" --strip-components=1
    fi
    [ -f "$T/pip.pyz" ] || curl -fsSL https://bootstrap.pypa.io/pip/pip.pyz -o "$T/pip.pyz"
    {
        go version
        rustc -V
        cargo -V
        node -v
        npm -v
        python3 -V
        java -version 2>&1 | head -1
        mvn -v 2>&1 | head -1
    } > "$D/tool-versions.txt" 2>&1
    cat "$D/tool-versions.txt"
}

locks() {
    mkdir -p "$LOCKS"/{go,rust,js,python}
    local src
    src="$W/lock-go"; rm -rf "$src"; mkdir -p "$src"; cp "$FX"/go/*.go "$FX/go/go.mod" "$src/"
    (cd "$src" && GOFLAGS=-mod=mod GOTELEMETRY=off GOTOOLCHAIN=local GOPATH="$W/lock-gopath" go mod tidy) && cp "$src/go.mod" "$src/go.sum" "$LOCKS/go/"
    src="$W/lock-rust"; rm -rf "$src"; mkdir -p "$src"; cp -r "$FX/rust/." "$src/"
    (cd "$src" && CARGO_HOME="$W/lock-cargo" cargo generate-lockfile) && cp "$src/Cargo.lock" "$LOCKS/rust/"
    src="$W/lock-js"; rm -rf "$src"; mkdir -p "$src"; cp -r "$FX/js/." "$src/"
    (cd "$src" && npm install --package-lock-only --no-audit --no-fund) && cp "$src/package-lock.json" "$LOCKS/js/"
    src="$W/lock-py"; rm -rf "$src"; mkdir -p "$src"
    printf 'numpy\npandas\nscipy\nrequests\n' > "$src/requirements.in"
    python3 "$T/pip.pyz" install --quiet --target "$src/site" -r "$src/requirements.in" &&
        python3 "$T/pip.pyz" freeze --path "$src/site" > "$LOCKS/python/requirements.txt"
    cp "$src/requirements.in" "$LOCKS/python/"
    ls -R "$LOCKS" | head -20
}

# --- per-language job definitions: each prints/uses its entry directories via $E_* -------------------------------

prep() { # lang -> fresh project directory with committed sources and lockfiles
    local lang="$1" p="$W/$1"
    rm -rf "$p"; mkdir -p "$p/src"
    case "$lang" in
        go) cp "$FX"/go/*.go "$p/src/"; cp "$(fixture go go.mod)" "$(fixture go go.sum)" "$p/src/" ;;
        rust) cp -r "$FX/rust/." "$p/src/"; cp "$(fixture rust Cargo.lock)" "$p/src/" ;;
        js) cp -r "$FX/js/." "$p/src/"; cp "$(fixture js package-lock.json)" "$p/src/" ;;
        python) cp "$(fixture python requirements.txt)" "$p/src/" ;;
        java) cp -r "$FX/java/." "$p/src/" ;;
        custom) cp "$FX/custom/render.py" "$p/src/" ;;
    esac
    mkdir -p "$p/e"
}

rmtree() { chmod -R u+w "$@" 2>/dev/null; rm -rf "$@"; }

# Every job is a single command string run by bash -c under the lock; $P is the project directory.
job_cmd() { # lang state
    local lang="$1" state="$2" p="$W/$1"
    case "$lang" in
        go)
            local proxy="https://proxy.golang.org"
            [ "$state" = cold ] || proxy=off
            echo "cd $p/src && env GOPATH=$p/gopath GOMODCACHE=$p/e/mod GOCACHE=$p/e/build GOFLAGS=-mod=mod GOPROXY=$proxy GOTELEMETRY=off GOTOOLCHAIN=local sh -c 'go build ./... && go test ./...'" ;;
        rust)
            local offline=--offline
            [ "$state" = cold ] && offline=
            echo "cd $p/src && env CARGO_HOME=$p/e/cargo CARGO_TARGET_DIR=$p/e/target CARGO_BUILD_JOBS=4 sh -c 'cargo build --locked $offline && cargo test --locked $offline'" ;;
        js)
            echo "cd $p/src && env npm_config_cache=$p/e/npmcache sh -c 'if [ ! -d $p/src/node_modules/.bin ]; then npm ci --prefer-offline --no-audit --no-fund; fi; npx tsc -p .'" ;;
        python)
            echo "cd $p/src && sh -c 'if [ ! -d $p/e/wheelhouse ]; then python3 $T/pip.pyz download --quiet -d $p/e/wheelhouse -r requirements.txt; fi; if [ ! -d $p/e/site ]; then python3 $T/pip.pyz install --quiet --no-index --find-links $p/e/wheelhouse --target $p/e/site -r requirements.txt; fi; PYTHONPATH=$p/e/site python3 -c \"import numpy, pandas, scipy, requests\"'" ;;
        java)
            local offline=-o
            [ "$state" = cold ] && offline=
            echo "cd $p/src && mvn -B -q $offline -Dmaven.repo.local=$p/e/m2 package" ;;
        custom)
            echo "cd $p/src && sh -c 'if [ ! -d $p/e/assets ]; then python3 render.py $p/e/assets $CUSTOM_COUNT $CUSTOM_BYTES; fi'" ;;
    esac
}

# Which entries a state removes before the job: cold = all, deps = the build outputs only.
reset() { # lang state
    local lang="$1" state="$2" p="$W/$1"
    case "$state:$lang" in
        cold:*) rmtree "$p/e" "$p/src/node_modules" "$p/src/target" "$p/src/dist"; mkdir -p "$p/e" ;;
        deps:go) rmtree "$p/e/build" ;;
        deps:rust) rmtree "$p/e/target" ;;
        deps:js) rmtree "$p/src/node_modules" "$p/src/dist" ;;
        deps:python) rmtree "$p/e/site" ;;
        deps:java) rmtree "$p/src/target" ;;
        deps:custom) rmtree "$p/e/assets" ;;
    esac
}

measure() { # lang rep position: one repetition of the cold / deps / warm sequence for one language
    local lang="$1" rep="$2" state
    POS="$3"
    for state in cold deps warm; do
        [ "$lang" = custom ] && [ "$state" = deps ] && continue
        reset "$lang" "$state"
        tm "$lang" "$state" job "$rep" -- bash -c "$(job_cmd "$lang" "$state")" || { FAILED=$((FAILED + 1)); log "$lang $state rep$rep failed (see $W/logs)"; }
    done
}

report_trees() { # lang -> one line per entry directory: files, bytes, symlinks
    local lang="$1" p="$W/$1" dir
    for dir in "$p/e"/* "$p/src/node_modules"; do
        [ -d "$dir" ] || continue
        printf '{"record":"b05-tree","workload":"%s","entry":"%s","files":%s,"symlinks":%s,"bytes":%s,%s}\n' \
            "$lang" "$(basename "$(dirname "$dir")")/$(basename "$dir")" \
            "$(find "$dir" -type f | wc -l)" "$(find "$dir" -type l | wc -l)" \
            "$(du -sb --apparent-size "$dir" | cut -f1)" "$B05_STAMP"
    done >> "$OUT"
}

run() {
    local lang rep position
    stamped
    log "shuffle seed $SHUF_SEED"
    for lang in "$@"; do prep "$lang"; done
    # Repetitions are the outer loop and the languages are shuffled within each, so no language always runs first
    # (or right after the same neighbour) and a host that drifts over the run spreads over all of them.
    for rep in $(seq 1 "$REPS"); do
        position=0
        for lang in $(printf '%s\n' "$@" | shuffle_lines "$SHUF_SEED/rep$rep"); do
            position=$((position + 1))
            measure "$lang" "$rep" "$position"
        done
    done
    for lang in "$@"; do report_trees "$lang"; done
    if [ "$FAILED" -gt 0 ]; then
        log "$FAILED timed job(s) failed; the measurement is incomplete"
        return 1
    fi
}

clean() {
    # Stub toolchains are tracked files: B05_TOOLS is never deleted.
    if [ -n "${B05_TOOLS:-}" ]; then rmtree "$W" "$LOCKS"; else rmtree "$T" "$W" "$LOCKS"; fi
}

cmd="${1:-}"
shift || true
case "$cmd" in
    tools) tools ;;
    locks) locks ;;
    run) run "$@" ;;
    clean) clean ;;
    *) echo "usage: $0 [--profile full|smoke] tools|locks|run <lang>...|clean" >&2; exit 2 ;;
esac
