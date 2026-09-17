#!/usr/bin/env bash
# K07 recipe measurements: nine cache/environment recipes (custom tool,
# Go, Rust, npm, pnpm, Bun, Python, Maven, Gradle) each run through five
# cases — cold, warm, small-edit, changed-dependency, changed-toolchain —
# as REAL attempts via crates/sentinel-worker/examples/k07-recipes.rs
# (checkout, digest-pinned pull, cache restore, rootless Podman steps,
# cache publication). One JSON record per case lands in $OUT.
#
# Measured steps run with --network none: every dependency comes from a
# checked-in store — pkgs/ tarballs, a file:// Go module proxy, a cargo
# local-registry, a file:// Maven repo — the same shapes a private mirror
# serves in production. Provisioning builds those stores once, with the
# real tools, into $WORK/prov (it may use the network; measurements do
# not).
#
# A recipe whose store cannot be provisioned records `blocked` for every
# case — never an invented number.
#
# Run inside WSL2 (rootless Podman) from the repo root:
#   bash bench/k07-recipes.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIX="$ROOT/fixtures/recipes"
WORK="${WORK:-/srv/k07}"
OUT="${OUT:-$ROOT/bench/k07-recipes.jsonl}"
DRIVER="${DRIVER:-$ROOT/target/wsl/release/examples/k07-recipes}"
LOGS="$WORK/logs"
RECIPES="${RECIPES:-custom-tool go rust npm pnpm bun python maven gradle}"

mkdir -p "$WORK/prov" "$WORK/src" "$WORK/repos" "$WORK/worker" "$LOGS"

log() { printf 'k07 %s %s\n' "$(date +%T)" "$*" >&2; }

jstr() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }

blocked() { # recipe case reason
    printf '{"recipe":%s,"case":%s,"status":"blocked","reason":%s}\n' \
        "$(jstr "$1")" "$(jstr "$2")" "$(jstr "$3")" >> "$OUT"
    log "blocked $1/$2: $3"
}

# Deterministic rep_<uuid> per recipe: cache scope is repo-bound, so all
# five cases of a recipe must share one id across reruns.
repo_id() {
    python3 -c 'import hashlib,sys,uuid
b = bytearray(hashlib.sha256(sys.argv[1].encode()).digest()[:16])
b[6] = (b[6] & 0x0F) | 0x40; b[8] = (b[8] & 0x3F) | 0x80
print("rep_" + str(uuid.UUID(bytes=bytes(b))))' "k07-$1"
}

# Pinned digest pairs: A is the recipe's own image, B the toolchain change.
declare -A IMG_A IMG_B
IMG_A[custom-tool]="docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
IMG_B[custom-tool]="docker.io/library/busybox@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
IMG_A[go]="docker.io/library/golang@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59"
IMG_B[go]="docker.io/library/golang@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191"
IMG_A[rust]="docker.io/library/rust@sha256:1716b3aa042d735f4566d14dc54e8037de9d69556e2d5dd58131d93a613d173d"
IMG_B[rust]="docker.io/library/rust@sha256:45c1c35cd364b8055e9e86f8ecd3e8c874b2dcb658d8a4f94b5d111aa0d651a2"
IMG_A[npm]="docker.io/library/node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32"
IMG_B[npm]="docker.io/library/node@sha256:50c8e8ca1d27439048670df5883f32d57cf81cff6233222c893fd0d9884cbd81"
IMG_A[pnpm]="${IMG_A[npm]}"
IMG_B[pnpm]="${IMG_B[npm]}"
IMG_A[bun]="docker.io/oven/bun@sha256:d888c0ae6c86d7866ff10c5aafdd9077b36aee6455b33dd270fb93c0dd5cef6f"
IMG_B[bun]="docker.io/oven/bun@sha256:0841c588f6304300baf1d395ae339ce09a6e18c4b6a7cdd4fddcbdb87a2f096a"
IMG_A[python]="docker.io/library/python@sha256:7415fbc3c9e4979cc717d92377ab2bc7b2b4a2af1ac03cc52b5f3f88efedaf3a"
IMG_B[python]="docker.io/library/python@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a"
IMG_A[maven]="docker.io/library/maven@sha256:91f028e13c429b20491181157918b90c926116723e452fb41a9c29887042f188"
IMG_B[maven]="docker.io/library/maven@sha256:529278c758cac25258da21a71de9eecc553e2fc66304676bc8004260e8fc15bf"
IMG_A[gradle]="docker.io/library/gradle@sha256:9c694fc78bbf3a63ca678e2c5794258447d19f26a802185ebd17227906a8d3c9"
IMG_B[gradle]="docker.io/library/gradle@sha256:eb2209db6d5a025a0a8711a6f1a5556b654ecc07f05dc8703d2317eab410aa8e"

# Bounded-output podman for provisioning. Images like maven/gradle/bun
# carry a tool ENTRYPOINT, so provision commands always run through an
# explicit /bin/sh entrypoint.
pod() {
    echo "\$ podman $*" >> "$LOGS/last-pod.log"
    timeout 900 podman "$@" >> "$LOGS/last-pod.log" 2>&1
}
podsh() { # image, then any podman run flags via $3+, command = $2
    local img="$1" cmd="$2"
    shift 2
    pod run --rm --entrypoint /bin/sh "$@" "$img" -c "$cmd"
}

# ---------------------------------------------------------------------
# Provision: build each recipe's checked-in dependency store once.
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

prov_go() { # $1 = shared dir → goproxy/
    python3 - "$1/goproxy" <<'PY'
import json, pathlib, sys, zipfile
out = pathlib.Path(sys.argv[1])
def mod(mod, ver, body):
    d = out / mod / "@v"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{ver}.info").write_text(
        json.dumps({"Version": ver, "Time": "2025-01-01T00:00:00Z"}))
    gomod = f"module {mod}\n\ngo 1.24\n"
    (d / f"{ver}.mod").write_text(gomod)
    pkg = mod.rsplit("/", 1)[1]
    with zipfile.ZipFile(d / f"{ver}.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{mod}@{ver}/go.mod", gomod)
        z.writestr(f"{mod}@{ver}/{pkg}.go", body)
    lst = d / "list"
    have = lst.read_text() if lst.exists() else ""
    if ver not in have.split():
        lst.write_text(have + ver + "\n")
def lib(pkg, ver):
    return (f'package {pkg}\n\n// V returns the library version.\n'
            f'func V() string {{ return "{ver}" }}\n')
mod("example.com/k07a", "v0.1.0", lib("k07a", "0.1.0"))
mod("example.com/k07b", "v0.1.0", lib("k07b", "0.1.0"))
mod("example.com/k07b", "v0.1.1", lib("k07b", "0.1.1"))
PY
}

# Per-variant go.sum through the real tool, offline against the proxy.
lock_go() { # $1 = variant dir
    podsh "${IMG_A[go]}" 'GOPROXY=file:///app/goproxy GOSUMDB=off GOFLAGS=-mod=mod GOTOOLCHAIN=local GOMODCACHE=/gomod GOCACHE=/gocache go mod tidy' \
        -v "$1:/app" -w /app
}

prov_rust() { # $1 = shared dir → local-registry/
    local lr="$1/local-registry" spec n v d idx ck
    mkdir -p "$lr/index"
    for spec in "k07a 0.1.0" "k07b 0.1.0" "k07b 0.1.1"; do
        n="${spec%% *}"; v="${spec##* }"
        d="$(mktemp -d)/$n-$v"
        mkdir -p "$d/src"
        printf '[package]\nname = "%s"\nversion = "%s"\nedition = "2021"\n' "$n" "$v" > "$d/Cargo.toml"
        printf '/// The library version.\npub fn v() -> &'\''static str { "%s" }\n' "$v" > "$d/src/lib.rs"
        tar -czf "$lr/$n-$v.crate" -C "${d%/*}" "$n-$v" || return 1
        ck="$(sha256sum "$lr/$n-$v.crate" | cut -d' ' -f1)"
        # Registry-index path: 1→1/, 2→2/, 3→3/c/, longer→cc/cc/
        case ${#n} in
            1) idx="1/$n";; 2) idx="2/$n";;
            3) idx="3/${n:0:1}/$n";;
            *) idx="${n:0:2}/${n:2:2}/$n";;
        esac
        mkdir -p "$lr/index/$(dirname "$idx")"
        printf '{"name":"%s","vers":"%s","deps":[],"cksum":"%s","features":{},"yanked":false}\n' \
            "$n" "$v" "$ck" >> "$lr/index/$idx"
        rm -rf "${d%/*}"
    done
}

lock_rust() { # $1 = variant dir (local-registry/ already inside)
    podsh "${IMG_A[rust]}" 'CARGO_HOME=/cargo CARGO_NET_OFFLINE=true cargo generate-lockfile --offline' \
        -v "$1:/workspace" -w /workspace
}

# npm-pack the two tiny libs (all three versions) into pkgs/ — always
# with the node image (the bun image has no npm; the tarballs are
# tool-agnostic).
prov_pkgs() { # $1 = shared dir
    local spec n v d
    mkdir -p "$1/pkgs"
    for spec in "k07a 1.0.0" "k07b 1.0.0" "k07b 1.0.1"; do
        n="${spec%% *}"; v="${spec##* }"
        d="$WORK/prov/.src-$n-$v"
        rm -rf "$d"; mkdir -p "$d"
        printf '{"name":"%s","version":"%s","main":"index.js"}\n' "$n" "$v" > "$d/package.json"
        printf 'module.exports = { v: "%s" };\n' "$v" > "$d/index.js"
        podsh "${IMG_A[npm]}" 'npm pack --pack-destination /out' \
            -v "$d:/src" -v "$1/pkgs:/out" -w /src || return 1
        rm -rf "$d"
    done
}

prov_npm() { prov_pkgs "$1"; }
lock_npm() {
    podsh "${IMG_A[npm]}" 'npm_config_cache=/npmc npm install --no-audit --no-fund' \
        -v "$1:/app" -w /app
}

prov_pnpm() {
    prov_pkgs "$1" || return 1
    # Vendor the pnpm dist bundle so the toolchain itself is checked in.
    local d="$WORK/prov/.pnpm-dist"
    rm -rf "$d"; mkdir -p "$d"
    podsh "${IMG_A[npm]}" 'npm pack pnpm@10.34.5 --pack-destination /out' \
        -v "$d:/out" -w /out || return 1
    tar -xzf "$d"/pnpm-*.tgz -C "$d" || return 1
    mkdir -p "$1/tool/pnpm/bin"
    cp -r "$d/package/dist" "$1/tool/pnpm/dist" || return 1
    cat > "$1/tool/pnpm/bin/pnpm" <<'EOF'
#!/bin/sh
exec node /workspace/tool/pnpm/dist/pnpm.cjs "$@"
EOF
    chmod +x "$1/tool/pnpm/bin/pnpm"
}
lock_pnpm() {
    podsh "${IMG_A[npm]}" 'PATH=/workspace/tool/pnpm/bin:$PATH npm_config_store_dir=/pstore pnpm install --lockfile-only' \
        -v "$1:/workspace" -w /workspace
}

prov_bun() { prov_pkgs "$1"; }
lock_bun() {
    podsh "${IMG_A[bun]}" 'BUN_INSTALL_CACHE_DIR=/bunc bun install' \
        -v "$1:/app" -w /app
}

prov_python() { # $1 → pkgs/sdist + pkgs/wheels
    local sd="$1/pkgs/sdist" wh="$1/pkgs/wheels" spec n v d
    mkdir -p "$sd" "$wh"
    for spec in "k07a 1.0.0" "k07b 1.0.0" "k07b 1.0.1"; do
        n="${spec%% *}"; v="${spec##* }"
        d="$(mktemp -d)/$n-$v"
        mkdir -p "$d/$n"
        printf 'VALUE = "%s"\n' "$v" > "$d/$n/__init__.py"
        cat > "$d/pyproject.toml" <<EOF
[build-system]
requires = ["setuptools>=61", "wheel"]
build-backend = "setuptools.build_meta"
[project]
name = "$n"
version = "$v"
[tool.setuptools]
packages = ["$n"]
EOF
        printf 'Metadata-Version: 2.1\nName: %s\nVersion: %s\n' "$n" "$v" > "$d/PKG-INFO"
        tar -czf "$sd/$n-$v.tar.gz" -C "${d%/*}" "$n-$v" || return 1
        rm -rf "${d%/*}"
    done
    # Build backends — the only part that needs the network, once.
    podsh "${IMG_A[python]}" 'pip download --no-deps -d /w setuptools wheel packaging' \
        -v "$wh:/w" -w /w
}
# requirements.txt is the lockfile; nothing else to generate.
lock_python() { :; }

# com.acme:k07a/k07b via the real installer into a maven-layout dir, then
# one online build seeds the plugin tree the recipe needs; the merged dir
# is a genuine mirror the file:// URL serves offline.
prov_maven() { # $1 → m2-mirror/
    local m2="$1/m2-mirror" spec n v d cls
    mkdir -p "$m2"
    for spec in "k07a 1.0.0" "k07b 1.0.0" "k07b 1.0.1"; do
        n="${spec%% *}"; v="${spec##* }"
        cls="Lib$(printf %s "${n#k07}" | tr a-z A-Z)"
        d="$WORK/prov/.mvn-$n-$v"
        rm -rf "$d"; mkdir -p "$d/com/acme"
        printf 'package com.acme;\n\n/** k07 fixture library. */\npublic final class %s {\n    private %s() {}\n    /** Version. */\n    public static String v() { return "%s"; }\n}\n' \
            "$cls" "$cls" "$v" > "$d/com/acme/$cls.java"
        cat > "$d/$n-$v.pom" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>com.acme</groupId><artifactId>$n</artifactId><version>$v</version><packaging>jar</packaging></project>
EOF
        podsh "${IMG_A[maven]}" "javac com/acme/$cls.java && jar cf $n-$v.jar com/acme/$cls.class && mvn -B -q org.apache.maven.plugins:maven-install-plugin:3.1.2:install-file -Dfile=$n-$v.jar -DpomFile=$n-$v.pom -DlocalRepositoryPath=/m2" \
            -v "$d:/src" -v "$m2:/m2" -w /src || return 1
    done
    # Stage a local repo: seed it with the k07 artifacts, then resolve
    # everything the measured build needs from Central, once, online.
    local stage="$WORK/prov/.m2-stage" app="$WORK/prov/.mvn-app"
    rm -rf "$stage" "$app"; mkdir -p "$stage" "$app"
    cp -a "$FIX/maven/tree/." "$app/"
    cp -rn "$m2"/* "$stage"/ 2>/dev/null || cp -r "$m2"/* "$stage"/
    podsh "${IMG_A[maven]}" 'MAVEN_OPTS=-Dmaven.repo.local=/stage mvn -B package org.apache.maven.plugins:maven-dependency-plugin:3.6.1:copy-dependencies -DoutputDirectory=target/deps' \
        -v "$app:/app" -v "$stage:/stage" -w /app || return 1
    cp -rn "$stage"/* "$m2"/ 2>/dev/null || cp -r "$stage"/* "$m2"/
}
lock_maven() { :; } # pom.xml is the dependency manifest

prov_gradle() { # $1 → m2-mirror/ (hand-laid jars+poms+checksums; offline)
    local m2="$1/m2-mirror" spec n v d r cls
    mkdir -p "$m2"
    for spec in "k07a 1.0.0" "k07b 1.0.0" "k07b 1.0.1"; do
        n="${spec%% *}"; v="${spec##* }"
        cls="Lib$(printf %s "${n#k07}" | tr a-z A-Z)"
        d="$WORK/prov/.gr-$n-$v"
        rm -rf "$d"; mkdir -p "$d/com/acme"
        printf 'package com.acme;\n\n/** k07 fixture library. */\npublic final class %s {\n    private %s() {}\n    /** Version. */\n    public static String v() { return "%s"; }\n}\n' \
            "$cls" "$cls" "$v" > "$d/com/acme/$cls.java"
        r="$m2/com/acme/$n/$v"
        mkdir -p "$r"
        podsh "${IMG_A[gradle]}" "javac com/acme/$cls.java && jar cf /src/$n-$v.jar com/acme/$cls.class" \
            -v "$d:/src" -w /src || return 1
        cat > "$r/$n-$v.pom" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
<groupId>com.acme</groupId><artifactId>$n</artifactId><version>$v</version><packaging>jar</packaging></project>
EOF
        cp "$d/$n-$v.jar" "$r/$n-$v.jar"
        for f in "$r/$n-$v.pom" "$r/$n-$v.jar"; do
            sha1sum "$f" | cut -d' ' -f1 > "$f.sha1"
            md5sum  "$f" | cut -d' ' -f1 > "$f.md5"
        done
        rm -rf "$d"
    done
}
lock_gradle() { # $1 = variant dir
    podsh "${IMG_A[gradle]}" 'GRADLE_USER_HOME=/guh GRADLE_OPTS=-Dorg.gradle.daemon=false gradle --no-daemon build --write-locks' \
        -v "$1:/workspace" -w /workspace
}

lock_none() { :; }

# ---------------------------------------------------------------------
# Materialize: copy tree + shared store + overlay into a variant dir.
# ---------------------------------------------------------------------

SHARED_PROV_custom_tool=prov_custom_tool
SHARED_PROV_go=prov_go
SHARED_PROV_rust=prov_rust
SHARED_PROV_npm=prov_npm
SHARED_PROV_pnpm=prov_pnpm
SHARED_PROV_bun=prov_bun
SHARED_PROV_python=prov_python
SHARED_PROV_maven=prov_maven
SHARED_PROV_gradle=prov_gradle

LOCK_custom_tool=lock_none
LOCK_go=lock_go
LOCK_rust=lock_rust
LOCK_npm=lock_npm
LOCK_pnpm=lock_pnpm
LOCK_bun=lock_bun
LOCK_python=lock_python
LOCK_maven=lock_maven
LOCK_gradle=lock_gradle

materialize() { # recipe variant dest
    local r="$1" v="$2" dest="$3" fn
    rm -rf "$dest"; mkdir -p "$dest"
    cp -a "$FIX/$r/tree/." "$dest/"
    # Shared store minus the .done marker, which is script bookkeeping.
    if [ -d "$WORK/prov/$r" ]; then
        (cd "$WORK/prov/$r" && find . -mindepth 1 -maxdepth 1 ! -name .done -exec cp -a {} "$dest/" \;)
    fi
    if [ "$v" != base ] && [ -d "$FIX/$r/$v" ]; then
        cp -a "$FIX/$r/$v/." "$dest/"
    fi
    fn="LOCK_${r//-/_}"
    if ! ${!fn} "$dest"; then
        tail -5 "$LOGS/last-pod.log" >&2
        return 1
    fi
    # Lockfile tools leave root-owned files on some engines; normalize so
    # git and later runs can read them.
    chmod -R u+rw "$dest" 2>/dev/null || true
}

# Build the three-commit repo: main = base, k07-source = edit-source,
# k07-dep = edit-dep. Echoes "<base> <source> <dep>" on success.
build_repo() { # recipe
    local r="$1" repo="$WORK/repos/$1" s
    rm -rf "$repo"; mkdir -p "$repo"
    git -C "$repo" init -q -b main
    git -C "$repo" config user.email k07@example.com
    git -C "$repo" config user.name k07
    for v in base edit-source edit-dep; do
        materialize "$r" "$v" "$WORK/src/$r/$v" || return 1
        case "$v" in
            base) ;;
            edit-source) git -C "$repo" checkout -qb k07-source;;
            edit-dep) git -C "$repo" checkout -qb k07-dep main;;
        esac
        # Fresh mtimes, not cp -a: the variants' equal-size edits can land
        # on recycled inodes with identical mtimes, which is exactly the
        # stat tuple git's index trusts — a racily-clean false match.
        find "$repo" -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +
        cp -r "$WORK/src/$r/$v/." "$repo/"
        git -C "$repo" add -A
        git -C "$repo" commit -qm "k07 $r $v"
    done
    git -C "$repo" checkout -q main
    for s in main k07-source k07-dep; do
        git -C "$repo" rev-parse "$s"
    done | tr '\n' ' '
}

run_case() { # recipe case sha image
    local r="$1" c="$2" sha="$3" img="$4" rec
    rec="$("$DRIVER" \
        --pipeline "$FIX/$r.yml" --job build \
        --repo "$WORK/repos/$r" --sha "$sha" \
        --worker-dir "$WORK/worker/$r" \
        --image "$img" --repo-id "$(repo_id "$r")" \
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
command -v python3 >/dev/null || { log "python3 required for provisioning"; exit 1; }
command -v podman  >/dev/null || { log "podman required"; exit 1; }
log "provisioning into $WORK"
for r in $RECIPES; do
    fn="SHARED_PROV_${r//-/_}"
    if [ ! -f "$WORK/prov/$r/.done" ]; then
        rm -rf "$WORK/prov/$r"; mkdir -p "$WORK/prov/$r"
        if ${!fn} "$WORK/prov/$r" >> "$LOGS/prov-$r.log" 2>&1; then
            touch "$WORK/prov/$r/.done"
            log "provisioned $r"
        else
            log "provision FAILED for $r (see $LOGS/prov-$r.log)"
            rm -rf "$WORK/prov/$r"
        fi
    else
        log "$r already provisioned"
    fi
done

for r in $RECIPES; do
    if [ ! -f "$WORK/prov/$r/.done" ]; then
        for c in cold warm small-edit changed-dependency changed-toolchain; do
            blocked "$r" "$c" "provisioning failed (see prov-$r.log)"
        done
        continue
    fi
    SHAS="$(build_repo "$r")"
    read -r SHA_BASE SHA_SRC SHA_DEP <<< "$SHAS"
    if [ -z "${SHA_BASE:-}" ] || [ -z "${SHA_SRC:-}" ] || [ -z "${SHA_DEP:-}" ]; then
        for c in cold warm small-edit changed-dependency changed-toolchain; do
            blocked "$r" "$c" "repo materialization failed"
        done
        continue
    fi
    log "$r shas: base=${SHA_BASE:0:8} src=${SHA_SRC:0:8} dep=${SHA_DEP:0:8}"
    rm -rf "$WORK/worker/$r"; mkdir -p "$WORK/worker/$r"
    run_case "$r" cold               "$SHA_BASE" "${IMG_A[$r]}"
    run_case "$r" warm               "$SHA_BASE" "${IMG_A[$r]}"
    run_case "$r" small-edit         "$SHA_SRC"  "${IMG_A[$r]}"
    run_case "$r" changed-dependency "$SHA_DEP"  "${IMG_A[$r]}"
    run_case "$r" changed-toolchain  "$SHA_BASE" "${IMG_B[$r]}"
done
log "records: $(wc -l < "$OUT") -> $OUT"
