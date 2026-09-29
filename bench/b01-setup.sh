#!/usr/bin/env bash
# B01: prepare a bench root for the lockwell-ci contract, as the bench user.
#   bench/b01-setup.sh ROOT BUNDLES_DIR
# ROOT gets src/<source> clones at the contract's commits (from git bundles
# in BUNDLES_DIR: the repositories are private and the host holds no
# credential for them), empty cache directories, and toolchain/go: the Go
# toolchain copied out of the contract's pinned image, so a scoped (direct)
# run uses the very binaries the container does. One root per runtime keeps
# their caches apart.
set -euo pipefail
ROOT=$1
BUNDLES=$2
CONTRACT=${CONTRACT:-$(dirname "$0")/contracts/lockwell-ci.json}
mkdir -p "$ROOT"/{src,cache,tmp,home}
ROOT=$(cd "$ROOT" && pwd)

read_contract() { python3 -c "import json,sys; c=json.load(open(sys.argv[1])); $1" "$CONTRACT"; }
read_contract 'print("\n".join(s["name"]+" "+s["commit"]+" "+s["path"] for s in c["sources"]))' |
  while read -r name commit path; do
    dir="$ROOT/$path"
    if [ ! -d "$dir/.git" ]; then
      git clone -q "$BUNDLES/$name.bundle" "$dir"
    fi
    git -C "$dir" fetch -q "$BUNDLES/$name.bundle" '+refs/*:refs/remotes/bundle/*' 2>/dev/null || true
    git -C "$dir" checkout -q -f "$commit"
    echo "$name at $(git -C "$dir" rev-parse HEAD)"
  done

IMAGE=$(read_contract 'print(c["images"]["go"])')
podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null
if [ ! -x "$ROOT/toolchain/go/bin/go" ]; then
  mkdir -p "$ROOT/toolchain"
  id=$(podman create "$IMAGE" true)
  podman cp "$id:/usr/local/go" "$ROOT/toolchain/go"
  podman rm -f "$id" >/dev/null
fi
echo "toolchain: $("$ROOT/toolchain/go/bin/go" version)"
echo "image: $IMAGE"
