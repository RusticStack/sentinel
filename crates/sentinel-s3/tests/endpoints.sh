#!/bin/sh
# Start the S3-compatible services the compatibility tests (R02/R03) run
# against, each in rootful Podman on loopback, and write their endpoints to
# $ROOT/endpoints: one line per service,
#   name endpoint region bucket path_style credentials_file
# `sh endpoints.sh up` (re)starts them; `sh endpoints.sh down` removes them.
# Test infrastructure only: Sentinel itself depends on none of these. Images
# are pinned by digest (MinIO withdrew its public images and downloads in
# 2025, so it is not among them).
set -eu
ROOT=${SENTINEL_S3_ROOT:-/srv/sentinel-s3}
GARAGE=docker.io/dxflrs/garage@sha256:0d7c74fc8ca6fef68a5a941c0e7558c8b1e92ba3588fa7505400e1350456c796        # v2.4.1
SEAWEED=docker.io/chrislusf/seaweedfs@sha256:f83509b0721dfd8e2e07faf76c0a899f67a8a889c89abe2fa0a5227ba1320362 # 4.47
VERSITY=docker.io/versity/versitygw@sha256:97e7d5a35ab758eb1761a9e717644fafc614c5f6026c05482bd1fb77205193a1
ZENKO=docker.io/zenko/cloudserver@sha256:b53e57829cf7df357323e60a19c9f98d2218f1b7ccb1d7cea5761a5a227a9ee3
RUSTFS=docker.io/rustfs/rustfs@sha256:ba0a1b53e36f321c0d46f3867104abef169f7bc59c467c664ddac87e7ddc9a8b
NAMES="s3-garage s3-seaweed s3-versity s3-zenko s3-rustfs"

secret() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

creds() { # name key secret
    (umask 077; printf 'access_key_id = %s\nsecret_access_key = %s\n' "$2" "$3" > "$ROOT/$1/credentials")
}

wait_port() { # any HTTP answer will do
    i=0
    until curl -s -o /dev/null --max-time 1 "http://127.0.0.1:$1/"; do
        i=$((i + 1)); [ $i -gt 240 ] && { echo "port $1 never answered" >&2; return 1; }
        sleep 0.5
    done
}

down() {
    for c in $NAMES; do podman rm -f "$c" >/dev/null 2>&1 || true; done
    rm -rf "$ROOT"
}

garage() {
    mkdir -p "$ROOT/garage/meta" "$ROOT/garage/data"
    cat > "$ROOT/garage/garage.toml" <<EOF
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "[::]:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret = "$(secret)$(secret | head -c 16)"
[s3_api]
s3_region = "garage"
api_bind_addr = "[::]:3900"
root_domain = ".s3.garage.localhost"
EOF
    podman run -d --name s3-garage -p 127.0.0.1:19020:3900 \
        -v "$ROOT/garage/garage.toml:/etc/garage.toml:ro" \
        -v "$ROOT/garage/meta:/var/lib/garage/meta" -v "$ROOT/garage/data:/var/lib/garage/data" \
        "$GARAGE" >/dev/null
    wait_port 19020 || return 1
    i=0
    until node=$(podman exec s3-garage /garage status 2>/dev/null | awk '/^[0-9a-f]{16}/ {print $1; exit}') && [ -n "$node" ]; do
        i=$((i + 1)); [ $i -gt 60 ] && { echo "garage never reported its node" >&2; return 1; }
        sleep 0.5
    done
    podman exec s3-garage /garage layout assign -z dc1 -c 1G "$node" >/dev/null
    podman exec s3-garage /garage layout apply --version 1 >/dev/null
    podman exec s3-garage /garage bucket create sentinel-test >/dev/null
    out=$(podman exec s3-garage /garage key create sentinel)
    k=$(echo "$out" | awk '/Key ID/ {print $NF}')
    s=$(echo "$out" | awk '/Secret key/ {print $NF}')
    podman exec s3-garage /garage bucket allow --read --write --owner sentinel-test --key sentinel >/dev/null
    creds garage "$k" "$s"
    echo "garage http://127.0.0.1:19020 garage sentinel-test true $ROOT/garage/credentials" >> "$ROOT/endpoints"
}

seaweed() {
    mkdir -p "$ROOT/seaweed/data"
    chmod 777 "$ROOT/seaweed/data" # the image runs as an unprivileged user
    k=seaweed$(secret | head -c 8); s=$(secret)
    cat > "$ROOT/seaweed/s3.json" <<EOF
{"identities":[{"name":"sentinel","credentials":[{"accessKey":"$k","secretKey":"$s"}],"actions":["Admin","Read","Write","List","Tagging"]}]}
EOF
    podman run -d --name s3-seaweed -p 127.0.0.1:19010:8333 -v "$ROOT/seaweed:/cfg" \
        "$SEAWEED" server -dir=/cfg/data -s3 -s3.config=/cfg/s3.json -volume.max=8 -master.telemetry=false >/dev/null
    creds seaweed "$k" "$s"
    wait_port 19010 || return 1
    echo "seaweedfs http://127.0.0.1:19010 us-east-1 sentinel-test true $ROOT/seaweed/credentials" >> "$ROOT/endpoints"
}

versity() {
    mkdir -p "$ROOT/versity/data"
    k=versity$(secret | head -c 8); s=$(secret)
    podman run -d --name s3-versity -p 127.0.0.1:19030:7070 -v "$ROOT/versity/data:/data" \
        -e ROOT_ACCESS_KEY="$k" -e ROOT_SECRET_KEY="$s" \
        "$VERSITY" --port :7070 posix /data >/dev/null
    creds versity "$k" "$s"
    wait_port 19030 || return 1
    echo "versitygw http://127.0.0.1:19030 us-east-1 sentinel-test true $ROOT/versity/credentials" >> "$ROOT/endpoints"
}

zenko() {
    mkdir -p "$ROOT/zenko"
    k=zenko$(secret | head -c 8); s=$(secret)
    podman run -d --name s3-zenko -p 127.0.0.1:19040:8000 \
        -e REMOTE_MANAGEMENT_DISABLE=1 -e S3BACKEND=mem -e S3DATA=mem -e S3METADATA=mem \
        -e SCALITY_ACCESS_KEY_ID="$k" -e SCALITY_SECRET_ACCESS_KEY="$s" \
        "$ZENKO" >/dev/null
    creds zenko "$k" "$s"
    wait_port 19040 || return 1
    echo "cloudserver http://127.0.0.1:19040 us-east-1 sentinel-test true $ROOT/zenko/credentials" >> "$ROOT/endpoints"
}

rustfs() {
    mkdir -p "$ROOT/rustfs/data"
    chmod 777 "$ROOT/rustfs/data"
    k=rustfs$(secret | head -c 8); s=$(secret)
    podman run -d --name s3-rustfs -p 127.0.0.1:19050:9000 -v "$ROOT/rustfs/data:/data" \
        -e RUSTFS_ACCESS_KEY="$k" -e RUSTFS_SECRET_KEY="$s" \
        "$RUSTFS" /data >/dev/null
    creds rustfs "$k" "$s"
    wait_port 19050 || return 1
    echo "rustfs http://127.0.0.1:19050 us-east-1 sentinel-test true $ROOT/rustfs/credentials" >> "$ROOT/endpoints"
}

up() {
    down
    mkdir -p "$ROOT"
    : > "$ROOT/endpoints"
    for service in ${SERVICES:-garage seaweed versity zenko rustfs}; do
        "$service" || echo "$service failed to start" >&2
    done
    cat "$ROOT/endpoints"
}

case "${1:-up}" in
    up) up ;;
    down) down ;;
    *) echo "usage: endpoints.sh up|down" >&2; exit 2 ;;
esac
