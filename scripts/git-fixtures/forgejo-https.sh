#!/usr/bin/env bash
# G08 fixture: Forgejo over HTTPS, a local CA the binding pins, and a read:repository token.
#
# Same shape as the Gitea HTTPS fixture on its own port: the user `ci`, the private repository
# `ci/app` with a first pipeline commit, and `hooks/post-receive.d/sentinel` carrying the shipped
# hook. The binding lands at $SENTINEL_FIXTURE_ROOT/forgejo-https/binding.json (0600).
#
#   scripts/git-fixtures/forgejo-https.sh up|down|status
set -euo pipefail
. "$(dirname -- "$0")/lib.sh"
fx_shipped_hook

NAME=forgejo-https
PORT=${SENTINEL_FIXTURE_FORGEJO_HTTPS_PORT:-3444}

up() {
    local state
    fx_preflight "$NAME"
    fx_add_host
    fx_image "$FORGEJO_IMAGE"
    fx_down "$NAME"
    fx_need_ports "$NAME" "$PORT"
    state=$(fx_state "$NAME")
    mkdir -p "$state"
    chmod 700 "$state"
    fx_gen_ca "$state/tls"
    FX_REMOTE="https://127.0.0.1:$PORT/ci/app.git"
    FX_RUN_ARGS=(
        -p "127.0.0.1:$PORT:3000"
        -e GITEA__database__DB_TYPE=sqlite3
        -e GITEA__server__PROTOCOL=https
        -e GITEA__server__CERT_FILE=/data/tls/server.pem
        -e GITEA__server__KEY_FILE=/data/tls/server-key.pem
        -e "GITEA__server__ROOT_URL=https://127.0.0.1:$PORT/"
        -e GITEA__server__SSH_DISABLED=true
        -e GITEA__security__INSTALL_LOCK=true
        -e GITEA__service__DISABLE_REGISTRATION=true
        -e GITEA__log__LEVEL=Warn
    )
    fx_forge_up "$NAME" "$FORGEJO_IMAGE" forgejo "https://127.0.0.1:$PORT" https https ""
}

case "${1:-up}" in
    up) up ;;
    down) fx_down "$NAME"; echo "$NAME down" ;;
    status) fx_status "$NAME" ;;
    *) fx_usage ;;
esac
