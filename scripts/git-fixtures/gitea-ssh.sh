#!/usr/bin/env bash
# G08 fixture: Gitea served over its own built-in SSH server, with a deploy key and a pinned
# known_hosts line.
#
# The admin API stays on plain HTTP on loopback (the binding never uses it); the remote the
# binding is given is ssh://git@127.0.0.1:3022/ci/app.git. Creates the user `ci`, the private
# repository `ci/app`, a write deploy key for the fixture's own pushes, and
# `hooks/post-receive.d/sentinel` carrying the shipped post-receive hook.
#
#   scripts/git-fixtures/gitea-ssh.sh up|down|status
set -euo pipefail
. "$(dirname -- "$0")/lib.sh"
fx_shipped_hook

NAME=gitea-ssh
SSH_PORT=${SENTINEL_FIXTURE_GITEA_SSH_PORT:-3022}
HTTP_PORT=${SENTINEL_FIXTURE_GITEA_SSH_HTTP_PORT:-3445}

up() {
    local state
    fx_preflight "$NAME"
    fx_add_host
    fx_image "$GITEA_IMAGE"
    fx_down "$NAME"
    fx_need_ports "$NAME" "$SSH_PORT" "$HTTP_PORT"
    state=$(fx_state "$NAME")
    mkdir -p "$state"
    chmod 700 "$state"
    FX_REMOTE="ssh://git@127.0.0.1:$SSH_PORT/ci/app.git"
    FX_RUN_ARGS=(
        -p "127.0.0.1:$HTTP_PORT:3000"
        -p "127.0.0.1:$SSH_PORT:2222"
        -e GITEA__database__DB_TYPE=sqlite3
        -e GITEA__server__PROTOCOL=http
        -e "GITEA__server__ROOT_URL=http://127.0.0.1:$HTTP_PORT/"
        -e GITEA__server__START_SSH_SERVER=true
        -e GITEA__server__SSH_DOMAIN=127.0.0.1
        -e "GITEA__server__SSH_PORT=$SSH_PORT"
        -e GITEA__server__SSH_LISTEN_PORT=2222
        -e GITEA__security__INSTALL_LOCK=true
        -e GITEA__service__DISABLE_REGISTRATION=true
        -e GITEA__log__LEVEL=Warn
    )
    fx_forge_up "$NAME" "$GITEA_IMAGE" gitea "http://127.0.0.1:$HTTP_PORT" http ssh "$SSH_PORT"
}

case "${1:-up}" in
    up) up ;;
    down) fx_down "$NAME"; echo "$NAME down" ;;
    status) fx_status "$NAME" ;;
    *) fx_usage ;;
esac
