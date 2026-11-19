#!/usr/bin/env bash
# G08 fixture: a bare repository served by a bare sshd container, no forge in the way.
#
# Creates `git@127.0.0.1:2222:/srv/git/app.git` with a first pipeline commit, an authorized key
# for the fixture's own pushes, and a plain `hooks/post-receive` carrying the shipped hook. The
# binding lands at $SENTINEL_FIXTURE_ROOT/bare-sshd/binding.json (0600).
#
#   scripts/git-fixtures/bare-sshd.sh up|down|status
set -euo pipefail
. "$(dirname -- "$0")/lib.sh"
fx_shipped_hook

NAME=bare-sshd
SSH_PORT=${SENTINEL_FIXTURE_BARE_SSH_PORT:-2222}
REPO=/srv/git/app.git

up() {
    local state container
    fx_preflight "$NAME"
    fx_add_host
    fx_down "$NAME"
    fx_need_ports "$NAME" "$SSH_PORT"
    state=$(fx_state "$NAME")
    mkdir -p "$state"
    chmod 700 "$state"
    if ! fx_rt image inspect "$SSHD_IMAGE" >/dev/null 2>&1; then
        fx_err "building $SSHD_IMAGE"
        fx_rt build -q -t "$SSHD_IMAGE" -f "$(dirname -- "$0")/sshd.Containerfile" \
            "$(dirname -- "$0")" >&2 || fx_die "$name: cannot build the sshd image"
    fi
    container=$(fx_container "$NAME")
    fx_rt create --name "$container" "${FX_ADD_HOST[@]}" \
        -p "127.0.0.1:$SSH_PORT:22" -v "$(fx_volume "$NAME"):/srv/git" "$SSHD_IMAGE" >/dev/null
    fx_rt start "$container" >/dev/null
    fx_wait_tcp "$SSH_PORT" 60 || fx_die "$NAME: sshd never listened on $SSH_PORT"

    fx_gen_key "$state/client-key"
    fx_rt exec -i -u git "$container" sh -c '
        git init --bare -q /srv/git/app.git
        install -d -m 700 -o git -g git /home/git/.ssh
        cat > /home/git/.ssh/authorized_keys
        chown git:git /home/git/.ssh/authorized_keys
        chmod 600 /home/git/.ssh/authorized_keys' <"$state/client-key.pub"

    ssh-keyscan -t ed25519 -p "$SSH_PORT" 127.0.0.1 >"$state/known_hosts" 2>/dev/null
    [ -s "$state/known_hosts" ] || fx_die "$NAME: no SSH host key to pin"
    FX_REMOTE="ssh://git@127.0.0.1:$SSH_PORT/srv/git/app.git"
    FX_SSH_KEY=$state/client-key
    FX_KNOWN_HOSTS=$state/known_hosts

    fx_seed_repo "$state/seed"
    fx_git_push "$FX_REMOTE" "$state/seed" ||
        fx_die "$NAME: the fixture's own push over SSH failed"

    fx_hook_env "$state/hook.env" "sentinel_hook_fixture_${NAME//-/_}" "$(fx_intake "$NAME")"
    fx_rt exec -i -u git "$container" sh -c \
        "cat > '$REPO/hooks/post-receive' && chmod 755 '$REPO/hooks/post-receive'" <"$FX_SHIPPED_HOOK"
    fx_rt exec -i -u git "$container" sh -c \
        "cat > '$REPO/hooks/sentinel-hook.env' && chmod 600 '$REPO/hooks/sentinel-hook.env'" \
        <"$state/hook.env"

    fx_bind "$NAME" "$FX_REMOTE" ssh "ssh:$state/client-key"
    fx_print "$NAME"
}

case "${1:-up}" in
    up) up ;;
    down) fx_down "$NAME"; echo "$NAME down" ;;
    status) fx_status "$NAME" ;;
    *) fx_usage ;;
esac
