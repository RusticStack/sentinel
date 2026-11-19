#!/usr/bin/env bash
# G08 fixture: GitLab CE over SSH, with a per-repository `custom_hooks/post-receive` under
# Gitaly's hashed storage.
#
# Creates the user `root`'s project `gitlab-app` with a first pipeline commit, an SSH key for the
# fixture's own pushes and for the binding, and the shipped hook as the project's custom hook.
# The admin API stays on plain HTTP on loopback; the remote the binding is given is
# ssh://git@127.0.0.1:3023/root/gitlab-app.git. The binding lands at
# $SENTINEL_FIXTURE_ROOT/gitlab-ssh/binding.json (0600).
#
# GitLab is the one fixture that is slow to boot (a full Omnibus reconfigure, minutes not
# seconds); it is pinned by digest like the rest and pulls nothing once present.
#
#   scripts/git-fixtures/gitlab-ssh.sh up|down|status
set -euo pipefail
. "$(dirname -- "$0")/lib.sh"
fx_shipped_hook

NAME=gitlab-ssh
SSH_PORT=${SENTINEL_FIXTURE_GITLAB_SSH_PORT:-3023}
HTTP_PORT=${SENTINEL_FIXTURE_GITLAB_HTTP_PORT:-8080}
PROJECT=gitlab-app

runner() { # RUBY on stdout, with GitLab's own chatter dropped
    fx_rt exec "$(fx_container "$NAME")" gitlab-rails runner "$1" 2>/dev/null
}

up() {
    local state container token disk_path url
    fx_preflight "$NAME"
    fx_add_host
    fx_image "$GITLAB_IMAGE"
    fx_down "$NAME"
    fx_need_ports "$NAME" "$HTTP_PORT" "$SSH_PORT"
    state=$(fx_state "$NAME")
    mkdir -p "$state"
    chmod 700 "$state"
    container=$(fx_container "$NAME")
    fx_rt create --name "$container" "${FX_ADD_HOST[@]}" --shm-size 256m \
        -p "127.0.0.1:$HTTP_PORT:80" -p "127.0.0.1:$SSH_PORT:22" \
        -e "GITLAB_OMNIBUS_CONFIG=external_url 'http://127.0.0.1'
puma['worker_processes'] = 0
sidekiq['max_concurrency'] = 4
prometheus_monitoring['enable'] = false
gitlab_kas['enable'] = false
gitlab_rails['lfs_enabled'] = false
gitlab_rails['gitlab_shell_ssh_port'] = $SSH_PORT" \
        "$GITLAB_IMAGE" >/dev/null
    fx_rt start "$container" >/dev/null
    # A first boot reconfigure is minutes; the API answering /users/sign_in is the readiness gate.
    fx_wait_http "http://127.0.0.1:$HTTP_PORT/users/sign_in" "" 1800 ||
        fx_die "$NAME: GitLab never answered on $HTTP_PORT; see '$FX_RUNTIME logs $container'"

    fx_gen_key "$state/client-key"
    token=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
    # One runner call: a root personal access token for the admin API, shown to this script only.
    runner "
user = User.find_by_username('root')
token = user.personal_access_tokens.create!(scopes: ['api'], name: 'sentinel-fixture',
                                            expires_at: Date.today + 30)
token.set_token('$token')
token.save!
puts 'PAT=' + token.token
" >/dev/null || fx_die "$NAME: could not mint a root token"
    (umask 077 && printf '%s\n' "$token" >"$state/pat")

    url="http://127.0.0.1:$HTTP_PORT/api/v4"
    curl -fsS --max-time 60 -H "PRIVATE-TOKEN: $token" -H 'content-type: application/json' \
        --data '{"name":"gitlab-app","path":"gitlab-app","visibility":"private","initialize_with_readme":false}' \
        "$url/projects" >/dev/null || fx_die "$NAME: could not create $PROJECT"
    curl -fsS --max-time 60 -H "PRIVATE-TOKEN: $token" -H 'content-type: application/json' \
        --data "$(python3 -c 'import json,sys; print(json.dumps({"title":"sentinel","key":open(sys.argv[1]).read().strip()}))' \
            "$state/client-key.pub")" \
        "$url/user/keys" >/dev/null || fx_die "$NAME: could not add the SSH key"

    ssh-keyscan -t ed25519 -p "$SSH_PORT" 127.0.0.1 >"$state/known_hosts" 2>/dev/null
    [ -s "$state/known_hosts" ] || fx_die "$NAME: no SSH host key to pin"
    FX_REMOTE="ssh://git@127.0.0.1:$SSH_PORT/root/$PROJECT.git"
    FX_SSH_KEY=$state/client-key
    FX_KNOWN_HOSTS=$state/known_hosts
    fx_seed_repo "$state/seed"
    fx_git_push "$FX_REMOTE" "$state/seed" || fx_die "$NAME: the fixture's own push over SSH failed"

    # Gitaly stores repositories at a hashed path; the custom hooks directory sits beside it.
    disk_path=$(runner "puts Project.find_by_full_path('root/$PROJECT').repository.disk_path")
    [ -n "$disk_path" ] || fx_die "$NAME: no disk path for root/$PROJECT"
    # Gitaly's repository directory, which is where it looks for custom hooks: the API's disk
    # path may name it without the `.git` suffix.
    case "$disk_path" in *.git) ;; *) disk_path=$disk_path.git ;; esac
    fx_hook_env "$state/hook.env" "sentinel_hook_fixture_${NAME//-/_}" "$(fx_intake "$NAME")"
    hooks=/var/opt/gitlab/git-data/repositories/$disk_path/custom_hooks
    fx_rt exec -i "$container" sh -c \
        "mkdir -p '$hooks' && cat > '$hooks/post-receive' && chmod 755 '$hooks/post-receive'" \
        <"$FX_SHIPPED_HOOK"
    fx_rt exec -i "$container" sh -c \
        "cat > '$hooks/sentinel-hook.env' && chmod 600 '$hooks/sentinel-hook.env'" \
        <"$state/hook.env"
    # Gitaly refuses a custom hooks directory that git does not own.
    fx_rt exec "$container" sh -c "chown -R git:git '$hooks' && chmod 755 '$hooks'"

    fx_bind "$NAME" "$FX_REMOTE" ssh "ssh:$state/client-key"
    fx_print "$NAME"
    printf 'admin      http://127.0.0.1:%s (root token in %s/pat, not printed)\n' "$HTTP_PORT" "$state"
}

case "${1:-up}" in
    up) up ;;
    down) fx_down "$NAME"; echo "$NAME down" ;;
    status) fx_status "$NAME" ;;
    *) fx_usage ;;
esac
