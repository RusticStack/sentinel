#!/usr/bin/env bash
# Shared by the G08 forge fixtures (docs/generic-git-verification.md). Sourced, never run.
#
# Every fixture script sources this file and implements `up`, `down` and `status`: it stands a
# forge up as a container on loopback, creates a user, a repository and the shipped intake hook,
# and writes the binding a verification run applies with `sentinel admin source bind`. Nothing
# here needs root — the runtime is a rootless Podman (what the bench harnesses use) or a Docker
# the account can drive, and every file it writes lives under $SENTINEL_FIXTURE_ROOT (0700).
#
# Exit codes: 0 ok, 2 usage, 3 the fixture's runtime, tools or account are unusable.

FX_ROOT=${SENTINEL_FIXTURE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-git-fixtures}
FX_RUNTIME=${SENTINEL_FIXTURE_RUNTIME:-}
FX_NAMES="gitea-https gitea-ssh forgejo-https gitlab-ssh bare-sshd"
FX_INTAKE_ORIGIN=${SENTINEL_FIXTURE_INTAKE_ORIGIN:-http://host.containers.internal:7099}
FX_CA_DAYS=825

# Digests, not tags: a second run pulls nothing unless the image is absent.
GITEA_IMAGE=docker.io/gitea/gitea@sha256:87a67ee09d3ae0d1df5fda5dcda3e2a1f9236a45b0a59025d6e00e46adc43bef          # 1.27.3
FORGEJO_IMAGE=codeberg.org/forgejo/forgejo@sha256:879f4f10a98e3e167b32cde5f7ae3af0163d50bfacf567559a27a0e95a95670c # 17.0.2
GITLAB_IMAGE=docker.io/gitlab/gitlab-ce@sha256:180f75ce26ad984f72b556eb7039a970ec2056c2716962affd98cf392b9ed404 # 18.3.2-ce.0
ALPINE_IMAGE=docker.io/library/alpine@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f  # 3.22
SSHD_IMAGE=sentinel-fixture-sshd:1

fx_err() { printf '%s\n' "$*" >&2; }
fx_die() { fx_err "$*"; exit 3; }
fx_usage() { printf 'usage: %s up|down|status\n' "${0##*/}" >&2; exit 2; }

fx_rt() { "$FX_RUNTIME" "$@"; }

# A tag would drift and re-pull; the digest either is in the store or is pulled once, here.
fx_image() { # IMAGE
    if ! fx_rt image inspect "$1" >/dev/null 2>&1; then
        fx_err "pulling $1"
        fx_rt pull "$1" >&2 || fx_die "cannot pull $1"
    fi
}

# Rootless Podman is what the bench harnesses run, Docker is accepted when the account is in
# `docker`; both are driven through the same flags below.
fx_require_runtime() { # NAME: the one check `down` and `status` share with `up`
    local name=$1
    if [ -z "$FX_RUNTIME" ]; then
        if command -v podman >/dev/null 2>&1; then
            FX_RUNTIME=podman
        elif command -v docker >/dev/null 2>&1; then
            FX_RUNTIME=docker
        else
            fx_die "$name: no container runtime: use a rootless podman (or docker), or set SENTINEL_FIXTURE_RUNTIME"
        fi
    fi
    case "$FX_RUNTIME" in
        podman | docker) ;;
        *) fx_die "$name: SENTINEL_FIXTURE_RUNTIME must name podman or docker, not '$FX_RUNTIME'" ;;
    esac
    command -v "$FX_RUNTIME" >/dev/null 2>&1 ||
        fx_die "$name: $FX_RUNTIME is not an executable on PATH"
    fx_rt info >/dev/null 2>&1 ||
        fx_die "$name: $FX_RUNTIME is installed but unusable as uid $EUID"
}

fx_preflight() { # NAME
    local name=$1 tool
    [ "$EUID" -ne 0 ] || fx_die "$name: run this as the unprivileged verification account, not root"
    fx_require_runtime "$name"
    for tool in git curl openssl ssh ssh-keygen ssh-keyscan python3; do
        command -v "$tool" >/dev/null 2>&1 || fx_die "$name: $tool is not on PATH"
    done
    [ -n "${FX_SHIPPED_HOOK:-}" ] && [ -f "$FX_SHIPPED_HOOK" ] ||
        fx_die "$name: examples/hooks/post-receive is missing; run from a repository checkout"
    (umask 077 && mkdir -p "$FX_ROOT") || fx_die "$name: cannot create $FX_ROOT"
}

# The hook the fixture installs is the shipped one, never a copy: a fixture that carried its own
# copy could pass while the shipped hook was broken.
fx_shipped_hook() {
    local here
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    FX_SHIPPED_HOOK=$(cd -- "$here/../.." && pwd)/examples/hooks/post-receive
}

fx_state() { printf '%s/%s' "$FX_ROOT" "$1"; }
fx_container() { printf 'sentinel-fixture-%s' "$1"; }
fx_volume() { printf 'sentinel-fixture-%s-data' "$1"; }

fx_port_free() { # PORT
    python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

fx_need_ports() { # NAME PORT...
    local name=$1 port
    shift
    for port in "$@"; do
        fx_port_free "$port" ||
            fx_die "$name: port $port is already in use; stop what holds it or set the fixture's port variable"
    done
}

fx_down() { # NAME
    local name=$1
    fx_require_runtime "$name"
    fx_rt rm -f "$(fx_container "$name")" >/dev/null 2>&1 || true
    fx_rt volume rm -f "$(fx_volume "$name")" >/dev/null 2>&1 || true
    rm -rf "$(fx_state "$name")"
}

fx_wait_tcp() { # PORT DEADLINE_SECONDS
    local i=0 limit=$(($2 * 4))
    while ! python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(1)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
    do
        i=$((i + 1))
        [ "$i" -gt "$limit" ] && return 1
        sleep 0.25
    done
}

fx_wait_http() { # URL CA-PEM DEADLINE_SECONDS
    local i=0 limit=$(($3 * 2)) cert=()
    [ -n "${2:-}" ] && cert=(--cacert "$2")
    until curl -fs -o /dev/null --max-time 3 "${cert[@]}" "$1" 2>/dev/null; do
        i=$((i + 1))
        [ "$i" -gt "$limit" ] && return 1
        sleep 0.5
    done
}

# A local CA and a leaf for 127.0.0.1, so the fixture's HTTPS is verified, never trusted blindly.
fx_gen_ca() { # DIR
    local dir=$1
    mkdir -p "$dir"
    (umask 077 &&
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$dir/ca-key.pem" -out "$dir/ca.pem" -days "$FX_CA_DAYS" \
            -subj "/CN=sentinel fixture CA" -addext "basicConstraints=critical,CA:true" \
            -addext "keyUsage=critical,keyCertSign" 2>/dev/null &&
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -keyout "$dir/server-key.pem" -out "$dir/server.csr" -subj "/CN=127.0.0.1" 2>/dev/null &&
        printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:false\n' \
            >"$dir/server.ext" &&
        openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.pem" -CAkey "$dir/ca-key.pem" \
            -CAcreateserial -out "$dir/server.pem" -days "$FX_CA_DAYS" -extfile "$dir/server.ext" 2>/dev/null &&
        rm -f "$dir/server.csr" "$dir/server.ext" "$dir/ca.srl")
}

fx_gen_key() { # PATH
    rm -f "$1" "$1.pub"
    ssh-keygen -q -t ed25519 -N '' -C sentinel-fixture -f "$1" >/dev/null
    chmod 600 "$1"
}

# One intake route per fixture, so a listener can tell whose hook delivered what.
fx_intake_path() { printf '/api/v1/intake/rep_fixture_%s' "${1//-/_}"; }
fx_intake() { printf '%s%s' "$FX_INTAKE_ORIGIN" "$(fx_intake_path "$1")"; }

# Podman already publishes host.containers.internal; a Docker bridge needs the alias to reach the
# host from inside a container.
fx_add_host() {
    FX_ADD_HOST=()
    [ "$FX_RUNTIME" = docker ] &&
        FX_ADD_HOST=(--add-host host.containers.internal:host-gateway)
}

fx_askpass() { # PATH: answers git's prompts from the environment, so no credential is an argument
    (umask 077 && printf '%s\n' '#!/bin/sh' \
        'case "$1" in *sername*) printf "%s\n" "$FX_GIT_USER" ;; *) printf "%s\n" "$FX_GIT_SECRET" ;; esac' >"$1")
    chmod 700 "$1"
}

# Pushes $2's HEAD to $1 with the fixture's own credential. The credential reaches git through
# the environment (askpass) or a key file, never the URL, so .git/config and `ps` never hold it.
fx_git_push() { # REMOTE REPO_DIR
    local remote=$1 repo=$2
    case "$remote" in
        https://*)
            GIT_ASKPASS=$FX_ASKPASS FX_GIT_USER=$FX_GIT_USER FX_GIT_SECRET=$FX_GIT_SECRET \
                git -C "$repo" -c http.sslCAInfo="$FX_CA_PEM" -c credential.helper= \
                    push --quiet "$remote" HEAD:refs/heads/main
            ;;
        ssh://*)
            GIT_SSH_COMMAND="ssh -i $FX_SSH_KEY -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile='$FX_KNOWN_HOSTS' -o StrictHostKeyChecking=yes -o LogLevel=ERROR" \
                git -C "$repo" push --quiet "$remote" HEAD:refs/heads/main
            ;;
        *) fx_err "unsupported remote $remote"; return 1 ;;
    esac
}

# Writes $STATE/binding.json (the `admin source bind` input, mode 0600) and $STATE/bindings.sh
# (addresses and paths only — never the credential).
fx_bind() { # NAME REMOTE TRUST_KIND(https|ssh) CREDENTIAL(https:USER:SECRET_FILE|ssh:KEY_FILE)
    local name=$1 remote=$2 trust_kind=$3 cred=$4 state trust on_host
    state=$(fx_state "$name")
    if [ "$trust_kind" = https ]; then trust=$state/tls/ca.pem; else trust=$state/known_hosts; fi
    on_host=${FX_INTAKE_ORIGIN/host.containers.internal/127.0.0.1}
    python3 - "$remote" "$trust" "$cred" "$state/binding.json" <<'PY'
import json, os, sys
remote, trust_file, cred, out = sys.argv[1:5]
kind, _, rest = cred.partition(":")
if kind == "https":
    username, secret_file = rest.split(":", 1)
    credential = {"Https": {"username": username, "secret": open(secret_file, encoding="utf8").read()}}
else:
    credential = {"Ssh": {"private_key": open(rest, encoding="utf8").read()}}
doc = {"binding": {"remote": remote, "allowed_refs": ["refs/heads/main"],
                   "pipeline_path": ".sentinel.yml", "trust": open(trust_file, encoding="utf8").read()},
       "credential": credential, "forge": None}
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
    {
        printf 'FIXTURE_NAME=%s\n' "$name"
        printf 'FIXTURE_REMOTE=%s\n' "$remote"
        printf 'FIXTURE_BINDING=%s/binding.json\n' "$state"
        printf 'FIXTURE_CA_PEM=%s/tls/ca.pem\n' "$state"
        printf 'FIXTURE_KNOWN_HOSTS=%s/known_hosts\n' "$state"
        printf 'FIXTURE_SSH_KEY=%s/client-key\n' "$state"
        printf 'FIXTURE_HOOK_ENV=%s/hook.env\n' "$state"
        printf 'FIXTURE_HOOK_INTAKE=%s\n' "$(fx_intake "$name")"
        printf 'FIXTURE_HOOK_INTAKE_ON_HOST=%s%s\n' "$on_host" "$(fx_intake_path "$name")"
    } >"$state/bindings.sh"
    chmod 600 "$state/bindings.sh"
}

fx_hook_env() { # PATH SECRET URL
    (umask 077 && printf 'SENTINEL_INTAKE_URL=%s\nSENTINEL_HOOK_SECRET=%s\n' "$3" "$2" >"$1")
}

# A first commit with a real pipeline, so a push has a parent and a run has something to read.
fx_seed_repo() { # DIR
    local dir=$1
    mkdir -p "$dir"
    cat >"$dir/.sentinel.yml" <<'YAML'
schema: 1
on: push
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps:
      - id: hello
        run: 'true'
YAML
    git -C "$dir" init -q -b main
    git -C "$dir" add -A
    git -C "$dir" -c user.name=fixture -c user.email=fixture@example.invalid \
        commit -qm "fixture: initial pipeline"
}

# Tags a repository with a new commit and pushes it: every exercise has a fresh object id.
fx_commit() { # REPO_DIR MARKER -> new HEAD
    mkdir -p "$1"
    { printf 'fixture %s %s\n' "$2" "$(date +%s%N)"; } >>"$1/.fixture-pushes"
    git -C "$1" add -A
    git -C "$1" -c user.name=fixture -c user.email=fixture@example.invalid \
        commit -qm "fixture push $2"
    git -C "$1" rev-parse HEAD
}

fx_status() { # NAME
    local name=$1 container state
    fx_require_runtime "$name"
    container=$(fx_container "$name")
    state=$(fx_state "$name")
    if fx_rt inspect "$container" >/dev/null 2>&1; then
        printf '%s up (%s)\n' "$name" "$(fx_rt inspect --format '{{.State.Status}}' "$container")"
        [ -f "$state/bindings.sh" ] && sed 's/^/  /' "$state/bindings.sh"
    else
        printf '%s down\n' "$name"
    fi
}

fx_print() { # NAME
    local trust
    # shellcheck disable=SC1090
    . "$(fx_state "$1")/bindings.sh"
    if [ -s "$FIXTURE_CA_PEM" ]; then trust=$FIXTURE_CA_PEM; else trust=$FIXTURE_KNOWN_HOSTS; fi
    printf 'fixture    %s\n' "$1"
    printf 'remote     %s\n' "$FIXTURE_REMOTE"
    printf 'binding    %s (0600, holds the credential)\n' "$FIXTURE_BINDING"
    printf 'trust      %s\n' "$trust"
    printf 'hook env   %s\n' "$FIXTURE_HOOK_ENV"
    printf 'hook post  %s\n' "$FIXTURE_HOOK_INTAKE_ON_HOST"
}

# --- Gitea and Forgejo -----------------------------------------------------------------------
# Both take the same app.ini overrides through GITEA__* and the same admin CLI, so one flow
# serves the two forges and the HTTPS and SSH transports.

fx_forge_api() { # CA-OR-EMPTY METHOD PATH JSON
    local cert=() status body
    [ -n "$1" ] && cert=(--cacert "$1")
    body=$(curl -sS --max-time 20 "${cert[@]}" -X "$2" -H "Authorization: token $FX_TOKEN" \
        -H 'content-type: application/json' -d "$4" -w '\n%{http_code}' "$FX_API_URL$3") || return 1
    status=${body##*$'\n'}
    case "$status" in
        2*) printf '%s\n' "${body%$'\n'*}" ;;
        *) fx_err "the forge API answered $status for $2 $3"; return 1 ;;
    esac
}

fx_forge_hook() { # NAME HOOK_DIR SECRET
    local container hook_dir
    container=$(fx_container "$1")
    hook_dir=$2
    fx_hook_env "$(fx_state "$1")/hook.env" "$3" "$(fx_intake "$1")"
    fx_rt exec -i -u git "$container" sh -c \
        "mkdir -p '$hook_dir' && cat > '$hook_dir/sentinel' && chmod 755 '$hook_dir/sentinel'" \
        <"$FX_SHIPPED_HOOK"
    fx_rt exec -i -u git "$container" sh -c \
        "cat > '$hook_dir/sentinel-hook.env' && chmod 600 '$hook_dir/sentinel-hook.env'" \
        <"$(fx_state "$1")/hook.env"
}

# FX_RUN_ARGS holds the fixture's own container flags (ports, environment); the caller sets it.
# TLS_MODE is https (a copied local CA) or http. CREDENTIAL is https (a read-only token) or ssh
# (a deploy key). SSH_PORT is empty for an HTTPS fixture.
fx_forge_up() { # NAME IMAGE CLI API_URL TLS_MODE CREDENTIAL SSH_PORT
    local name=$1 image=$2 cli=$3 api=$4 tls_mode=$5 credential=$6 ssh_port=$7
    local container state ca read_token push_token
    container=$(fx_container "$name")
    state=$(fx_state "$name")
    mkdir -p "$state"
    chmod 700 "$state"
    FX_API_URL=$api
    fx_image "$image"
    fx_rt create --name "$container" "${FX_ADD_HOST[@]}" \
        -v "$(fx_volume "$name"):/data" "${FX_RUN_ARGS[@]}" "$image" >/dev/null
    ca=
    if [ "$tls_mode" = https ]; then
        # The leaf must be readable by the forge's own uid inside the container, and the CA's
        # private key never leaves the host: it is not among the three files copied.
        mkdir -p "$state/tls-public"
        chmod 701 "$state/tls-public"
        cp "$state/tls/ca.pem" "$state/tls/server.pem" "$state/tls/server-key.pem" "$state/tls-public/"
        chmod 644 "$state"/tls-public/*.pem
        fx_rt cp "$state/tls-public" "$container:/data/tls" >/dev/null
        ca=$state/tls/ca.pem
    fi
    fx_rt start "$container" >/dev/null
    fx_wait_http "$api/api/v1/version" "$ca" 180 ||
        fx_die "$name: $api never answered; see '$FX_RUNTIME logs $container'"

    # No password is handled at all: the account exists for its tokens and deploy key.
    fx_rt exec -u git "$container" "$cli" admin user create --username ci --random-password \
        --email ci@example.invalid --must-change-password=false >/dev/null
    # Two credentials on purpose: the binding gets read:repository, the fixture's own push needs
    # write:repository. Neither is ever printed.
    push_token=$(fx_rt exec -u git "$container" "$cli" admin user generate-access-token \
        --username ci --token-name sentinel-push --scopes write:repository,write:user --raw)
    read_token=$(fx_rt exec -u git "$container" "$cli" admin user generate-access-token \
        --username ci --token-name sentinel-read --scopes read:repository --raw)
    [ -n "$push_token" ] && [ -n "$read_token" ] || fx_die "$name: the forge issued no token"
    printf '%s\n' "$read_token" >"$state/read-token"
    chmod 600 "$state/read-token"

    FX_TOKEN=$push_token
    fx_forge_api "$ca" POST /api/v1/user/repos \
        '{"name":"app","private":true,"auto_init":false,"default_branch":"main"}' >/dev/null ||
        fx_die "$name: cannot create ci/app"
    FX_TOKEN=

    fx_seed_repo "$state/seed"
    if [ "$credential" = https ]; then
        printf '%s\n' "$push_token" >"$state/push-token"
        chmod 600 "$state/push-token"
        fx_askpass "$state/askpass"
        FX_CA_PEM=$ca FX_ASKPASS=$state/askpass FX_GIT_USER=ci FX_GIT_SECRET=$push_token
        fx_git_push "$FX_REMOTE" "$state/seed" ||
            fx_die "$name: the fixture's own push over HTTPS failed"
    else
        fx_gen_key "$state/client-key"
        FX_TOKEN=$push_token
        fx_forge_api "$ca" POST /api/v1/repos/ci/app/keys \
            "$(python3 -c 'import json,sys; print(json.dumps({"title":"sentinel","key":open(sys.argv[1]).read().strip(),"read_only":False}))' \
                "$state/client-key.pub")" >/dev/null
        FX_TOKEN=
        # The served key, not the one on the volume: pin what the server actually presents.
        fx_wait_tcp "$ssh_port" 120 || fx_die "$name: the built-in SSH server never listened"
        ssh-keyscan -t ed25519 -p "$ssh_port" 127.0.0.1 >"$state/known_hosts" 2>/dev/null
        [ -s "$state/known_hosts" ] || fx_die "$name: no SSH host key to pin"
        FX_SSH_KEY=$state/client-key FX_KNOWN_HOSTS=$state/known_hosts
        fx_git_push "$FX_REMOTE" "$state/seed" ||
            fx_die "$name: the fixture's own push over SSH failed"
    fi

    fx_forge_hook "$name" /data/git/repositories/ci/app.git/hooks/post-receive.d \
        "sentinel_hook_fixture_${name//-/_}"
    if [ "$credential" = https ]; then
        fx_bind "$name" "$FX_REMOTE" https "https:ci:$state/read-token"
    else
        fx_bind "$name" "$FX_REMOTE" ssh "ssh:$state/client-key"
    fi
    repo=$(fx_state "$name")
    fx_print "$name"
    printf 'push       %s push %s\n' "${0##*/}" "$name"
}
