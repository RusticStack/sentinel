#!/usr/bin/env bash
# The G08 fixture matrix: raise the forges, push through their hooks, tear them down.
#
#   scripts/git-fixtures/run.sh up [fixture ...]
#   scripts/git-fixtures/run.sh down [fixture ...]
#   scripts/git-fixtures/run.sh status [fixture ...]
#   scripts/git-fixtures/run.sh push FIXTURE        a new commit through the fixture's remote
#   scripts/git-fixtures/run.sh exercise [fixture ...]
#
# `exercise` proves the hook without a controller: it starts the recording listener, raises each
# fixture, pushes twice through the fixture's own remote, and checks that the shipped
# `post-receive` hook delivered both pushes to the intake URL with the bearer secret, the JSON
# body and the ref the fixture is bound to. Nothing here needs root, and every image is pinned by
# digest, so a second run pulls nothing it already has.
set -euo pipefail
. "$(dirname -- "$0")/lib.sh"
fx_shipped_hook

LISTEN_PORT=${SENTINEL_FIXTURE_LISTEN_PORT:-7099}
HERE=$(dirname -- "$0")
WORK=  # the exercise's scratch (<root>/.exercise), removed on exit

fixture_script() { printf '%s/%s.sh' "$HERE" "$1"; }

selected() { # the fixtures asked for, defaulting to the whole matrix
    if [ "$#" -gt 0 ]; then printf '%s\n' "$@"; else printf '%s\n' $FX_NAMES; fi
}

# A push needs the fixture's own client credential, not the binding's read token.
fx_client() { # NAME
    local state
    state=$(fx_state "$1")
    # shellcheck disable=SC1090
    . "$state/bindings.sh"
    FX_REMOTE=$FIXTURE_REMOTE
    if [ -s "$state/push-token" ]; then
        FX_CA_PEM=$FIXTURE_CA_PEM
        FX_ASKPASS=$state/askpass
        FX_GIT_USER=ci
        FX_GIT_SECRET=$(cat "$state/push-token")
    else
        FX_SSH_KEY=$FIXTURE_SSH_KEY
        FX_KNOWN_HOSTS=$FIXTURE_KNOWN_HOSTS
    fi
}

push_once() { # NAME MARKER -> the pushed commit
    local state rev
    state=$(fx_state "$1")
    fx_client "$1"
    rev=$(fx_commit "$state/seed" "$2")
    fx_git_push "$FX_REMOTE" "$state/seed"
    printf '%s\n' "$rev"
}

listener_start() { # the addresses a fixture's container can reach the listener on
    local address binds=(--bind 127.0.0.1)
    if [ "$FX_RUNTIME" = docker ]; then
        address=$(fx_rt network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')
        binds+=(--bind "$address")
    fi
    WORK=$(fx_state .exercise)
    rm -rf "$WORK"
    mkdir -p "$WORK"
    python3 "$HERE/listener.py" --out "$WORK/deliveries.jsonl" --port "$LISTEN_PORT" \
        "${binds[@]}" >"$WORK/listener.log" 2>&1 &
    LISTENER_PID=$!
    local i=0
    until [ -s "$WORK/listener.log" ]; do
        i=$((i + 1))
        [ "$i" -gt 40 ] && { fx_err "the listener never started"; return 1; }
        sleep 0.25
    done
}

listener_stop() {
    [ -n "${LISTENER_PID:-}" ] && kill "$LISTENER_PID" 2>/dev/null || true
    LISTENER_PID=
}

# Checks the deliveries the listener recorded for one fixture: two pushes, in order, each with the
# hook's bearer secret, a JSON content type and the revisions that were pushed.
verify() { # NAME PATH SECRET EXPECTED_OLD EXPECTED_NEW SECOND_OLD SECOND_NEW
    python3 - "$WORK/deliveries.jsonl" "$2" "$3" "$4" "$5" "$6" "$7" <<'PY'
import json, sys
file, path, secret, old1, new1, old2, new2 = sys.argv[1:8]
try:
    records = [json.loads(line) for line in open(file, encoding="utf8")]
except FileNotFoundError:
    records = []
mine = [r for r in records if r["path"] == path]
def seen():
    out = []
    for r in mine:
        try:
            out.append(json.loads(r["body"]).get("new_sha", "?")[:8])
        except ValueError:
            out.append("not JSON")
    return ", ".join(out) or "nothing"
def find(old, new):
    for r in mine:
        try:
            body = json.loads(r["body"])
        except ValueError:
            continue
        if body.get("ref") == "refs/heads/main" and body.get("old_sha") == old and body.get("new_sha") == new:
            return r, body
    return None, None
failures = []
pushes = [(old1, new1), (old2, new2)]
delivered = []
for old, new in pushes:
    record, body = find(old, new)
    if record is None:
        failures.append(f"no delivery for {old[:8]}..{new[:8]} (the hook delivered {seen()})")
        continue
    if record["headers"].get("authorization") != f"Bearer {secret}":
        failures.append(f"{new[:8]}: authorization header is not the hook secret")
    if "application/json" not in record["headers"].get("content-type", ""):
        failures.append(f"{new[:8]}: content-type is {record['headers'].get('content-type')!r}")
    if not body.get("delivery_id"):
        failures.append(f"{new[:8]}: no delivery id")
    delivered.append(body.get("delivery_id"))
if len(set(delivered)) != len(delivered):
    failures.append("the two pushes share a delivery id")
if failures:
    print("FAIL " + "; ".join(failures))
    sys.exit(1)
print(f"PASS {len(delivered)} deliveries, ids {', '.join(delivered)}")
PY
}

exercise_one() { # NAME -> 0 delivered and verified
    local name=$1 state old1 new1 old2 new2 prefix secret
    state=$(fx_state "$name")
    if [ "${SENTINEL_FIXTURE_REUSE:-0}" != 1 ]; then
        "$(fixture_script "$name")" up >/dev/null || { echo "FAIL $name did not come up"; return 1; }
    fi
    # shellcheck disable=SC1090
    . "$state/bindings.sh"
    old1=$(git -C "$state/seed" rev-parse HEAD)
    new1=$(push_once "$name" first)
    old2=$new1
    new2=$(push_once "$name" second)
    prefix=$(fx_intake_path "$name")
    secret="sentinel_hook_fixture_${name//-/_}"
    if ! verify "$name" "$prefix" "$secret" "$old1" "$new1" "$old2" "$new2"; then
        echo "FAIL $name push $old1..$new2"
        return 1
    fi
    echo "PASS $name $FIXTURE_REMOTE"
}

case "${1:-}" in
    up)
        shift
        for name in $(selected "$@"); do "$(fixture_script "$name")" up; done
        ;;
    down)
        shift
        for name in $(selected "$@"); do "$(fixture_script "$name")" down; done
        ;;
    status)
        shift
        for name in $(selected "$@"); do fx_status "$name"; done
        ;;
    push)
        [ "$#" -eq 2 ] || { fx_err "usage: $0 push FIXTURE"; exit 2; }
        fx_preflight "$1"
        fx_add_host
        push_once "$1" manual
        ;;
    exercise)
        shift
        fx_preflight exercise
        fx_add_host
        trap 'listener_stop; [ -n "$WORK" ] && rm -rf "$WORK"' EXIT
        listener_start
        failed=0
        for name in $(selected "$@"); do
            if ! exercise_one "$name"; then failed=$((failed + 1)); fi
        done
        if [ "$failed" -ne 0 ]; then
            fx_err "$failed of the requested fixtures did not deliver; deliveries are in $WORK/deliveries.jsonl"
            exit 1
        fi
        echo "matrix: every requested fixture delivered both pushes"
        ;;
    *) fx_usage ;;
esac
