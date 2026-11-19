#!/usr/bin/env bash
# Self-test for the G08 fixtures. Runs no container and pulls no image: it checks what can be
# checked without a runtime, and in particular that every script's preflight fails cleanly —
# exit 3 and a message naming what is missing — when there is no runtime at all.
#
#   scripts/git-fixtures/selftest.sh
set -uo pipefail
# The checks below decide for themselves that no runtime exists, whatever the caller exported.
unset SENTINEL_FIXTURE_RUNTIME
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
REPO=$(cd -- "$HERE/../.." && pwd)
FIXTURES="gitea-https gitea-ssh forgejo-https gitlab-ssh bare-sshd"
failed=0
pass() { printf 'PASS %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failed=$((failed + 1)); }

# A PATH with the account's own tools but no container runtime: the preflight has to reach its
# runtime check through the same sourcing and tool lookups a real run does, and fail there.
without_runtime() { # DIR
    local file name
    for file in /usr/local/bin/* /usr/bin/* /bin/*; do
        [ -x "$file" ] || continue
        name=${file##*/}
        case "$name" in podman | docker | nerdctl | podman-remote) continue ;; esac
        [ -e "$1/$name" ] || ln -s "$file" "$1/$name"
    done
}

empty=$(mktemp -d)
trap 'rm -rf "$empty"' EXIT
bash_path=$(command -v bash)
without_runtime "$empty"
if PATH=$empty command -v podman >/dev/null 2>&1 || PATH=$empty command -v docker >/dev/null 2>&1; then
    fail "the self-test could not build a PATH without a container runtime"
else
    pass "the self-test's PATH has no container runtime"
fi

for name in $FIXTURES; do
    script=$HERE/$name.sh
    [ -f "$script" ] || { fail "$name.sh is missing"; continue; }
    [ -x "$script" ] || fail "$name.sh is not executable"
    bash -n "$script" 2>/dev/null && pass "$name.sh parses" || fail "$name.sh does not parse"

    for verb in up down status; do
        err=$(PATH=$empty SENTINEL_FIXTURE_ROOT="$empty/state" "$bash_path" "$script" "$verb" 2>&1)
        code=$?
        if [ "$code" -ne 3 ]; then
            fail "$name.sh $verb without a runtime exited $code, not 3: $err"
        elif ! printf '%s' "$err" | grep -q "no container runtime"; then
            fail "$name.sh $verb without a runtime did not name the missing runtime: $err"
        else
            pass "$name.sh $verb without a runtime fails cleanly"
        fi
    done

    err=$(PATH=$empty SENTINEL_FIXTURE_RUNTIME=definitely-not-a-runtime "$bash_path" "$script" up 2>&1)
    code=$?
    if [ "$code" -eq 3 ] && printf '%s' "$err" | grep -q "definitely-not-a-runtime"; then
        pass "$name.sh refuses a runtime it does not have"
    else
        fail "$name.sh with a named but absent runtime exited $code: $err"
    fi

    out=$("$bash_path" "$script" --selftest-unknown-verb 2>&1)
    [ $? -eq 2 ] && pass "$name.sh refuses an unknown verb" || fail "$name.sh accepted an unknown verb: $out"
done

sh -n "$HERE/sshd-entrypoint.sh" && pass "sshd-entrypoint.sh parses" || fail "sshd-entrypoint.sh does not parse"
python3 - "$HERE/listener.py" <<'PY' && pass "listener.py compiles" || fail "listener.py does not compile"
import sys
compile(open(sys.argv[1], encoding="utf8").read(), sys.argv[1], "exec")
PY

# The fixtures must never need root, and never run a command that only root could use.
if grep -rnw sudo --include=*.sh --exclude=selftest.sh "$HERE" >/dev/null 2>&1; then
    fail "a fixture script asks for sudo"
else
    pass "no fixture script asks for sudo"
fi

# A tag would drift under a re-run; every image is pinned by digest.
for image in GITEA_IMAGE FORGEJO_IMAGE GITLAB_IMAGE ALPINE_IMAGE; do
    line=$(grep -m1 "^$image=" "$HERE/lib.sh")
    case "$line" in
        *@sha256:*) pass "$image is pinned by digest" ;;
        *) fail "$image is not pinned by digest: $line" ;;
    esac
done

# The shipped hook, not a copy: a fixture that shipped its own could pass while the real one broke.
if grep -q 'FX_SHIPPED_HOOK=$(cd' "$HERE/lib.sh" && grep -q 'examples/hooks/post-receive' "$HERE/lib.sh"; then
    pass "fixtures install the shipped post-receive hook"
else
    fail "fixtures do not resolve examples/hooks/post-receive"
fi
[ -f "$REPO/examples/hooks/post-receive" ] && pass "the shipped hook exists" ||
    fail "$REPO/examples/hooks/post-receive is missing"

if [ "$failed" -ne 0 ]; then
    printf '%s check(s) failed\n' "$failed" >&2
    exit 1
fi
printf 'selftest: %s fixture scripts behave without a runtime\n' "$(printf '%s\n' $FIXTURES | wc -l)"
