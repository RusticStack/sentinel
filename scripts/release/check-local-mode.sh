#!/usr/bin/env bash
# Fully local operation (V02): a controller, one worker and a generic Git remote
# on one host, with no GitHub, no mail, no S3 and no outbound network. A push to
# the remote runs the repository's `post-receive` hook, the hook posts the ref
# update to the controller, and the worker runs the pipeline's job.
#
#   scripts/release/check-local-mode.sh <server-package-dir> <worker-package-dir> <work-dir>
#
# Prerequisites, all on the verification host:
#  - Run it as an unprivileged account with rootless Podman (subordinate ids),
#    git, ssh/sshd and python3, inside a network namespace that has only
#    loopback. As root that is
#      unshare --net -- sh -c 'ip link set lo up; exec runuser -u ACCOUNT -- bash scripts/release/check-local-mode.sh ...'
#  - The pinned busybox image must already be in the account's Podman store
#    (`podman pull docker.io/library/busybox@sha256:73aaf090...` BEFORE the
#    network is closed); point CONTAINERS_STORAGE_CONF / CONTAINERS_CONF at a
#    private store to keep the account's own images out of it.
#  - <work-dir> must not exist yet or be empty; everything is written below it.
# It listens on loopback ports 42222 (sshd), 47080 (API) and 47443 (worker link).
# Exit status is 0 only when the job passed and both processes stopped with 0.
# as $ME, inside a network namespace that has only loopback.
set -uo pipefail
SP_DIR=${1:?server package dir}; WP_DIR=${2:?worker package dir}; R=${3:?work dir}; mkdir -p "$R/tmp"; R=$(cd "$R" && pwd)
HOOK_SRC=$(cd "$(dirname "$0")/../.." && pwd)/examples/hooks/post-receive; ME=$(id -un)
S=$SP_DIR/bin/sentinel
W=$WP_DIR/bin/sentinel
export HOME=$(getent passwd "$ME" | cut -d: -f6) XDG_RUNTIME_DIR=/run/user/$(id -u) TMPDIR=$R/tmp
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
DATA=$R/controller; WDATA=$R/worker
PIDS=
cleanup() { for p in $PIDS; do kill $p 2>/dev/null; done; }
trap cleanup EXIT
step() { echo; echo "=== $*"; }
srcadm() { $S admin source --actor $ACTOR --data-dir $DATA "$@"; }
adm() { local p=$1; shift; printf 'correct horse battery staple' | $S admin $p --data-dir $DATA "$@"; }

step "network state"
ip -br addr 2>&1 | head; ip route 2>&1 | head -3; echo "routes above (none expected)"
curl -sS -m 4 -o /dev/null https://github.com 2>&1 | head -2
curl -sS -m 4 -o /dev/null https://1.1.1.1 2>&1 | head -2

step "ssh git remote on loopback"
mkdir -p $R/ssh && chmod 700 $R/ssh
ssh-keygen -q -t ed25519 -N '' -f $R/ssh/host
ssh-keygen -q -t ed25519 -N '' -f $R/ssh/deploy
cp $R/ssh/deploy.pub $R/ssh/authorized_keys
cat > $R/ssh/sshd_config <<C
Port 42222
ListenAddress 127.0.0.1
HostKey $R/ssh/host
AuthorizedKeysFile $R/ssh/authorized_keys
PidFile $R/ssh/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
C
/usr/sbin/sshd -f $R/ssh/sshd_config -D -e > $R/ssh/sshd.log 2>&1 &
PIDS="$PIDS $!"
git init -q --bare --initial-branch=main $R/origin.git
REPO=ssh://$ME@127.0.0.1:42222$R/origin.git
git init -q --initial-branch=main $R/work
cat > $R/work/.sentinel.yml <<'C'
schema: 1
on: {push: {branches: [main]}}
jobs:
  build:
    image: docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
    steps:
      - id: hello
        run: echo local-mode-ok && cat /proc/net/dev | wc -l
C
(cd $R/work && git add .sentinel.yml && git commit -q -m pipeline)

step "admin setup (controller stopped)"
mkdir -p $DATA $WDATA
adm bootstrap --username root || exit 1
adm "key create" || exit 1
TENANT=$(adm "tenant create" --slug acme | tr -d '\n'); echo "tenant=$TENANT"
ACTOR=$(adm status | sed -n 's/.*subject=\([^ ]*\).*/\1/p' | head -1); echo "actor=$ACTOR"
adm "pool create" --name local --tenant acme || exit 1
printf '["ssh://%s@127.0.0.1:42222"]' "$ME" > $DATA/source-destinations.json
REPOID=$(srcadm create --tenant $TENANT --name app | sed -n 's/.*"repo":"\([^"]*\)".*/\1/p'); echo "repo=$REPOID"
PUB=$(cut -d' ' -f1,2 $R/ssh/host.pub)
python3 - "$R" "$REPO" "$PUB" > $R/bind.json <<'PY'
import json,sys
r,repo,pub=sys.argv[1:4]
print(json.dumps({"binding":{"remote":repo,"allowed_refs":["refs/heads/main"],"pipeline_path":".sentinel.yml","trust":"[127.0.0.1]:42222 "+pub+"\n"},
 "credential":{"Ssh":{"private_key":open(r+"/ssh/deploy").read()}},"forge":None}))
PY
$S admin source --actor $ACTOR --data-dir $DATA bind --repo $REPOID --expected 0 < $R/bind.json || exit 1
HOOK=$($S admin source --actor $ACTOR --data-dir $DATA hook-token --repo $REPOID | tr -d '\n')
echo "hook token issued: ${HOOK:0:14}..."
adm "worker enroll" --pool local > $WDATA/enrollment; chmod 600 $WDATA/enrollment
TOKEN=$(adm "token issue" --user root --name smoke --scope read,run --expires-in 1h | tr -d '\n')

step "start controller"
cat > $R/server.toml <<C
data_dir = "$DATA"
log_format = "json"
listen = "127.0.0.1:47443"
api_listen = "127.0.0.1:47080"
C
$S server --config $R/server.toml > $R/server.log 2>&1 &
SP=$!; PIDS="$PIDS $SP"
for i in $(seq 1 100); do grep -q link_listening $R/server.log && grep -q api_listening $R/server.log && break; sleep 0.2; done
FP=$(sed -n 's/.*"event":"link_listening".*"fingerprint":"\([0-9a-f]*\)".*/\1/p' $R/server.log | head -1)
echo "fingerprint=${FP:0:12}..."
curl -sS -m 5 http://127.0.0.1:47080/api/v1/health; echo

step "start worker"
cat > $R/worker.toml <<C
data_dir = "$WDATA"
log_format = "json"
controller = "127.0.0.1:47443"
controller_fingerprint = "$FP"
worker_name = "local-1"
enrollment_file = "$WDATA/enrollment"
C
$W worker --config $R/worker.toml > $R/worker.log 2>&1 &
WP=$!; PIDS="$PIDS $WP"
for i in $(seq 1 100); do grep -q executor_ready $R/worker.log && break; sleep 0.2; done
grep -o '"event":"[a-z_]*"' $R/worker.log | sort | uniq -c
sleep 3
grep -o '"event":"[a-z_]*"' $R/server.log | sort | uniq -c

step "install the post-receive hook and push"
cp $HOOK_SRC $R/origin.git/hooks/post-receive; chmod +x $R/origin.git/hooks/post-receive
cat > $R/origin.git/hooks/sentinel-hook.env <<C
SENTINEL_INTAKE_URL=http://127.0.0.1:47080/api/v1/intake/$REPOID
SENTINEL_HOOK_SECRET=$HOOK
SENTINEL_SPOOL_DIR=$R/spool
C
chmod 600 $R/origin.git/hooks/sentinel-hook.env; mkdir -p $R/spool
(cd $R/work && GIT_SSH_COMMAND="ssh -F /dev/null -i $R/ssh/deploy -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" git push $REPO main 2>&1)
step "wait for the run"
for i in $(seq 1 120); do
  RUNS=$(curl -sS -m 5 -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:47080/api/v1/tenants/acme/repos/app/runs?limit=5")
  echo "$RUNS" | grep -q '"state":"\(passed\|failed\|cancelled\)"' && break
  sleep 1
done
echo "$RUNS"
grep -o '"outcome":"[^"]*"' $R/server.log | head
ATT=$(grep -o 'att_[0-9a-f-]*' $R/server.log $R/worker.log | head -1 | cut -d: -f2); echo "attempt=$ATT"

step "stop"
kill -TERM $WP; wait $WP; WRC=$?; echo "worker exit=$WRC"
kill -TERM $SP; wait $SP; SRC=$?; echo "controller exit=$SRC"
PIDS=
[ -n "$ATT" ] && adm logs --attempt $ATT
$S admin intake --data-dir $DATA list --repo $REPOID
if grep -q "\"verdict\":\"Passed\"" "$R/worker.log" && [ "$WRC" = 0 ] && [ "$SRC" = 0 ]; then echo "ok  a push ran a job to Passed with no outbound network"; else echo "FAIL" >&2; exit 1; fi
