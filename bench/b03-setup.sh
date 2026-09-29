#!/usr/bin/env bash
# B03: a Sentinel deployment for the latency budgets, as the bench user on
# the reference host: a controller and a worker, and a small repository bound
# over loopback HTTPS whose branches each carry one measurement's pipeline
# (bench/b03-latency.py pushes to them and posts the intake events).
#
#   bench/b03-setup.sh setup KIT ROOT
#   bench/b03-setup.sh start KIT ROOT
#   bench/b03-setup.sh stop  KIT ROOT
#
# KIT holds `sentinel` (release, both roles) and git_https.py.
set -euo pipefail
MODE=$1 KIT=$2 ROOT=$3
BIN="$KIT/sentinel"
C="$ROOT/controller" W="$ROOT/worker"
IMAGE=docker.io/library/golang:1.27.1-trixie@sha256:7bffdb405cd12940d2980daa49a86ef575ed4525a17ee7d0c9562547357ab46a
ident=(-c user.name=sentinel-bench -c user.email=bench@sentinel.invalid)

event() { # event <log> <event>: the first such record, waiting up to 60 s
  for _ in $(seq 1 600); do
    line=$(grep -m1 "\"event\":\"$2\"" "$1" 2>/dev/null || true)
    [ -n "$line" ] && { printf '%s' "$line"; return; }
    sleep 0.1
  done
  echo "no $2 in $1" >&2; tail -5 "$1" >&2; return 1
}
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fields"][sys.argv[2]])' "$1" "$2"; }
admin() { "$BIN" admin "$@" --data-dir "$C"; }
source_admin() { "$BIN" admin source --data-dir "$C" --actor "$(cat "$ROOT/actor")" "$@"; }
stop_group() {
  [ -f "$1" ] || return 0
  kill -TERM -- "-$(cat "$1")" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 -- "-$(cat "$1")" 2>/dev/null || break; sleep 0.1; done
  rm -f "$1"
}

pipeline() { # pipeline <job body>: a one-job pipeline on the warm image
  printf 'schema: 1\non: [push]\njobs:\n  probe:\n    image: %s\n    resources: { cpu: 1, memory: 512MiB }\n    timeout: 20m\n%s\n' "$IMAGE" "$1"
}

case "$MODE" in
setup)
  mkdir -p "$ROOT" && cd "$ROOT"
  if [ ! -d work ]; then
    git init -q -b main work
    echo "B03 latency fixture" > work/README
    git -C work add README && git "${ident[@]}" -C work commit -q -m base
    branch() { # branch <name> <job body>
      git -C work checkout -q -B "$1" main
      pipeline "$2" > work/.sentinel.yml
      git -C work add .sentinel.yml && git "${ident[@]}" -C work commit -q -m "$1"
    }
    # Budget 4: the first user process prints the wall clock (ns).
    branch first '    steps:
      - id: first
        run: date +%s%N'
    # Budget 6: a line every 100 ms, each carrying its own capture time.
    branch logs '    steps:
      - id: lines
        run: for i in $(seq 1 100); do echo "t=$(date +%s%N)"; sleep 0.1; done'
    # Budget 7: a step that ends on SIGTERM; the cancel is timed.
    branch cancel '    steps:
      - id: wait
        run: exec sleep 600'
    # Budget 8: 100 MiB of output, then a Go test failure, as go test -json.
    branch failure '    steps:
      - id: test
        run: |
          head -c 104857600 /dev/zero | tr "\\0" "x" | fold -w 511
          printf "%s\\n" "{\"Action\":\"run\",\"Package\":\"example/b03\",\"Test\":\"TestBudget\"}" "{\"Action\":\"output\",\"Package\":\"example/b03\",\"Test\":\"TestBudget\",\"Output\":\"    b03_test.go:7: the needle: want 1, got 2\\n\"}" "{\"Action\":\"fail\",\"Package\":\"example/b03\",\"Test\":\"TestBudget\",\"Elapsed\":0.01}"
          exit 1'
    # Budget 5: a fixed published fixture, 1,000 files of 64 KiB (64 MiB).
    branch cache '    cache:
      - name: fixture
        class: dependencies
        key: "b03-fixture-v1"
        paths: [/cache/fixture]
    steps:
      - id: use
        run: |
          if [ ! -f /cache/fixture/999 ]; then mkdir -p /cache/fixture; for i in $(seq 0 999); do head -c 65536 /dev/urandom > /cache/fixture/$i; done; fi
          test "$(ls /cache/fixture | wc -l)" = 1000'
    git -C work checkout -q main
    mkdir -p git
    git clone -q --bare work git/probe
    git -C git/probe config uploadpack.allowAnySHA1InWant true
    git -C work remote add bench "$ROOT/git/probe"
    git -C work push -q bench --all
  fi
  if [ ! -f tls.key ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=localhost \
      -addext subjectAltName=IP:127.0.0.1 -keyout tls.key -out ca.pem 2>/dev/null
    (umask 077; head -c 24 /dev/urandom | base64 | tr -d '\n' > password)
  fi
  if [ ! -d "$C" ]; then
    mkdir -p "$C"
    printf 'correct horse battery staple' | admin bootstrap --username root >/dev/null
    admin key create >/dev/null
    tenant=$(admin tenant create --slug acme | tr -d '\n')
    admin status | sed -n 's/.*subject=\([^ ]*\).*/\1/p' | head -1 > actor
    source_admin create --tenant "$tenant" --name probe | python3 -c 'import json,sys; print(json.load(sys.stdin)["repo"])' > repo
    admin pool create --name builders --tenant acme >/dev/null
    admin worker enroll --pool builders > enrollment
    admin token issue --user root --name b03 --scope read,run,tenant-admin,platform-admin --expires-in 7d > token
    printf 'listen = "127.0.0.1:0"\napi_listen = "127.0.0.1:0"\n' > server.toml
  fi
  ;;
start)
  cd "$ROOT"
  setsid env FIXTURE_PASSWORD="$ROOT/password" python3 "$KIT/git_https.py" "$ROOT/git" ca.pem tls.key > git.port 2>/dev/null < /dev/null &
  echo $! > git.pgid
  for _ in $(seq 1 100); do [ -s git.port ] && break; sleep 0.1; done
  port=$(head -1 git.port)
  printf '["https://127.0.0.1:%s"]' "$port" > "$C/source-destinations.json"
  expected=$( (source_admin show --repo "$(cat repo)" 2>/dev/null || echo '{}') | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version") or 0)')
  python3 - "$port" "$ROOT" <<'PY' | source_admin bind --repo "$(cat repo)" --expected "$expected" >/dev/null
import json, sys
port, root = sys.argv[1:]
print(json.dumps({
    "binding": {"remote": f"https://127.0.0.1:{port}/probe", "allowed_refs": ["refs/heads/*"],
                "pipeline_path": ".sentinel.yml", "trust": open(f"{root}/ca.pem").read()},
    "credential": {"Https": {"username": "deploy", "secret": open(f"{root}/password").read()}},
    "forge": None}))
PY
  source_admin hook-token --repo "$(cat repo)" | tr -d '\n' > hook
  setsid "$BIN" server --config server.toml --data-dir "$C" --log-format json > server.log 2>&1 < /dev/null &
  echo $! > server.pgid
  link=$(event server.log link_listening); api=$(event server.log api_listening)
  field "$api" addr > api.addr
  printf 'controller = "%s"\ncontroller_fingerprint = "%s"\nworker_name = "b03"\nenrollment_file = "%s/enrollment"\n' \
    "$(field "$link" addr)" "$(field "$link" fingerprint)" "$ROOT" > worker.toml
  setsid "$BIN" worker --config worker.toml --data-dir "$W" --log-format json > worker.log 2>&1 < /dev/null &
  echo $! > worker.pgid
  event worker.log link_connected >/dev/null
  curl -fsS -X PUT -H "authorization: Bearer $(cat token)" -H 'content-type: application/json' \
    -d '{"role":"admin"}' "http://$(cat api.addr)/api/v1/tenants/acme/members/root" >/dev/null
  echo "started: git on $port, api on $(cat api.addr)"
  ;;
stop)
  cd "$ROOT"
  stop_group worker.pgid; stop_group server.pgid; stop_group git.pgid
  ;;
esac
