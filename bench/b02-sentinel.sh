#!/usr/bin/env bash
# B02: the lockwell-ci contract's `unit` lane through Sentinel itself — a git
# push, the generic intake event, dispatch, a rootless worker, the pipeline in
# bench/b02-sentinel.yml — on the reference host, as the bench user.
#
#   bench/b02-sentinel.sh setup   KIT ROOT BUNDLES MODCACHE
#   bench/b02-sentinel.sh start   KIT ROOT
#   bench/b02-sentinel.sh measure KIT ROOT CONDITION SAMPLES WARMUP OUT
#   bench/b02-sentinel.sh stop    KIT ROOT
#
# KIT holds `sentinel` (a release build with both roles), git_https.py (the
# repository's loopback HTTPS Git fixture, its per-request limit raised from
# 10 s to 300 s for a repository of this size) and b02-sentinel.yml. setup builds
# the bench source — Lockwell at the contract's commit with the SDK trees
# vendored under sdk-checkouts/ and .goproxy completed from MODCACHE (a warm
# module cache of the same go.sum), since jobs have no egress and no extra
# checkouts yet — serves it from a bare repository over loopback HTTPS, and
# prepares a controller (tenant, bound source, pool, enrollment) and a worker.
# measure pushes one commit per run (empty; for small-edit the contract's
# edit; for cold after emptying the worker's cache), posts the ref update to
# the intake route, and times intake to the run's end. One JSON line per run.
set -euo pipefail
MODE=$1 KIT=$2 ROOT=$3
BIN="$KIT/sentinel"
LOCKWELL=cbe48fc712dc510ca77bfa4de7efe8101c7cc521
NODE_SDK=bccad4c89ee6d2270cc2a90298e76d244f9285e4
JAVA_SDK=37c921f6390ff85a8f2e4034a62482cab7c54020
C="$ROOT/controller" W="$ROOT/worker"
ident=(-c user.name=sentinel-bench -c user.email=bench@sentinel.invalid)

event() { # event <log> <event> [nth]: that record's JSON, waiting up to 60 s
  local n=${3:-1}
  for _ in $(seq 1 600); do
    line=$(grep "\"event\":\"$2\"" "$1" 2>/dev/null | sed -n "${n}p" || true)
    [ -n "$line" ] && { printf '%s' "$line"; return; }
    sleep 0.1
  done
  echo "no $2 #$n in $1" >&2; tail -5 "$1" >&2; return 1
}
field() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])["fields"][sys.argv[2]])' "$1" "$2"; }
admin() { "$BIN" admin "$@" --data-dir "$C"; }
source_admin() { "$BIN" admin source --data-dir "$C" --actor "$(cat "$ROOT/actor")" "$@"; }

start_worker() {
  setsid "$BIN" worker --config "$ROOT/worker.toml" --data-dir "$W" --log-format json > "$ROOT/worker.log" 2>&1 < /dev/null &
  echo $! > "$ROOT/worker.pgid"
  event "$ROOT/worker.log" link_connected >/dev/null
}
stop_group() { # stop_group <pgid file>
  [ -f "$1" ] || return 0
  kill -TERM -- "-$(cat "$1")" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 -- "-$(cat "$1")" 2>/dev/null || break; sleep 0.1; done
  rm -f "$1"
}

case "$MODE" in
setup)
  BUNDLES=$4 MODCACHE=$5
  mkdir -p "$ROOT" && cd "$ROOT"
  if [ ! -d work ]; then
    git clone -q "$BUNDLES/lockwell.bundle" work
    git -C work checkout -q -B main "$LOCKWELL"
    for sdk in node:$NODE_SDK java:$JAVA_SDK; do
      name=lockwell-sdk-${sdk%%:*} commit=${sdk#*:}
      git clone -q "$BUNDLES/$name.bundle" "tmp-$name"
      mkdir -p "work/sdk-checkouts/$name"
      git -C "tmp-$name" archive "$commit" | tar -x -C "work/sdk-checkouts/$name"
      rm -rf "tmp-$name"
    done
    # Complete the checked-in module proxy from a warm module cache of the
    # same go.sum (the proxy protocol's layout is the cache's download tree).
    (cd "$MODCACHE/cache/download" && find . -path ./sumdb -prune -o -type f -print) | while read -r f; do
      [ -e "work/.goproxy/$f" ] || install -D -m 644 "$MODCACHE/cache/download/$f" "work/.goproxy/$f"
    done
    cp "$KIT/b02-sentinel.yml" work/.sentinel.yml
    git -C work add -f sdk-checkouts .goproxy .sentinel.yml
    git "${ident[@]}" -C work commit -q -m "bench: B02 source (SDK trees vendored, .goproxy completed, pipeline)"
    mkdir -p git
    git clone -q --bare work git/lockwell
    git -C git/lockwell config uploadpack.allowAnySHA1InWant true
    git -C work remote add bench "$ROOT/git/lockwell"
  fi
  echo "bench source $(git -C work rev-parse HEAD) on $LOCKWELL"
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
    actor=$(admin status | sed -n 's/.*subject=\([^ ]*\).*/\1/p' | head -1)
    echo "$actor" > actor
    source_admin create --tenant "$tenant" --name lockwell | python3 -c 'import json,sys; print(json.load(sys.stdin)["repo"])' > repo
    admin pool create --name builders --tenant acme >/dev/null
    admin worker enroll --pool builders > enrollment
    admin token issue --user root --name b02 --scope read,run,tenant-admin,platform-admin --expires-in 7d > token
    printf 'listen = "127.0.0.1:0"\napi_listen = "127.0.0.1:0"\n' > server.toml
  fi
  ;;
start)
  cd "$ROOT"
  # The Git server, then the binding to its (new) port, then the processes.
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
    "binding": {"remote": f"https://127.0.0.1:{port}/lockwell", "allowed_refs": ["refs/heads/main"],
                "pipeline_path": ".sentinel.yml", "trust": open(f"{root}/ca.pem").read()},
    "credential": {"Https": {"username": "deploy", "secret": open(f"{root}/password").read()}},
    "forge": None}))
PY
  source_admin hook-token --repo "$(cat repo)" | tr -d '\n' > hook
  setsid "$BIN" server --config server.toml --data-dir "$C" --log-format json > server.log 2>&1 < /dev/null &
  echo $! > server.pgid
  link=$(event server.log link_listening); api=$(event server.log api_listening)
  field "$api" addr > api.addr
  printf 'controller = "%s"\ncontroller_fingerprint = "%s"\nworker_name = "b02"\nenrollment_file = "%s/enrollment"\n' \
    "$(field "$link" addr)" "$(field "$link" fingerprint)" "$ROOT" > worker.toml
  start_worker
  # The bench account reads its own tenant's runs.
  curl -fsS -X PUT -H "authorization: Bearer $(cat token)" -H 'content-type: application/json' \
    -d '{"role":"admin"}' "http://$(cat api.addr)/api/v1/tenants/acme/members/root" >/dev/null
  echo "started: git on $port, api on $(cat api.addr)"
  ;;
measure)
  CONDITION=$4 SAMPLES=$5 WARMUP=$6 OUT=$7
  cd "$ROOT"
  API="http://$(cat api.addr)/api/v1" TOKEN=$(cat token)
  settle() {
    for _ in $(seq 1 60); do
      awk '/^some/ { split($3, a, "="); exit !(a[2] < 2) }' /proc/pressure/cpu && return 0
      sleep 10
    done
    echo "the host did not settle" >&2; return 1
  }
  for i in $(seq 1 $((WARMUP + SAMPLES))); do
    settle
    if [ "$CONDITION" = cold ]; then
      stop_group worker.pgid
      rm -rf "$W/cache"
      start_worker
    fi
    if [ "$CONDITION" = small-edit ]; then
      printf '\nvar _ = %d // sentinel-bench small edit\n' "$(( $(date +%s%N) / 1000 ))" >> work/internal/s3/cors.go
      git "${ident[@]}" -C work commit -q -am "bench: small edit"
    else
      git "${ident[@]}" -C work commit -q --allow-empty -m "bench: $CONDITION"
    fi
    old=$(git -C git/lockwell rev-parse refs/heads/main)
    git -C work push -q bench HEAD:main
    new=$(git -C git/lockwell rev-parse refs/heads/main)
    pressure=$(awk '/^some/ { split($3, a, "="); print a[2] }' /proc/pressure/cpu)
    start=$(date +%s%N)
    delivery=$(curl -fsS -H "authorization: Bearer $(cat hook)" -H 'content-type: application/json' \
      -d "{\"delivery_id\":\"b02-$start\",\"ref\":\"refs/heads/main\",\"old_sha\":\"$old\",\"new_sha\":\"$new\"}" \
      "$API/intake/$(cat repo)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["delivery"])')
    run=""
    for _ in $(seq 1 600); do
      run=$(grep "\"$delivery\"" server.log | grep -o 'dispatched:run_[0-9a-f-]*' | head -1 | sed 's/dispatched://' || true)
      [ -n "$run" ] && break
      sleep 0.05
    done
    [ -n "$run" ] || { echo "no run for delivery $delivery" >&2; grep "$delivery" server.log | tail -3 >&2; exit 1; }
    dispatched=$(date +%s%N)
    # Park on the run until it finishes: each answer's version goes back as
    # `since`, so a call returns only on a visible change (or after 25 s).
    body="" since=""
    for _ in $(seq 1 400); do
      body=$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/runs/$run/wait?timeout_ms=25000${since:+&since=$since}")
      read -r finished since < <(printf '%s' "$body" | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["finished"], b["version"])')
      [ "$finished" = True ] && break
    done
    end=$(date +%s%N)
    attempt=$(printf '%s' "$body" | python3 -c 'import json,sys; r=json.load(sys.stdin)["run"]; print(r["jobs"][0]["attempt"])')
    steps=$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/attempts/$attempt/steps")
    summary=$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/attempts/$attempt/summary")
    python3 - "$CONDITION" "$([ "$i" -le "$WARMUP" ] && echo 1 || echo 0)" "$pressure" "$start" "$dispatched" "$end" "$run" "$new" "$body" "$steps" "$summary" "$("$BIN" --version)" >> "$OUT" <<'PY'
import json, sys
condition, warmup, pressure, start, dispatched, end, run, sha, body, steps, summary, version = sys.argv[1:]
job = json.loads(body)["run"]["jobs"][0]
print(json.dumps({
    "schema": "sentinel-bench/sentinel-run/1",
    "contract": {"id": "lockwell-ci", "revision": 1, "lane": "unit", "condition": condition},
    "sentinel": version, "warmup": warmup == "1", "cpu_pressure_avg60": float(pressure),
    "run": run, "sha": sha, "job_state": job.get("state"),
    "intake_to_dispatch_ns": int(dispatched) - int(start),
    "intake_to_finished_ns": int(end) - int(start),
    "steps": json.loads(steps), "caches": json.loads(summary).get("caches"),
}, separators=(",", ":")))
PY
    state=$(tail -1 "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_state"])')
    echo "$CONDITION run $i: $(( (end - start) / 1000000 )) ms, job $state (warmup=$([ "$i" -le "$WARMUP" ] && echo yes || echo no))"
    [ "$state" = passed ] || { echo "the job did not pass; stopping" >&2; exit 1; }
  done
  ;;
stop)
  cd "$ROOT"
  stop_group worker.pgid; stop_group server.pgid; stop_group git.pgid
  ;;
esac
