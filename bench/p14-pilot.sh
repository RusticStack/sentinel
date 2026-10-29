#!/usr/bin/env bash
# Part 14 pilot lanes (cli, ripgrep, gson) through Sentinel; the successor of
# b02-sentinel.sh's Legacy Go pilot lane, with the same deployment shape: one
# controller, one worker and a local HTTPS Git fixture, no forge. One pilot per ROOT.
#   p14-pilot.sh prep  KIT ROOT PILOT [ISOLATION]   clone the fork at its pinned commit and commit its live pipeline;
#                      ISOLATION (or SENTINEL_BENCH_ISOLATION) container or microvm states runs_on.isolation on every job
#   p14-pilot.sh setup KIT ROOT         controller, tenant, repository, pool and worker enrollment
#   p14-pilot.sh start|stop KIT ROOT
#   p14-pilot.sh measure KIT ROOT CONDITION SAMPLES WARMUP OUT   CONDITION: cold, warm or small-edit
# Contract pilots-ci revision 4: each lane is the fork's own live pipeline (examples/pilots/, copied into
# KIT/pilots/), run on a worker with operator-granted egress (job_network = "egress"), so jobs download their
# dependencies as the GitHub jobs do and a cold sample includes those downloads. Pushes go to the fork's default branch.
# KIT also holds seed-membership.py (bench/seed-membership.py), which gives the platform admin its tenant membership through the API.
# The fixture commits use the account's own git identity (user.name and user.email in its git config).
# M08: with an ISOLATION the lane is measured under contract pilots-ci-isolation revision 1 (bench/contracts/
# pilots-ci-isolation.json), which keeps every revision-4 input and adds only that one stated field; one ROOT per
# isolation, on the same host and caps, compared by bench/m08_overhead.py. Without one the records stay revision 4.
set -euo pipefail
MODE=$1 KIT=$2 ROOT=$3
BIN="$KIT/sentinel"
C="$ROOT/controller" W="$ROOT/worker"
declare -A FORK=([cli]="${SENTINEL_PILOT_CLI_URL:-}" [ripgrep]="${SENTINEL_PILOT_RIPGREP_URL:-}" [gson]="${SENTINEL_PILOT_GSON_URL:-}")
declare -A COMMIT=([cli]=4f2cfe92e3499f8581bf39db77e0a1431fa7b55c [ripgrep]=3fce3b5bb0236da2df6d99672afb8a719642eca7 [gson]=e2292f9c9f2e07a4791827e8eea34aa7d80545d6)
# The file a small edit touches: a compiled source of the lane's main package.
declare -A BRANCH=([cli]=trunk [ripgrep]=master [gson]=main)
declare -A EDIT=([cli]=internal/ghcmd/cmd.go [ripgrep]=crates/searcher/src/lib.rs [gson]=gson/src/main/java/com/google/gson/JsonNull.java)

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
images() { sed -n 's/^    image: //p' "$KIT/pilots/$1.sentinel.yml" | sort -u; }

start_worker() {
  # B04A_PROFILE=1: the worker gets its own transient scope, so its cgroup's cpu.stat and PSI are its own.
  local scope=()
  [ -z "${B04A_PROFILE:-}" ] || scope=(systemd-run --user --scope --quiet --collect --unit "b04a-worker-$$-$RANDOM")
  setsid "${scope[@]}" "$BIN" worker --config "$ROOT/worker.toml" --data-dir "$W" --log-format json > "$ROOT/worker.log" 2>&1 < /dev/null &
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
prep)
  PILOT=$4 ISOLATION=${5:-${SENTINEL_BENCH_ISOLATION:-}}
  case "$ISOLATION" in ""|container|microvm) ;; *) echo "ISOLATION must be container or microvm" >&2; exit 2 ;; esac
  [ -n "${FORK[$PILOT]}" ] || { echo "set SENTINEL_PILOT_${PILOT^^}_URL to the private mirror URL" >&2; exit 2; }
  mkdir -p "$ROOT" && cd "$ROOT"
  echo "$PILOT" > pilot
  # An existing ROOT keeps the isolation its source commit was prepared with.
  [ ! -d work ] || [ "$(cat isolation 2>/dev/null || true)" = "$ISOLATION" ] || { echo "ROOT was prepared with isolation '$(cat isolation 2>/dev/null)'" >&2; exit 2; }
  printf '%s' "$ISOLATION" > isolation
  if [ ! -d work ]; then
    git clone -q "${FORK[$PILOT]}" work
    git -C work checkout -q -B "${BRANCH[$PILOT]}" "${COMMIT[$PILOT]}"
    cp "$KIT/pilots/$PILOT.sentinel.yml" work/.sentinel.yml
    if [ -n "$ISOLATION" ]; then # state the isolation on every job; the caps, images and steps stay as frozen
      want=$(grep -c 'runs_on: { labels: \[egress\] }' work/.sentinel.yml)
      sed -i "s/runs_on: { labels: \[egress\] }/runs_on: { labels: [egress], isolation: $ISOLATION }/" work/.sentinel.yml
      [ "$want" -gt 0 ] && [ "$(grep -c "isolation: $ISOLATION" work/.sentinel.yml)" = "$want" ] || { echo "could not state the isolation on every job of $PILOT" >&2; exit 1; }
    fi
    git -C work add -f .sentinel.yml
    git -C work commit -q -m "bench: $PILOT pilot source (live pipeline)"
    mkdir -p git
    git clone -q --bare work "git/$PILOT"
    git -C "git/$PILOT" config uploadpack.allowAnySHA1InWant true
    git -C work remote add bench "$ROOT/git/$PILOT"
  fi
  echo "bench source $(git -C work rev-parse HEAD) on $PILOT ${COMMIT[$PILOT]}"
  ;;
setup)
  cd "$ROOT"
  PILOT=$(cat pilot)
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
    source_admin create --tenant "$tenant" --name "$PILOT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["repo"])' > repo
    admin pool create --name builders --tenant acme >/dev/null
    # The longest lifetime: a queue may start this pilot hours after its setup.
    admin worker enroll --pool builders --expires-in 1d > enrollment
    admin token issue --user root --name p14 --scope read,run,tenant-admin,platform-admin --expires-in 7d > token
    printf 'listen = "127.0.0.1:0"\napi_listen = "127.0.0.1:0"\n' > server.toml
  fi
  ;;
start)
  cd "$ROOT"
  PILOT=$(cat pilot)
  setsid env FIXTURE_PASSWORD="$ROOT/password" python3 "$KIT/git_https.py" "$ROOT/git" ca.pem tls.key > git.port 2>/dev/null < /dev/null &
  echo $! > git.pgid
  for _ in $(seq 1 100); do [ -s git.port ] && break; sleep 0.1; done
  port=$(head -1 git.port)
  printf '["https://127.0.0.1:%s"]' "$port" > "$C/source-destinations.json"
  expected=$( (source_admin show --repo "$(cat repo)" 2>/dev/null || echo '{}') | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version") or 0)')
  python3 - "$port" "$ROOT" "$PILOT" "${BRANCH[$PILOT]}" <<'PY' | source_admin bind --repo "$(cat repo)" --expected "$expected" >/dev/null
import json, sys
port, root, pilot, branch = sys.argv[1:]
print(json.dumps({
    "binding": {"remote": f"https://127.0.0.1:{port}/{pilot}", "allowed_refs": [f"refs/heads/{branch}"],
                "pipeline_path": ".sentinel.yml", "trust": open(f"{root}/ca.pem").read()},
    "credential": {"Https": {"username": "deploy", "secret": open(f"{root}/password").read()}},
    "forge": None}))
PY
  source_admin hook-token --repo "$(cat repo)" | tr -d '\n' > hook
  setsid "$BIN" server --config server.toml --data-dir "$C" --log-format json > server.log 2>&1 < /dev/null &
  echo $! > server.pgid
  link=$(event server.log link_listening); api=$(event server.log api_listening)
  field "$api" addr > api.addr
  # A platform admin has no ambient tenant access and no host-local command adds it to one; the audited override
  # (session, step-up, reason) is the supported path, so the membership is made over the running API.
  printf 'correct horse battery staple' | python3 "$KIT/seed-membership.py" --api "http://$(cat api.addr)/api/v1" \
    --username root --tenant acme --reason "benchmark seed"
  printf 'controller = "%s"\ncontroller_fingerprint = "%s"\nworker_name = "p14"\nenrollment_file = "%s/enrollment"\njob_network = "egress"\n' \
    "$(field "$link" addr)" "$(field "$link" fingerprint)" "$ROOT" > worker.toml
  start_worker
  echo "started: git on $port, api on $(cat api.addr)"
  ;;
measure)
  CONDITION=$4 SAMPLES=$5 WARMUP=$6 OUT=$7
  : "${SENTINEL_SRC:?set SENTINEL_SRC to the checkout the sentinel binary was built from}"
  git -C "$SENTINEL_SRC" rev-parse HEAD >/dev/null || { echo "cannot read the commit of $SENTINEL_SRC" >&2; exit 1; }
  cd "$ROOT"
  PILOT=$(cat pilot)
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
      stamp=$(( $(date +%s%N) / 1000 ))
      case "$PILOT" in
      cli) printf '\nvar _ = %d // sentinel-bench small edit\n' "$stamp" >> "work/${EDIT[$PILOT]}" ;;
      *) printf '\n// sentinel-bench small edit %d\n' "$stamp" >> "work/${EDIT[$PILOT]}" ;;
      esac
      git -C work commit -q -am "bench: small edit"
    else
      git -C work commit -q --allow-empty -m "bench: $CONDITION"
    fi
    ref=refs/heads/${BRANCH[$PILOT]}
    old=$(git -C "git/$PILOT" rev-parse "$ref")
    git -C work push -q bench "HEAD:$ref"
    new=$(git -C "git/$PILOT" rev-parse "$ref")
    pressure=$(awk '/^some/ { split($3, a, "="); print a[2] }' /proc/pressure/cpu)
    raw=""
    if [ -n "${B04A_PROFILE:-}" ]; then
      raw="$ROOT/b04a.raw"
      rm -f "$raw"
      python3 "$KIT/b04a_profile.py" sample --out "$raw" --worker-pid "$(cat worker.pgid)" --data-dir "$W" &
      sampler=$!
      sleep 0.5
    fi
    start=$(date +%s%N)
    delivery=$(curl -fsS -H "authorization: Bearer $(cat hook)" -H 'content-type: application/json' \
      -d "{\"delivery_id\":\"p14-$start\",\"ref\":\"$ref\",\"old_sha\":\"$old\",\"new_sha\":\"$new\"}" \
      "$API/intake/$(cat repo)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["delivery"])')
    run=""
    for _ in $(seq 1 600); do
      run=$(grep "\"$delivery\"" server.log | grep -o 'dispatched:run_[0-9a-f-]*' | head -1 | sed 's/dispatched://' || true)
      [ -n "$run" ] && break
      sleep 0.05
    done
    [ -n "$run" ] || { echo "no run for delivery $delivery" >&2; grep "$delivery" server.log | tail -3 >&2; exit 1; }
    dispatched=$(date +%s%N)
    # Long-poll: passing the last version as since makes each call return only on a visible change.
    body="" since=""
    for _ in $(seq 1 1000); do
      body=$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/runs/$run/wait?timeout_ms=25000${since:+&since=$since}")
      read -r finished since < <(printf '%s' "$body" | python3 -c 'import json,sys; b=json.load(sys.stdin); print(b["finished"], b["version"])')
      [ "$finished" = True ] && break
    done
    end=$(date +%s%N)
    if [ -n "$raw" ]; then
      sleep 0.5
      kill -TERM "$sampler"
      wait "$sampler" || true
    fi
    steps="{" summary="{" sep=""
    for attempt in $(printf '%s' "$body" | python3 -c 'import json,sys; print(" ".join(j["attempt"] for j in json.load(sys.stdin)["run"]["jobs"] if j.get("attempt")))'); do
      steps="$steps$sep\"$attempt\":$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/attempts/$attempt/steps")"
      summary="$summary$sep\"$attempt\":$(curl -fsS -H "authorization: Bearer $TOKEN" "$API/attempts/$attempt/summary")"
      sep=,
    done
    steps="$steps}" summary="$summary}"
    python3 - "$PILOT" "$CONDITION" "$([ "$i" -le "$WARMUP" ] && echo 1 || echo 0)" "$pressure" "$start" "$dispatched" "$end" "$run" "$new" "$body" "$steps" "$summary" "$("$BIN" --version)" "$SENTINEL_SRC" "$BIN" "$raw" "$KIT" "$(cat isolation 2>/dev/null || true)" >> "$OUT" <<'PY'
import hashlib, json, os, subprocess, sys
pilot, condition, warmup, pressure, start, dispatched, end, run, sha, body, steps, summary, version, src, binary, raw, kit, isolation = sys.argv[1:]
jobs = json.loads(body)["run"]["jobs"]
steps, summary = json.loads(steps), json.loads(summary)
def git(*a):
    r = subprocess.run(["git", "-C", src, *a], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None
def first(path):
    try:
        return open(path).read().strip()
    except OSError:
        return None
def field(path, key):
    try:
        for line in open(path):
            k, _, v = line.partition(":")
            if k.strip() == key:
                return v.strip()
    except OSError:
        pass
mem = field("/proc/meminfo", "MemTotal")
host = {"hostname": os.environ.get("SENTINEL_BENCH_HOST_LABEL") or None,
        "kernel": first("/proc/sys/kernel/osrelease"),
        "cpu_model": field("/proc/cpuinfo", "model name"), "cpus_online": os.cpu_count(),
        "mem_total_kib": int(mem.split()[0]) if mem else None,
        "cpu_governor": first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "loadavg": first("/proc/loadavg")}
status = git("status", "--porcelain", "--untracked-files=no")
profile = None
if raw and os.path.exists(raw):
    sys.path.insert(0, kit)
    import b04a_profile
    lead = next((j for j in jobs if j.get("attempt")), {})
    profile = b04a_profile.reduce_run(json.load(open(raw)), lead.get("timestamps") or {},
                                      steps.get(lead.get("attempt"), {}).get("timings_ns") or {})
    os.remove(raw)
print(json.dumps({
    **({"profile": profile} if profile else {}),
    "schema": "sentinel-bench/pilot-run/1",
    "build": {"commit": git("rev-parse", "HEAD"), "dirty": None if status is None else bool(status),
              "binary_sha256": hashlib.sha256(open(binary, "rb").read()).hexdigest()},
    "host": {k: v for k, v in host.items() if v is not None},
    "contract": {"id": "pilots-ci-isolation", "revision": 1, "lane": pilot, "condition": condition, "isolation": isolation}
                if isolation else {"id": "pilots-ci", "revision": 4, "lane": pilot, "condition": condition},
    "sentinel": version, "warmup": warmup == "1", "cpu_pressure_avg60": float(pressure),
    "run": run, "sha": sha,
    "job_state": "passed" if jobs and all(j.get("state") == "passed" for j in jobs) else "failed",
    "jobs": [{k: j.get(k) for k in ("name", "state", "attempt", "timestamps")} for j in jobs],
    "intake_to_dispatch_ns": int(dispatched) - int(start),
    "intake_to_finished_ns": int(end) - int(start),
    "steps": steps, "caches": {a: s.get("caches") for a, s in summary.items()},
}, separators=(",", ":")))
PY
    state=$(tail -1 "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["job_state"])')
    echo "$PILOT $CONDITION run $i: $(( (end - start) / 1000000 )) ms, $state (warmup=$([ "$i" -le "$WARMUP" ] && echo yes || echo no))"
    [ "$state" = passed ] || { echo "a job did not pass; stopping" >&2; exit 1; }
  done
  ;;
stop)
  cd "$ROOT"
  stop_group worker.pgid; stop_group server.pgid; stop_group git.pgid
  ;;
*) echo "usage: $0 prep|setup|start|measure|stop KIT ROOT ..." >&2; exit 2 ;;
esac
