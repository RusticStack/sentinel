#!/usr/bin/env bash
# F07 probe: can a pinned Tailcat helper run unattended and forward one TCP port?
# Both ends run on this host; NAT traversal is therefore trivial and only the
# unattended lifecycle, key persistence, allow-list and tunnel latency are probed.
set -uo pipefail
TC="${TC:-/root/tailcat/tailcat}"
export HOME="${PROBE_HOME:-/root/f07-tailcat}"; rm -rf "$HOME"; mkdir -p "$HOME"
OUT="$HOME/out"; mkdir -p "$OUT"
cd "$HOME"
result() { printf '%s %s: %s\n' "$1" "$2" "$3"; }
echo "tailcat: $($TC --version 2>&1 | head -1) sha256=$(sha256sum "$TC" | cut -c1-16)"

# Local TCP echo service the server side will expose.
python3 - <<'PY' >"$OUT/echo.log" 2>&1 &
import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("127.0.0.1",17777)); s.listen(16)
def h(c):
    with c:
        while True:
            d=c.recv(65536)
            if not d: break
            c.sendall(d)
while True:
    c,_=s.accept(); threading.Thread(target=h,args=(c,),daemon=True).start()
PY
ECHO_PID=$!
sleep 0.5

# 1. Persistent keys on both sides, no prompts, no account.
$TC genkey --key=default --fixed-region >"$OUT/genkey-server.log" 2>&1; rc1=$?
$TC genkey --client --key=client-default >"$OUT/genkey-client.log" 2>&1; rc2=$?
client_key=$(grep -o 'nodekey:[0-9a-f]*' "$OUT/genkey-client.log" | head -1)
if [[ $rc1 -eq 0 && $rc2 -eq 0 && -n "$client_key" ]]; then result PASS genkey "server+client keys created unattended; client=$client_key"; else result FAIL genkey "rc=$rc1/$rc2 $(head -c 200 "$OUT/genkey-server.log" "$OUT/genkey-client.log" | tr '\n' ' ')"; fi

start_server() {
  $TC serve --allow="$client_key" 17777 >"$OUT/serve-$1.log" 2>&1 &
  echo $! >"$OUT/server.pid"
  for i in $(seq 1 60); do addr=$(grep -oE 'listening.*: tc[A-Za-z0-9_-]{20,}' "$OUT/serve-$1.log" | head -1 | sed 's/.*: //'); [[ -n "$addr" ]] && break; sleep 0.5; done
  echo "$addr"
}

# 2. Server starts unattended and prints an address (bootstrap via DERP).
t0=$(date +%s%N); ADDR=$(start_server 1); t1=$(date +%s%N); SERVER_PID=$(cat "$OUT/server.pid")
if [[ -n "$ADDR" ]]; then result PASS serve_start "address obtained in $(( (t1-t0)/1000000 )) ms: $(head -c 12 <<<"$ADDR")... $(grep -i 'relay' "$OUT/serve-1.log" | head -1)"; else result FAIL serve_start "$(head -c 300 "$OUT/serve-1.log" | tr '\n' ' ')"; kill $ECHO_PID; exit 1; fi

# 3. Ping: connectivity and direct vs DERP path.
$TC ping --until-direct --timeout 20s "$ADDR" >"$OUT/ping.log" 2>&1; rc=$?
result "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" ping_direct "rc=$rc $(tail -2 "$OUT/ping.log" | tr '\n' ' ')"

# 4. Forward a local port through the tunnel and measure round trips.
$TC forward "$ADDR" 18777:17777 >"$OUT/forward.log" 2>&1 &
FWD_PID=$!
for i in $(seq 1 40); do (echo >/dev/tcp/127.0.0.1/18777) 2>/dev/null && break; sleep 0.25; done
python3 - <<'PY' | tee "$OUT/rtt.txt"
import socket,time,statistics
def rtts(port,n=50,size=64):
    s=socket.create_connection(("127.0.0.1",port),timeout=10); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    out=[]; payload=b"x"*size
    for _ in range(n):
        t=time.perf_counter_ns(); s.sendall(payload); got=0
        while got<size: got+=len(s.recv(65536))
        out.append(time.perf_counter_ns()-t)
    s.close(); return out
def bw(port,total=64<<20,chunk=1<<20):
    s=socket.create_connection(("127.0.0.1",port),timeout=30); data=b"y"*chunk; t=time.perf_counter(); sent=0
    while sent<total:
        s.sendall(data); got=0
        while got<chunk: got+=len(s.recv(1<<20))
        sent+=chunk
    s.close(); return total/(time.perf_counter()-t)/1e6
for name,port in (("direct_loopback",17777),("via_tailcat",18777)):
    r=rtts(port); r.sort()
    print(f"{name}: rtt_us median={statistics.median(r)/1000:.0f} p95={r[int(len(r)*0.95)-1]/1000:.0f} max={r[-1]/1000:.0f} echo_MBps={bw(port):.0f}")
PY

# 5. Allow-list: a second client identity must be rejected.
$TC genkey --client --key=other >"$OUT/genkey-other.log" 2>&1
timeout 20 $TC --key=other "$ADDR" 17777 </dev/null >"$OUT/other.log" 2>&1; rc=$?
if [[ $rc -ne 0 ]]; then result PASS allow_list "unlisted client rejected rc=$rc: $(tail -c 160 "$OUT/other.log" | tr '\n' ' ')"; else result FAIL allow_list "unlisted client connected"; fi

# 6. Restart: address must be identical with the persisted key; forward must reconnect.
kill $SERVER_PID; wait $SERVER_PID 2>/dev/null
ADDR2=$(start_server 2); SERVER_PID=$(cat "$OUT/server.pid")
if [[ "$ADDR2" == "$ADDR" ]]; then result PASS stable_address "same address after server restart"; else result FAIL stable_address "changed: $ADDR -> $ADDR2"; fi
sleep 2
ok=0; for i in $(seq 1 30); do if python3 -c "
import socket;s=socket.create_connection(('127.0.0.1',18777),timeout=3);s.sendall(b'z');assert s.recv(1)==b'z'" 2>/dev/null; then ok=1; t_re=$i; break; fi; sleep 1; done
if [[ $ok -eq 1 ]]; then result PASS forward_reconnect "existing forward usable again after ~$t_re s"; else result FAIL forward_reconnect "forward did not recover within 30 s"; fi

kill $FWD_PID $SERVER_PID $ECHO_PID 2>/dev/null; wait 2>/dev/null
echo "logs in $OUT"
