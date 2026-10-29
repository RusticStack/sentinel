#!/usr/bin/env python3
"""A fake `sentinel` for the B09 rehearsal (bench/test_b09_rehearsal.py). Standard library only.

It answers exactly what bench/b09-harness.py asks of the real binary, so the harness can be driven end to end on a
machine with no root, no namespaces and no containers:

  sentinel admin ...                   host-local administration over a JSON state file in the data directory; like the
                                       real one it needs the database to itself and fails while a server runs on it
  sentinel server --config C --data-dir D --log-format json
                                       an HTTP API (intake 202, run wait, attempt steps, queue, workers) over a SQLite
                                       file with the jobs/attempts columns the harness reads, and a line-oriented TCP
                                       link the workers connect to; JSON log lines the harness parses
  sentinel worker --config C --data-dir D --log-format json
                                       connects to the link, "runs" the job by sleeping, reconnects after a loss
  sentinel worker enroll ...           fleet mode: writes the worker's configuration and identity

It proves orchestration, never performance: durations are the job's sleep scaled by FAKE_TIME_SCALE, and the only
number the API reports (steps) is the controller's own monotonic measurement of that sleep. Knobs (environment):

  FAKE_TIME_SCALE=0.1   multiplier for the seconds in a pipeline's `sleep N`
  FAKE_RUN_MS=100       job time when the pipeline has no sleep
  FAKE_SLOTS=4          concurrent jobs per worker
  FAKE_429_EVERY=N      every Nth intake answers 429 with retry_after_ms
  FAKE_STATE            the shim state directory: a worker whose veth (b09n<i>) carries a 100% loss qdisc is partitioned
  FAKE_DEFECT=lose-run-on-restart   a controller restart fails the runs that were in flight (infra_failed)
  FAKE_DEFECT=never-reconnect       a worker that loses its link exits instead of reconnecting
"""
import hashlib
import http.server
import json
import os
import re
import signal
import socket
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

DEFECT = os.environ.get("FAKE_DEFECT", "")
SCALE = float(os.environ.get("FAKE_TIME_SCALE", "0.1"))
RUN_MS = int(os.environ.get("FAKE_RUN_MS", "100"))
SLOTS = int(os.environ.get("FAKE_SLOTS", "4"))
EVERY_429 = int(os.environ.get("FAKE_429_EVERY", "0"))
HEARTBEAT_DEADLINE_S = 15.0  # the real link's deadline (sentinel-link HEARTBEAT_DEADLINE)
HEARTBEAT_EVERY_S = 0.5
VALUE_FLAGS = {"--data-dir", "--actor", "--username", "--slug", "--name", "--pool", "--tenant", "--user", "--scope",
               "--expires-in", "--transport", "--priority", "--cpu-millis", "--memory-bytes", "--disk-bytes", "--repo",
               "--expected", "--config", "--log-format", "--api-url"}
TERMINAL = ("passed", "failed", "infra_failed", "canceled")


def now_ms():
    return int(time.time() * 1000)


def emit(event, **fields):
    print(json.dumps({"event": event, "fields": fields}, separators=(",", ":")), flush=True)


def parse(argv):
    """(positional words, flag values). A flag in VALUE_FLAGS takes the next word; any other --flag is a switch."""
    pos, flags, i = [], {}, 0
    while i < len(argv):
        a = argv[i]
        if a in VALUE_FLAGS and i + 1 < len(argv):
            flags[a] = argv[i + 1]
            i += 2
        elif a.startswith("--"):
            flags[a] = True
            i += 1
        else:
            pos.append(a)
            i += 1
    return pos, flags


def read_toml(path):
    with open(path) as f:
        text = f.read()
    return {m.group(1): m.group(2) for m in re.finditer(r'^([a-z_]+) = "([^"]*)"', text, re.M)}


# ------------------------------------------------------------------------------------------------ admin

def state_path(d):
    return os.path.join(d, "admin.json")


def load_state(d):
    try:
        with open(state_path(d)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"tenants": {}, "pools": {}, "tokens": [], "enrollments": {}, "repos": {}, "hooks": {}}


def save_state(d, st):
    tmp = state_path(d) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, state_path(d))


def server_running(d):
    try:
        with open(os.path.join(d, "server.pid")) as f:
            pid = int(f.read())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def tok(prefix):
    return f"{prefix}_{uuid.uuid4().hex}"


def admin(argv):
    pos, fl = parse(argv)
    d = fl.get("--data-dir")
    if not d:
        sys.exit("admin: --data-dir is required")
    if server_running(d):
        sys.exit("admin: the database is in use by a running server; stop it first (host-local administration needs it to itself)")
    os.makedirs(d, exist_ok=True)
    st = load_state(d)
    cmd = pos[:2] if pos[:1] in (["pool"], ["worker"], ["tenant"], ["token"], ["key"], ["source"]) else pos[:1]
    if cmd == ["bootstrap"]:
        if not sys.stdin.read().strip():
            sys.exit("admin bootstrap: the password is read from standard input")
        st["bootstrapped"] = True
    elif cmd == ["key", "create"]:
        st["key"] = True
    elif cmd == ["tenant", "create"]:
        tid = "tnt_" + fl["--slug"]
        st["tenants"][fl["--slug"]] = tid
        print(tid)
    elif cmd == ["status"]:
        print("subject=usr_root")
    elif cmd == ["pool", "create"]:
        st["pools"][fl["--name"]] = []
    elif cmd == ["pool", "grant"]:
        st["pools"].setdefault(fl["--pool"], []).append(fl["--tenant"])
    elif cmd == ["token", "issue"]:
        t = tok("tok")
        st["tokens"].append(t)
        print(t)
    elif cmd == ["worker", "enroll"]:
        secret = tok("enr")
        st["enrollments"][secret] = {"pool": fl.get("--pool"), "worker": None}
        print(secret)
    elif cmd == ["source", "create"]:
        repo = "repo_" + uuid.uuid4().hex[:12]
        st["repos"][repo] = {"tenant": fl["--tenant"], "bound": False}
        print(json.dumps({"repo": repo}))
    elif cmd == ["source", "bind"]:
        sys.stdin.read()  # the binding payload carries a credential: read, never stored or echoed
        st["repos"][fl["--repo"]]["bound"] = True
        print("{}")
    elif cmd == ["source", "hook-token"]:
        h = tok("hook")
        st["hooks"][h] = fl["--repo"]
        print(h)
    else:
        sys.exit(f"admin: unknown command {' '.join(pos)}")
    save_state(d, st)


# ------------------------------------------------------------------------------------------------ server

class Link:
    def __init__(self, sock, wid):
        self.sock, self.wid = sock, wid
        self.wfile = sock.makefile("wb")
        self.lock = threading.Lock()
        self.running = set()
        self.last_hb = time.monotonic()
        self.alive = True

    def send(self, obj):
        with self.lock:
            try:
                self.wfile.write((json.dumps(obj) + "\n").encode())
                self.wfile.flush()
            except OSError:
                self.alive = False

    def close(self):
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Controller:
    def __init__(self, cfg, data_dir):
        self.cfg, self.dir = cfg, data_dir
        conf = read_toml(cfg)
        self.listen = conf["listen"]
        self.api_listen = conf["api_listen"]
        self.root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(cfg))))  # ROOT/run/<name>/server.toml
        self.state = load_state(data_dir)
        self.cv = threading.Condition()
        self.version = 0
        self.links = {}
        self.intakes = 0
        self.db = sqlite3.connect(os.path.join(data_dir, "metadata.sqlite"), check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout = 5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY, run_id BLOB UNIQUE, queued_ms INTEGER, state TEXT,
                attempt TEXT, terminal_ms INTEGER, run_ms INTEGER, steps_ns INTEGER, tenant TEXT);
            CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY, job_id INTEGER, offered_ms INTEGER, acked_ms INTEGER,
                fence INTEGER, worker_id BLOB, label TEXT);""")
        stale = self.db.execute("SELECT id FROM jobs WHERE state = 'running'").fetchall()
        for (jid,) in stale:  # in flight when the previous server went away
            if DEFECT == "lose-run-on-restart":
                self.db.execute("UPDATE jobs SET state = 'infra_failed', terminal_ms = ? WHERE id = ?", (now_ms(), jid))
            else:
                self.db.execute("UPDATE jobs SET state = 'queued' WHERE id = ?", (jid,))
        with open(os.path.join(data_dir, "server.pid"), "w") as f:
            f.write(str(os.getpid()))

    def bump(self):
        with self.cv:
            self.version += 1
            self.cv.notify_all()

    # -- placement
    def dispatch_loop(self):
        while True:
            time.sleep(0.02)
            with self.cv:
                free = [lk for lk in self.links.values() if lk.alive and len(lk.running) < SLOTS]
                if not free:
                    continue
                for jid, run_ms in self.db.execute("SELECT id, run_ms FROM jobs WHERE state = 'queued' ORDER BY id").fetchall():
                    free = [lk for lk in free if len(lk.running) < SLOTS]
                    if not free:
                        break
                    lk = min(free, key=lambda x: len(x.running))
                    fence = self.db.execute("SELECT COUNT(*) FROM attempts WHERE job_id = ?", (jid,)).fetchone()[0] + 1
                    label = f"att_{uuid.uuid4().hex[:16]}"
                    self.db.execute("INSERT INTO attempts (job_id, offered_ms, fence, worker_id, label) VALUES (?, ?, ?, ?, ?)",
                                    (jid, now_ms(), fence, bytes.fromhex(lk.wid.removeprefix("wrk_")), label))
                    self.db.execute("UPDATE jobs SET state = 'running', attempt = ? WHERE id = ?", (label, jid))
                    lk.running.add(jid)
                    lk.send({"op": "run", "job": jid, "fence": fence, "ms": run_ms})
                    self.version += 1
                    self.cv.notify_all()

    def drop(self, lk):
        with self.cv:
            if self.links.get(lk.wid) is lk:
                del self.links[lk.wid]
            for jid in list(lk.running):  # the attempt is abandoned; the job is offered again with a new fence
                self.db.execute("UPDATE jobs SET state = 'queued' WHERE id = ? AND state = 'running'", (jid,))
            lk.running.clear()
            self.version += 1
            self.cv.notify_all()
        lk.close()
        emit("link_closed", worker=lk.wid)

    def watchdog(self):
        while True:
            time.sleep(0.5)
            for lk in list(self.links.values()):
                if time.monotonic() - lk.last_hb > HEARTBEAT_DEADLINE_S:
                    emit("heartbeat_deadline", worker=lk.wid)
                    self.drop(lk)

    def serve_link(self, sock):
        rf = sock.makefile("rb")
        try:
            hello = json.loads(rf.readline())
            self.state = load_state(self.dir)
            enr = self.state["enrollments"].get(hello.get("enrollment"))
            if enr is None:
                sock.sendall(b'{"ok":false}\n')
                return
            # The identity is derived from the secret, so it is the same after a controller restart.
            wid = "wrk_" + hashlib.sha256(hello["enrollment"].encode()).hexdigest()[:32]
            lk = Link(sock, wid)
            lk.send({"ok": True, "worker": wid})
            with self.cv:
                old = self.links.get(wid)
                self.links[wid] = lk
            if old:
                old.close()
            emit("worker_connected", worker=wid)
            self.bump()
            for line in rf:
                msg = json.loads(line)
                lk.last_hb = time.monotonic()
                op = msg.get("op")
                if op == "ack":
                    self.db.execute("UPDATE attempts SET acked_ms = ? WHERE job_id = ? AND fence = ?", (now_ms(), msg["job"], msg["fence"]))
                elif op == "done":
                    with self.cv:
                        row = self.db.execute("SELECT COUNT(*) FROM attempts WHERE job_id = ?", (msg["job"],)).fetchone()[0]
                        if row == msg["fence"] and msg["job"] in lk.running:  # a stale attempt's verdict is ignored
                            lk.running.discard(msg["job"])
                            off = self.db.execute("SELECT offered_ms FROM attempts WHERE job_id = ? AND fence = ?", (msg["job"], msg["fence"])).fetchone()[0]
                            self.db.execute("UPDATE jobs SET state = 'passed', terminal_ms = ?, steps_ns = ? WHERE id = ?",
                                            (now_ms(), int(msg.get("steps_ns", (now_ms() - off) * 1_000_000)), msg["job"]))
                            self.version += 1
                            self.cv.notify_all()
            self.drop(lk)
        except (OSError, ValueError, KeyError):
            pass
        finally:
            for lk in [x for x in self.links.values() if x.sock is sock]:
                self.drop(lk)

    # -- intake
    def pipeline_ms(self, sha):
        bare = os.path.join(self.root, "git", "probe")
        r = subprocess.run(["git", "--git-dir", bare, "show", f"{sha}:.sentinel.yml"], capture_output=True, text=True)
        m = re.search(r"sleep (\d+)", r.stdout) if r.returncode == 0 else None
        return int(int(m.group(1)) * 1000 * SCALE) if m else RUN_MS

    def intake(self, repo, body):
        run_ms = self.pipeline_ms(body["new_sha"])
        run_id = uuid.uuid4()
        with self.cv:
            self.db.execute("INSERT INTO jobs (run_id, queued_ms, state, run_ms, tenant) VALUES (?, ?, 'queued', ?, ?)",
                            (run_id.bytes, now_ms(), run_ms, self.state["repos"].get(repo, {}).get("tenant")))
            self.version += 1
            self.cv.notify_all()
        emit("intake", delivery=body["delivery_id"], outcome=f"dispatched:run_{run_id.hex}")
        return f"run_{run_id.hex}"

    def run_view(self, run):
        row = self.db.execute("SELECT state, attempt, terminal_ms FROM jobs WHERE run_id = ?", (bytes.fromhex(run.removeprefix("run_")),)).fetchone()
        if row is None:
            return None
        state, attempt, terminal = row
        job = {"state": state, "attempt": attempt}
        if terminal:
            job["timestamps"] = {"terminal_ms": terminal}
        return {"finished": state in TERMINAL, "version": self.version, "run": {"jobs": [job]}}


class Api(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    ctl = None

    def log_message(self, *_):
        pass

    def reply(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def bearer(self):
        h = self.headers.get("authorization", "")
        return h[7:] if h.startswith("Bearer ") else ""

    def do_POST(self):
        c = self.ctl
        n = int(self.headers.get("content-length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        m = re.fullmatch(r"/api/v1/intake/(\w+)", self.path)
        if not m:
            return self.reply(404, {})
        st = load_state(c.dir)
        if st["hooks"].get(self.bearer()) != m.group(1):
            return self.reply(401, {})
        c.intakes += 1
        if EVERY_429 and c.intakes % EVERY_429 == 0:
            return self.reply(429, {"error": {"details": {"retry_after_ms": 20}}})
        c.intake(m.group(1), body)
        self.reply(202, {"delivery": body["delivery_id"]})

    def do_GET(self):
        c = self.ctl
        if self.bearer() not in load_state(c.dir)["tokens"]:
            return self.reply(401, {})
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        m = re.fullmatch(r"/api/v1/runs/(run_\w+)/wait", u.path)
        if m:
            wait_s = min(int(q.get("timeout_ms", ["25000"])[0]) / 1000, 25)
            since = int(q["since"][0]) if "since" in q else None
            deadline = time.monotonic() + wait_s
            with c.cv:
                while True:
                    view = c.run_view(m.group(1))
                    if view is None:
                        return self.reply(404, {})
                    if view["finished"] or since is None or view["version"] != since or time.monotonic() > deadline:
                        break
                    c.cv.wait(min(0.5, max(0.01, deadline - time.monotonic())))
            return self.reply(200, view)
        m = re.fullmatch(r"/api/v1/attempts/(att_\w+)/steps", u.path)
        if m:
            row = c.db.execute("SELECT steps_ns FROM jobs WHERE attempt = ?", (m.group(1),)).fetchone()
            return self.reply(200, {"timings_ns": {"steps": row[0]} if row and row[0] else {}})
        if u.path == "/api/v1/queue":
            rows = c.db.execute("SELECT state FROM jobs WHERE state IN ('queued', 'running')").fetchall()
            return self.reply(200, {"placement_paused": False, "jobs": [{"reason": "waiting for a worker"} for (s,) in rows if s == "queued"]})
        if u.path == "/api/v1/admin/workers":
            return self.reply(200, {"workers": [{"id": w, "connected": lk.alive} for w, lk in c.links.items()]})
        self.reply(404, {})


class Threaded(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


class LinkServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def split_addr(a):
    host, _, port = a.rpartition(":")
    return host, int(port)


def server(argv):
    pos, fl = parse(argv)
    ctl = Controller(fl["--config"], fl["--data-dir"])
    Api.ctl = ctl

    class LinkHandler(socketserver.BaseRequestHandler):
        def handle(self):
            ctl.serve_link(self.request)

    links = LinkServer(split_addr(ctl.listen), LinkHandler)
    api = Threaded(split_addr(ctl.api_listen), Api)
    for fn in (links.serve_forever, api.serve_forever, ctl.dispatch_loop, ctl.watchdog):
        threading.Thread(target=fn, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    emit("link_listening", fingerprint="sha256:" + hashlib.sha256(ctl.listen.encode()).hexdigest())
    emit("api_listening", address=ctl.api_listen)
    while True:
        time.sleep(3600)


# ------------------------------------------------------------------------------------------------ worker

def partitioned(name):
    """True while the harness holds this worker's veth at 100 percent loss (the shim keeps the qdisc in FAKE_STATE)."""
    m = re.search(r"-w(\d+)$", name)
    state = os.environ.get("FAKE_STATE")
    if not (m and state):
        return False
    try:
        with open(os.path.join(state, "qdisc", f"b09n{m.group(1)}")) as f:
            return "loss 100" in f.read()
    except OSError:
        return False


def worker(argv):
    pos, fl = parse(argv)
    if pos[:1] == ["enroll"]:
        return worker_enroll(fl)
    conf = read_toml(fl["--config"])
    host, port = split_addr(conf["controller"])
    name = conf.get("worker_name", "w")
    with open(conf["enrollment_file"]) as f:
        secret = f.read().strip()
    os.makedirs(fl["--data-dir"], exist_ok=True)
    signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.settimeout(None)
            rf = sock.makefile("rb")
            sock.sendall((json.dumps({"hello": name, "enrollment": secret}) + "\n").encode())
            ack = json.loads(rf.readline())
            if not ack.get("ok"):
                sys.exit("worker: enrollment refused")
            session(sock, rf, ack["worker"], name, fl["--data-dir"])
            emit("link_lost")
        except (OSError, ValueError):
            pass
        if DEFECT == "never-reconnect":
            sys.exit(1)
        time.sleep(0.2)


def session(sock, rf, wid, name, data_dir):
    with open(os.path.join(data_dir, "worker.id"), "w") as f:
        f.write(wid)
    emit("link_connected", worker=wid)
    out = sock.makefile("wb")
    lock = threading.Lock()
    closed = threading.Event()

    def send(obj):
        while partitioned(name) and not closed.is_set():
            time.sleep(0.05)  # nothing leaves a partitioned worker; the controller's deadline decides
        with lock:
            out.write((json.dumps(obj) + "\n").encode())
            out.flush()

    def heartbeat():
        while not closed.is_set():
            try:
                send({"op": "hb"})
            except OSError:
                return
            time.sleep(HEARTBEAT_EVERY_S)

    def execute(job, fence, ms):
        try:
            send({"op": "ack", "job": job, "fence": fence})
            t0 = time.monotonic_ns()
            end = time.monotonic() + ms / 1000
            while time.monotonic() < end:
                if closed.is_set():
                    return  # the link went away: the attempt is abandoned
                time.sleep(0.02)
            send({"op": "done", "job": job, "fence": fence, "steps_ns": time.monotonic_ns() - t0})
        except OSError:
            pass

    threading.Thread(target=heartbeat, daemon=True).start()
    try:
        for line in rf:
            while partitioned(name):
                time.sleep(0.05)
            msg = json.loads(line)
            if msg.get("op") == "run":
                threading.Thread(target=execute, args=(msg["job"], msg["fence"], msg["ms"]), daemon=True).start()
    finally:
        closed.set()


def worker_enroll(fl):
    """Fleet mode: `sentinel worker enroll --api-url U --config C --data-dir D --name N --secret-stdin`."""
    secret = sys.stdin.readline().strip()
    if not secret:
        sys.exit("worker enroll: the secret is read from standard input")
    api = urllib.parse.urlparse(fl["--api-url"])
    cfg, data = fl["--config"], fl["--data-dir"]
    os.makedirs(data, exist_ok=True)
    enroll_file = os.path.join(data, "enroll")
    with open(enroll_file, "w") as f:
        f.write(secret)
    os.chmod(enroll_file, 0o600)
    # The real command learns the link address from the controller's API; the rehearsal puts the link on the port
    # just below the API's (bench/b09-harness.py: API_PORT = LINK_PORT + 1).
    with open(cfg, "w") as f:
        f.write(f'controller = "{api.hostname}:{api.port - 1}"\nworker_name = "{fl["--name"]}"\nenrollment_file = "{enroll_file}"\n')
    with open(os.path.join(data, "worker.id"), "w") as f:
        f.write("wrk_" + hashlib.sha256(secret.encode()).hexdigest()[:32])


def main():
    argv = sys.argv[1:]
    if not argv:
        sys.exit("usage: sentinel admin|server|worker ...")
    cmd, rest = argv[0], argv[1:]
    {"admin": admin, "server": server, "worker": worker}.get(cmd, lambda _: sys.exit(f"unknown command {cmd}"))(rest)


if __name__ == "__main__":
    main()
