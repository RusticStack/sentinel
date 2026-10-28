#!/usr/bin/env python3
"""B09: reliability/performance scenarios on a real controller and real workers.

    python3 bench/b09-harness.py list
    python3 bench/b09-harness.py run --kit KIT --root ROOT --out OUT.jsonl \
        --source CHECKOUT --scenarios ID[,ID...] [--repeats 5] [--runs 20]
    python3 bench/b09-harness.py cleanup --root ROOT

Run as root on the verification VPS. KIT holds the release `sentinel` binary;
CHECKOUT is the clone it was built from (its commit and dirty flag, and the
binary's sha256, go into every record). Every worker is a separate process
with its own identity, data directory and network namespace, attached to one
private bridge; all of them, the controller and the benchmark's Git fixture
share ONE host, so N workers measure the control plane's fan-out, not N
machines' capacity. Controller, workers and Git run as the bench account
(rootless Podman, storage in its home).

Faults: link shaping is `tc netem` on the worker veth pairs (never on a host
interface); slow and full disks are loop-mounted ext4 images, slow ones behind
dm-delay; restarts and partitions act on this run's own processes by PID. All
state is registered for removal and removed on exit, on a signal and by the
`cleanup` command, which is idempotent and touches only b09-named objects.

One record per repeat (perf) or per scenario (reliability) is appended to OUT
as a JSON line, schema `sentinel-bench/b09/1`. Durations are monotonic
nanoseconds measured by this driver; store stamps are wall-clock milliseconds
and named `_ms`. See docs/benchmarking.md and docs/resilience.md.
"""
import argparse
import atexit
import concurrent.futures
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

SCHEMA = "sentinel-bench/b09/1"
BENCH_USER = "benchmark"
IMAGE = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
BRIDGE, SUBNET, BRIDGE_ADDR = "b09br", "10.99.0", "10.99.0.1"
LINK_PORT, API_PORT, GIT_PORT = 47443, 47480, 47490
LOCK = "/srv/sentinel/runs/p14.lock"
# The harness runs git as root against repositories it hands to the bench user; git refuses those as dubious ownership.
# Local transport strips GIT_CONFIG_* before it starts receive-pack, so pushes carry the setting themselves.
os.environ.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="safe.directory", GIT_CONFIG_VALUE_0="*")
PUSH = ["push", "-q", "--receive-pack=git -c safe.directory=* receive-pack"]
SETTLE_BELOW = 5.0  # percent of CPU pressure ("some", avg60), the contract's start limit
IDENT = ["-c", "user.name=sentinel-bench", "-c", "user.email=bench@sentinel.invalid"]
ZERO = "0" * 40

# kind perf: repeated samples, comparable by the gate. kind reliability: asserted outcomes.
LINKS = {
    "direct": {},
    "relay-emulated": {"delay_ms": 30, "jitter_ms": 5, "rate_mbit": 50},
    "loss-1pct": {"loss_pct": 1.0},
    "loss-5pct": {"loss_pct": 5.0},
}
SCENARIOS = {}
for n in (1, 3, 10):
    SCENARIOS[f"w{n}-steady"] = dict(kind="perf", workers=n, mode="steady")
    SCENARIOS[f"w{n}-burst"] = dict(kind="perf", workers=n, mode="burst")
for name in ("relay-emulated", "loss-1pct", "loss-5pct"):
    SCENARIOS[f"link-{name}-steady"] = dict(kind="perf", workers=1, mode="steady", link=name)
    SCENARIOS[f"link-{name}-burst"] = dict(kind="perf", workers=1, mode="burst", link=name)
SCENARIOS["disk-slow-worker-steady"] = dict(kind="perf", workers=1, mode="steady", disk={"worker": "slow"})
SCENARIOS["disk-slow-controller-steady"] = dict(kind="perf", workers=1, mode="steady", disk={"controller": "slow"})
SCENARIOS["disk-full-worker"] = dict(kind="reliability", workers=1, disk={"worker": "small"})
SCENARIOS["disk-full-controller"] = dict(kind="reliability", workers=1, disk={"controller": "small"})
# The link's heartbeat deadline is 15 s (sentinel-link HEARTBEAT_DEADLINE) and a lease 30 s: an 8 s partition must be
# ridden out on the same link; a 20 s one must drop it, and the worker must come back by itself inside the lease.
SCENARIOS["partition"] = dict(kind="reliability", workers=1, partition_s=8)
SCENARIOS["partition-long"] = dict(kind="reliability", workers=1, partition_s=20)
SCENARIOS["restart-controller-kill"] = dict(kind="reliability", workers=3)
SCENARIOS["restart-controller-term"] = dict(kind="reliability", workers=3)
SCENARIOS["restart-worker-kill"] = dict(kind="reliability", workers=3)
SCENARIOS["noisy-tenant"] = dict(kind="reliability", workers=3, tenants=["acme", "noisy"])
SCENARIOS["noisy-tenant-control"] = dict(kind="reliability", workers=3, tenants=["acme", "noisy"])
SCENARIOS["tailcat-relay"] = dict(kind="blocked", workers=1)


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def sh(cmd, check=True, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[:6]} failed ({r.returncode}): {r.stderr.strip()[:400]}")
    return r


# ---------------------------------------------------------------- cleanup registry

_CLEAN = []
_CLEANING = False


def on_exit(fn):
    _CLEAN.append(fn)


def run_cleanups():
    global _CLEANING
    if _CLEANING:
        return
    _CLEANING = True
    while _CLEAN:
        fn = _CLEAN.pop()
        try:
            fn()
        except Exception as e:  # cleanup must continue past one failure
            log("cleanup step failed:", repr(e)[:200])
    _CLEANING = False


def install_traps():
    atexit.register(run_cleanups)
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, lambda *_: sys.exit(130))


def hard_cleanup(root):
    """Remove every b09 object, whether this process made it or a crashed one did."""
    # processes recorded by pgid files
    pids = os.path.join(root, "pids")
    if os.path.isdir(pids):
        for f in os.listdir(pids):
            try:
                pg = int(open(os.path.join(pids, f)).read())
                os.killpg(pg, signal.SIGKILL)
            except (OSError, ValueError):
                pass
            os.unlink(os.path.join(pids, f))
    for line in sh(["ip", "netns", "list"], check=False).stdout.splitlines():
        name = line.split()[0] if line.split() else ""
        if name.startswith("b09w"):
            sh(["ip", "netns", "delete", name], check=False)
    for line in sh(["ip", "-o", "link"], check=False).stdout.splitlines():
        m = re.match(r"\d+: (b09[a-z]+\d*)[@:]", line)
        if m:
            sh(["ip", "link", "delete", m.group(1)], check=False)
    mounts = open("/proc/mounts").read().splitlines()
    for m in mounts:
        dev, mp = m.split()[:2]
        if mp.startswith(os.path.join(root, "mnt")):
            sh(["umount", "-l", mp], check=False)
    for line in sh(["dmsetup", "ls"], check=False).stdout.splitlines():
        if line.startswith("b09-"):
            sh(["dmsetup", "remove", "--retry", line.split()[0]], check=False)
    for line in sh(["losetup", "-a"], check=False).stdout.splitlines():
        if f"{root}/img/" in line:
            sh(["losetup", "-d", line.split(":")[0]], check=False)
    shutil.rmtree(os.path.join(root, "img"), ignore_errors=True)


# ---------------------------------------------------------------- host state

def read_first(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def field(path, key):
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.partition(":")
                if k.strip() == key:
                    return v.strip()
    except OSError:
        pass
    return None


def psi(kind):
    try:
        for line in open(f"/proc/pressure/{kind}"):
            parts = line.split()
            kv = dict(p.split("=") for p in parts[1:])
            if parts[0] == "some":
                return {"avg10": float(kv["avg10"]), "avg60": float(kv["avg60"]), "total_us": int(kv["total"])}
    except OSError:
        return None


def steal_ns():
    try:
        v = open("/proc/stat").readline().split()
        return int(v[8]) * 10_000_000  # USER_HZ ticks to ns
    except (OSError, IndexError, ValueError):
        return None


def conditions():
    c = {"load_avg": [float(x) for x in open("/proc/loadavg").read().split()[:3]],
         "cpu_some": psi("cpu"), "io_some": psi("io"), "memory_some": psi("memory"), "steal_ns": steal_ns()}
    return {k: v for k, v in c.items() if v is not None}


def settle(limit_s=900):
    deadline = time.monotonic() + limit_s
    while time.monotonic() < deadline:
        p = psi("cpu")
        if p is None or p["avg60"] < SETTLE_BELOW:
            return
        time.sleep(5)
    raise RuntimeError(f"host did not settle below {SETTLE_BELOW}% CPU pressure in {limit_s}s")


def stamp(source, binary):
    def git(*args):
        r = subprocess.run(["git", "-C", source, *args], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None
    commit = git("rev-parse", "HEAD")
    if commit is None:
        raise SystemExit(f"cannot read the source commit of {source}; no record is written without it")
    status = git("status", "--porcelain", "--untracked-files=no")
    with open(binary, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    mem = field("/proc/meminfo", "MemTotal")
    host = {"hostname": os.environ.get("SENTINEL_BENCH_HOST_LABEL") or None,
            "kernel": read_first("/proc/sys/kernel/osrelease"),
            "cpu_model": field("/proc/cpuinfo", "model name"), "cpus_online": os.cpu_count(),
            "mem_total_kib": int(mem.split()[0]) if mem else None,
            "cpu_governor": read_first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            "shared_host": "all workers, the controller and the Git fixture run on this one host"}
    return {"build": {"commit": commit, "dirty": None if status is None else bool(status), "binary_sha256": digest},
            "host": {k: v for k, v in host.items() if v is not None}}


def percentile(sorted_values, q):
    """Nearest-rank, as the benchmark runner does."""
    n = len(sorted_values)
    return sorted_values[min(n - 1, max(0, math.ceil(q * n) - 1))]


def distribution(values):
    if not values:
        return {"n": 0}
    v = sorted(values)
    return {"n": len(v), "min": v[0], "p50": percentile(v, 0.50), "p95": percentile(v, 0.95),
            "p99": percentile(v, 0.99), "max": v[-1], "p95_is_max": len(v) < 20}


# ---------------------------------------------------------------- network and disks

class Net:
    def __init__(self, n):
        self.n = n
        sh(["ip", "link", "add", BRIDGE, "type", "bridge"])
        on_exit(lambda: sh(["ip", "link", "delete", BRIDGE], check=False))
        sh(["ip", "addr", "add", f"{BRIDGE_ADDR}/24", "dev", BRIDGE])
        sh(["ip", "link", "set", BRIDGE, "up"])
        for i in range(1, n + 1):
            ns = self.ns(i)
            sh(["ip", "netns", "add", ns])
            on_exit(lambda ns=ns: sh(["ip", "netns", "delete", ns], check=False))
            sh(["ip", "link", "add", f"b09h{i}", "type", "veth", "peer", "name", f"b09n{i}"])
            on_exit(lambda i=i: sh(["ip", "link", "delete", f"b09h{i}"], check=False))
            sh(["ip", "link", "set", f"b09n{i}", "netns", ns])
            sh(["ip", "link", "set", f"b09h{i}", "master", BRIDGE])
            sh(["ip", "link", "set", f"b09h{i}", "up"])
            for cmd in (["ip", "addr", "add", f"{self.addr(i)}/24", "dev", f"b09n{i}"],
                        ["ip", "link", "set", f"b09n{i}", "up"], ["ip", "link", "set", "lo", "up"]):
                sh(["ip", "netns", "exec", ns, *cmd])

    @staticmethod
    def ns(i):
        return f"b09w{i}"

    @staticmethod
    def addr(i):
        return f"{SUBNET}.{10 + i}"

    def devices(self, i):
        return [(["ip", "netns", "exec", self.ns(i)], f"b09n{i}"), ([], f"b09h{i}")]

    def shape(self, i, spec):
        """netem on both directions of worker i's link: its veth end and the bridge-side end."""
        for prefix, dev in self.devices(i):
            if not spec:
                sh([*prefix, "tc", "qdisc", "del", "dev", dev, "root"], check=False)
                continue
            args = [*prefix, "tc", "qdisc", "replace", "dev", dev, "root", "netem"]
            if spec.get("delay_ms"):
                args += ["delay", f"{spec['delay_ms']}ms", f"{spec.get('jitter_ms', 0)}ms"]
            if spec.get("loss_pct"):
                args += ["loss", f"{spec['loss_pct']}%"]
            if spec.get("rate_mbit"):
                args += ["rate", f"{spec['rate_mbit']}mbit"]
            sh(args)

    def shape_all(self, spec):
        for i in range(1, self.n + 1):
            self.shape(i, spec)

    def partition(self, i, down):
        self.shape(i, {"loss_pct": 100} if down else None)


def make_fs(root, name, size_mb, slow_ms=None):
    """A loop-mounted ext4 image owned by the bench account, optionally behind dm-delay."""
    img_dir, mp = os.path.join(root, "img"), os.path.join(root, "mnt", name)
    os.makedirs(img_dir, exist_ok=True)
    os.makedirs(mp, exist_ok=True)
    img = os.path.join(img_dir, f"{name}.img")
    sh(["truncate", "-s", f"{size_mb}M", img])
    dev = sh(["losetup", "-f", "--show", img]).stdout.strip()
    on_exit(lambda: (sh(["losetup", "-d", dev], check=False), os.path.exists(img) and os.unlink(img)))
    if slow_ms:
        sectors = sh(["blockdev", "--getsz", dev]).stdout.strip()
        sh(["modprobe", "dm-delay"], check=False)
        dm = f"b09-{name}"
        sh(["dmsetup", "create", dm, "--table", f"0 {sectors} delay {dev} 0 {slow_ms}"])
        on_exit(lambda: sh(["dmsetup", "remove", "--retry", dm], check=False))
        dev = f"/dev/mapper/{dm}"
    sh(["mkfs.ext4", "-q", "-F", dev])
    sh(["mount", dev, mp])
    on_exit(lambda: sh(["umount", mp], check=False))
    sh(["chown", f"{BENCH_USER}:{BENCH_USER}", mp])
    return mp


# ---------------------------------------------------------------- deployment

def bench_env():
    uid = int(sh(["id", "-u", BENCH_USER]).stdout)
    return {"HOME": f"/home/{BENCH_USER}", "XDG_RUNTIME_DIR": f"/run/user/{uid}",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{uid}/bus",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}


MEMBERSHIPS = """
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=20)
user = c.execute("SELECT id FROM users WHERE super_admin = 1").fetchone()[0]
for slug in sys.argv[2:]:
    tenant = c.execute("SELECT id FROM tenants WHERE slug = ?", (slug,)).fetchone()[0]
    c.execute("INSERT OR REPLACE INTO memberships(tenant_id, user_id, role) VALUES (?, ?, 3)", (tenant, user))
c.commit()
"""


_RETRIES = threading.local()


def retry_after_ms(raw):
    """The retry_after_ms detail anywhere in a 429's JSON body, else 1000."""
    def find(v):
        if isinstance(v, dict):
            if isinstance(v.get("retry_after_ms"), int):
                return v["retry_after_ms"]
            v = list(v.values())
        if isinstance(v, list):
            for x in v:
                found = find(x)
                if found is not None:
                    return found
        return None
    try:
        return find(json.loads(raw)) or 1000
    except ValueError:
        return 1000


def as_bench(argv, extra_env=None):
    env = dict(bench_env(), **(extra_env or {}))
    return ["runuser", "-u", BENCH_USER, "--", "env", *[f"{k}={v}" for k, v in env.items()], *argv]


class Proc:
    """A process group started for this run and recorded so cleanup can kill it by pgid."""

    def __init__(self, root, name, argv, logfile, netns=None, extra_env=None):
        self.root, self.name, self.logfile = root, name, logfile
        self.argv = (["nsenter", f"--net=/run/netns/{netns}", "--"] if netns else []) + as_bench(argv, extra_env)
        self.p = None

    def start(self):
        self.p = subprocess.Popen(["nice", "-n", "10", *self.argv], stdout=open(self.logfile, "ab"),
                                  stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
        os.makedirs(os.path.join(self.root, "pids"), exist_ok=True)
        with open(os.path.join(self.root, "pids", self.name), "w") as f:
            f.write(str(self.p.pid))
        on_exit(self.kill)
        return self

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def send(self, sig):
        if self.p and self.p.poll() is None:
            os.killpg(self.p.pid, sig)

    def stop(self, sig=signal.SIGTERM, wait=15):
        self.send(sig)
        try:
            self.p.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            os.killpg(self.p.pid, signal.SIGKILL)
            self.p.wait()

    def kill(self):
        if self.p is not None:
            try:
                os.killpg(self.p.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass


def log_events(path, name, offset=0):
    """Records named `name` in a JSON-lines log from byte `offset`, with the offset after them."""
    out = []
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read()
    except OSError:
        return out, offset
    end = offset + len(data)
    for line in data.split(b"\n"):
        if f'"event":"{name}"'.encode() in line:
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out, end


def wait_event(path, name, timeout=60, offset=0, count=1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ev, _ = log_events(path, name, offset)
        if len(ev) >= count:
            return ev
        time.sleep(0.05)
    raise RuntimeError(f"no {name} x{count} in {path} within {timeout}s")


class DeliveryTail(threading.Thread):
    """Follows the controller log and maps each intake delivery to the run it dispatched."""

    def __init__(self, path):
        super().__init__(daemon=True)
        self.path, self.runs, self.cond, self.stop_flag = path, {}, threading.Condition(), False
        self.offset = 0

    def run(self):
        buf = b""
        while not self.stop_flag:
            try:
                with open(self.path, "rb") as f:
                    f.seek(self.offset)
                    data = f.read()
            except OSError:
                data = b""
            if data:
                self.offset += len(data)
                buf += data
                *lines, buf = buf.split(b"\n")
                with self.cond:
                    for line in lines:
                        if b"dispatched:run_" not in line:
                            continue
                        try:
                            f = json.loads(line)["fields"]
                            self.runs[f["delivery"]] = f["outcome"].split("dispatched:", 1)[1]
                        except (ValueError, KeyError, IndexError):
                            pass
                    self.cond.notify_all()
            time.sleep(0.004)

    def wait(self, delivery, timeout=120):
        deadline = time.monotonic() + timeout
        with self.cond:
            while delivery not in self.runs:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise RuntimeError(f"no run for delivery {delivery}")
                self.cond.wait(min(left, 0.5))
            return self.runs[delivery]


def pipeline_yaml(step, cpu="0.25", memory="128MiB", disk="1GiB", timeout="5m", image=IMAGE):
    # disk: the schema's minimum. Undeclared, a job reserves the 10 GiB default, which no scenario's loop disk offers.
    return (f"schema: 1\non: [push]\njobs:\n  probe:\n    image: {image}\n"
            f"    resources: {{ cpu: \"{cpu}\", memory: {memory}, disk: {disk} }}\n    timeout: {timeout}\n"
            f"    steps:\n      - id: s\n        run: |\n" + "".join(f"          {l}\n" for l in step.splitlines()))


class Deploy:
    def __init__(self, a, name, spec):
        self.a, self.name, self.spec = a, name, spec
        self.root = a.root
        self.run_dir = os.path.join(a.root, "run", name)
        self.bin = os.path.join(a.kit, "sentinel")
        self.tenants = spec.get("tenants", ["acme"])
        self.n = spec.get("workers", 1)
        self.api = f"http://127.0.0.1:{API_PORT}/api/v1"
        self.workers = []
        self.mounts = {}
        self.tail = None

    # -- provisioning
    def admin(self, *args, stdin=None):
        r = sh(as_bench([self.bin, "admin", *args, "--data-dir", self.ctl]), input=stdin)
        return r.stdout

    def source_admin(self, *args):
        r = sh(as_bench([self.bin, "admin", "source", "--data-dir", self.ctl, "--actor", self.actor, *args]))
        return r.stdout

    def fixtures(self):
        """The Git fixture, built once under ROOT and reused by every scenario."""
        r = self.root
        work, bare = os.path.join(r, "work"), os.path.join(r, "git", "probe")
        if not os.path.isdir(work):
            os.makedirs(os.path.join(r, "git"), exist_ok=True)
            sh(["git", "init", "-q", "-b", "main", work])
            open(os.path.join(work, "README"), "w").write("B09 fixture\n")
            open(os.path.join(work, ".sentinel.yml"), "w").write(pipeline_yaml("true"))
            sh(["git", *IDENT, "-C", work, "add", "."])
            sh(["git", *IDENT, "-C", work, "commit", "-q", "-m", "base"])
            sh(["git", "clone", "-q", "--bare", work, bare])
            sh(["git", "-C", bare, "config", "uploadpack.allowAnySHA1InWant", "true"])
            sh(["git", "-C", work, "remote", "add", "bench", bare])
            sh(["git", "-C", work, *PUSH, "bench", "main"])
            sh(["chown", "-R", f"{BENCH_USER}:{BENCH_USER}", os.path.join(r, "git")])
        if not os.path.exists(os.path.join(r, "tls.key")):
            sh(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=b09",
                "-addext", f"subjectAltName=IP:{BRIDGE_ADDR}", "-keyout", os.path.join(r, "tls.key"),
                "-out", os.path.join(r, "ca.pem")])
            pw = os.path.join(r, "password")
            with open(pw, "w") as f:
                f.write(uuid.uuid4().hex)
            for f in ("tls.key", "ca.pem", "password"):
                sh(["chown", BENCH_USER, os.path.join(r, f)])
            os.chmod(os.path.join(r, "tls.key"), 0o600)
        self.work, self.bare = work, bare

    def provision(self):
        # A scenario's state from an earlier invocation under the same root would fail bootstrap.
        shutil.rmtree(self.run_dir, ignore_errors=True)
        os.makedirs(self.run_dir, exist_ok=True)
        base = self.run_dir
        d = self.spec.get("disk", {})
        for who in ("controller", "worker"):
            kind = d.get(who)
            if kind:
                # A small worker disk still admits a 1 GiB job (free space less the worker's 512 MiB reserve).
                size = 2048 if kind != "small" else 1792 if who == "worker" else 512
                self.mounts[who] = make_fs(self.root, f"{self.name}-{who}", size, slow_ms=8 if kind == "slow" else None)
        self.ctl = os.path.join(self.mounts.get("controller", base), "controller")
        self.logs = os.path.join(base, "logs")
        for p in (self.ctl, self.logs):
            os.makedirs(p, exist_ok=True)
        sh(["chown", "-R", f"{BENCH_USER}:{BENCH_USER}", base, self.ctl])
        self.admin("bootstrap", "--username", "root", stdin="correct horse battery staple")
        self.admin("key", "create")
        self.tenant_ids = {t: self.admin("tenant", "create", "--slug", t).strip() for t in self.tenants}
        self.actor = re.search(r"subject=(\S+)", self.admin("status")).group(1)
        self.admin("pool", "create", "--name", "shared")
        for t in self.tenants:
            self.admin("pool", "grant", "--pool", "shared", "--tenant", t)
        self.repos, self.hooks = {}, {}
        with open(os.path.join(self.ctl, "source-destinations.json"), "w") as f:
            json.dump([f"https://{BRIDGE_ADDR}:{GIT_PORT}"], f)
        self.token = self.admin("token", "issue", "--user", "root", "--name", "b09",
                                "--scope", "read,run,tenant-admin,platform-admin", "--expires-in", "2d").strip()
        storage = ""
        if d.get("controller") == "small":
            storage = ("[storage]\nreserve_bytes = 67108864\nlow_watermark_bytes = 134217728\n"
                       "high_watermark_bytes = 201326592\n")
        with open(os.path.join(base, "server.toml"), "w") as f:
            f.write(f'listen = "{BRIDGE_ADDR}:{LINK_PORT}"\napi_listen = "127.0.0.1:{API_PORT}"\n{storage}')
        sh(["chown", BENCH_USER, os.path.join(base, "server.toml")])

    def start_git(self):
        env = {"FIXTURE_PASSWORD": os.path.join(self.root, "password")}
        self.git = Proc(self.root, "git", ["python3", os.path.join(self.a.kit, "b09-git.py"), os.path.join(self.root, "git"),
                                         os.path.join(self.root, "ca.pem"), os.path.join(self.root, "tls.key"),
                                         BRIDGE_ADDR, str(GIT_PORT)], os.path.join(self.logs, "git.log"), extra_env=env).start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not read_first(os.path.join(self.logs, "git.log")):
            time.sleep(0.05)

    def start_controller(self):
        self.server_log = os.path.join(self.logs, "server.log")
        self.server = Proc(self.root, "server", [self.bin, "server", "--config", os.path.join(self.run_dir, "server.toml"),
                                               "--data-dir", self.ctl, "--log-format", "json"], self.server_log).start()
        link = wait_event(self.server_log, "link_listening")[-1]
        wait_event(self.server_log, "api_listening")
        self.fingerprint = link["fields"]["fingerprint"]
        if self.tail is None:
            self.tail = DeliveryTail(self.server_log)
            self.tail.start()

    def bind_repos(self):
        for t in self.tenants:
            rid = json.loads(self.source_admin("create", "--tenant", self.tenant_ids[t], "--name", "probe"))["repo"]
            self.repos[t] = rid
            payload = {"binding": {"remote": f"https://{BRIDGE_ADDR}:{GIT_PORT}/probe", "allowed_refs": ["refs/heads/*"],
                                   "pipeline_path": ".sentinel.yml", "trust": open(os.path.join(self.root, "ca.pem")).read()},
                       "credential": {"Https": {"username": "deploy", "secret": open(os.path.join(self.root, "password")).read()}},
                       "forge": None}
            sh(as_bench([self.bin, "admin", "source", "--data-dir", self.ctl, "--actor", self.actor, "bind",
                         "--repo", rid, "--expected", "0"]), input=json.dumps(payload))
            self.hooks[t] = self.source_admin("hook-token", "--repo", rid).strip()

    def memberships(self):
        """The host-local CLI has no membership command and a platform admin cannot add itself over the API.
        Written as the bench user, before the controller starts, so the database files keep their owner."""
        sh(as_bench(["python3", "-c", MEMBERSHIPS, os.path.join(self.ctl, "metadata.sqlite"), *self.tenants]))

    def enroll_workers(self):
        """Host-local admin needs the database to itself, so every enrollment is issued before the controller starts."""
        for i in range(1, self.n + 1):
            w = self.wk(i)
            with open(w["enroll"], "w") as f:
                f.write(self.admin("worker", "enroll", "--pool", "shared"))
            sh(["chown", BENCH_USER, w["enroll"]])

    def start_worker(self, i):
        w = self.wk(i)
        if not os.path.exists(w["cfg"]):
            with open(w["cfg"], "w") as f:
                f.write(f'controller = "{BRIDGE_ADDR}:{LINK_PORT}"\ncontroller_fingerprint = "{self.fingerprint}"\n'
                        f'worker_name = "b09-w{i}"\nenrollment_file = "{w["enroll"]}"\n')
            sh(["chown", BENCH_USER, w["cfg"]])
        self.workers[i - 1]["offset"] = os.path.getsize(w["log"]) if os.path.exists(w["log"]) else 0
        w["proc"] = Proc(self.root, f"worker{i}", [self.bin, "worker", "--config", w["cfg"], "--data-dir", w["data"],
                                                   "--log-format", "json"], w["log"], netns=Net.ns(i)).start()

    def wk(self, i):
        while len(self.workers) < i:
            k = len(self.workers) + 1
            base = self.mounts.get("worker", self.run_dir)
            data = os.path.join(base, f"worker{k}")
            os.makedirs(data, exist_ok=True)
            sh(["chown", f"{BENCH_USER}:{BENCH_USER}", data])
            self.workers.append({"data": data, "cfg": os.path.join(self.run_dir, f"worker{k}.toml"),
                                 "enroll": os.path.join(self.run_dir, f"worker{k}.enroll"),
                                 "log": os.path.join(self.logs, f"worker{k}.log"), "offset": 0})
        return self.workers[i - 1]

    def start_workers(self):
        for i in range(1, self.n + 1):
            self.start_worker(i)
        self.worker_ids = []
        for i in range(1, self.n + 1):
            w = self.wk(i)
            ev = wait_event(w["log"], "link_connected", timeout=90, offset=w["offset"])
            self.worker_ids.append(ev[0]["fields"]["worker"])

    def up(self):
        self.fixtures()
        self.provision()
        self.start_git()
        self.bind_repos()
        self.enroll_workers()
        self.memberships()
        self.start_controller()
        self.start_workers()
        on_exit(self.remove_containers)

    # -- HTTP
    def call(self, method, path, body=None, token=None, timeout=60):
        """A 429 is the controller's admission limit (parked waiters per user, a full intake queue), not a failure:
        wait the retry_after_ms it names (1 s if none) and send again, counting retries for the run's record."""
        data = None if body is None else json.dumps(body).encode()
        deadline = time.monotonic() + 300
        while True:
            req = urllib.request.Request(self.api + path, data=data, method=method)
            req.add_header("authorization", f"Bearer {token or self.token}")
            if data is not None:
                req.add_header("content-type", "application/json")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                if e.code != 429 or time.monotonic() > deadline:
                    raise
                _RETRIES.n = getattr(_RETRIES, "n", 0) + 1
                time.sleep(retry_after_ms(e.read()) / 1000)

    def get(self, path, timeout=60):
        return json.loads(self.call("GET", path, timeout=timeout)[1])

    # -- commits and runs
    def make_commits(self, n, yml=None, prefix="r"):
        """n distinct commits, each on its own new ref, pushed in one go."""
        tree = sh(["git", "-C", self.work, "rev-parse", "HEAD^{tree}"]).stdout.strip()
        if yml is not None:
            idx = os.path.join(self.run_dir, "index.tmp")
            env = dict(os.environ, GIT_INDEX_FILE=idx)
            sh(["git", "-C", self.work, "read-tree", "HEAD"], env=env)
            blob = sh(["git", "-C", self.work, "hash-object", "-w", "--stdin"], input=yml).stdout.strip()
            sh(["git", "-C", self.work, "update-index", "--cacheinfo", f"100644,{blob},.sentinel.yml"], env=env)
            tree = sh(["git", "-C", self.work, "write-tree"], env=env).stdout.strip()
        base = sh(["git", "-C", self.work, "rev-parse", "HEAD"]).stdout.strip()
        tag = uuid.uuid4().hex[:8]
        refs = []
        for i in range(n):
            sha = sh(["git", *IDENT, "-C", self.work, "commit-tree", tree, "-p", base, "-m", f"b09 {tag} {i}"]).stdout.strip()
            ref = f"refs/heads/{prefix}-{tag}-{i}"
            sh(["git", "-C", self.work, "update-ref", ref, sha])
            refs.append((ref, sha))
        sh(["git", "-C", self.work, *PUSH, "bench", *[f"{r}:{r}" for r, _ in refs]])
        for r, _ in refs:
            sh(["git", "-C", self.work, "update-ref", "-d", r])
        sh(["chown", "-R", f"{BENCH_USER}:{BENCH_USER}", self.bare])
        return refs

    def intake(self, tenant, ref, sha):
        """POST the ref update; returns (delivery, t0_ns, ack_ns, t0_wall_ms)."""
        body = {"delivery_id": f"b09-{uuid.uuid4().hex}", "ref": ref, "old_sha": ZERO, "new_sha": sha}
        t0, t0_wall_ms = time.monotonic_ns(), time.time_ns() / 1e6
        status, raw = self.call("POST", f"/intake/{self.repos[tenant]}", body, token=self.hooks[tenant])
        ack = time.monotonic_ns() - t0
        if status != 202:
            raise RuntimeError(f"intake answered {status}")
        return json.loads(raw)["delivery"], t0, ack, t0_wall_ms

    def wait_finished(self, run, limit_s=300):
        since, deadline = None, time.monotonic() + limit_s
        while time.monotonic() < deadline:
            body = self.get(f"/runs/{run}/wait?timeout_ms=25000" + (f"&since={since}" if since else ""), timeout=40)
            if body["finished"]:
                return body["run"], time.monotonic_ns()
            since = body["version"]
        # The queue view names why a job is still waiting (no fitting worker, placement paused).
        try:
            queue = {t: self.get(f"/queue?tenant={t}", timeout=10) for t in self.tenants}
        except Exception as e:
            queue = repr(e)[:200]
        raise RuntimeError(f"run {run} did not finish in {limit_s}s; queue: {json.dumps(queue)[:1500]}")

    def fire(self, tenant, ref, sha, limit_s=300):
        """One run end to end. e2e_ns runs from the intake POST to the controller's own terminal stamp (same
        host, wall clock, ms resolution), so a waiter that queued behind the parked-subscriber limit does not
        lengthen it; e2e_seen_ns is when the driver learned of it."""
        _RETRIES.n = 0
        delivery, t0, ack, t0_wall_ms = self.intake(tenant, ref, sha)
        run = self.tail.wait(delivery)
        seen = time.monotonic_ns()
        final, done = self.wait_finished(run, limit_s)
        terminal = [j["timestamps"]["terminal_ms"] for j in final["jobs"] if j.get("timestamps", {}).get("terminal_ms")]
        e2e = int((max(terminal) - t0_wall_ms) * 1e6) if terminal else done - t0
        return {"run": run, "tenant": tenant, "intake_ack_ns": ack, "intake_to_run_ns": seen - t0,
                "e2e_ns": e2e, "e2e_seen_ns": done - t0, "retries_429": _RETRIES.n,
                "state": final["jobs"][0]["state"], "attempt": final["jobs"][0].get("attempt")}

    def stamps(self, run):
        con = sqlite3.connect(f"file:{os.path.join(self.ctl, 'metadata.sqlite')}?mode=ro", uri=True, timeout=10)
        try:
            rid = bytes.fromhex(run.removeprefix("run_").replace("-", ""))
            rows = con.execute("""SELECT j.queued_ms, a.offered_ms, a.acked_ms, a.fence FROM jobs j
                JOIN attempts a ON a.job_id = j.id WHERE j.run_id = ? ORDER BY a.fence""", (rid,)).fetchall()
        finally:
            con.close()
        return rows

    def enrich(self, r):
        """Add the attempt's phase timings and the store's stamps to a fired run."""
        if r.get("attempt"):
            try:
                steps = self.get(f"/attempts/{r['attempt']}/steps")
                t = steps.get("timings_ns") or {}
                for k in ("checkout", "container_start", "image_pull", "steps", "finalize"):
                    if k in t:
                        r[f"{k}_ns"] = t[k]
                if "steps" in t:
                    r["overhead_ns"] = r["e2e_ns"] - t["steps"]
            except urllib.error.HTTPError:
                pass
        try:
            rows = self.stamps(r["run"])
            if rows:
                r["attempts"] = len(rows)
                q, o, k, _ = rows[-1]
                if o is not None and q is not None:
                    r["queue_wait_ms"] = o - q
        except sqlite3.Error:
            pass
        return r

    def remove_containers(self):
        """Remove only this run's workers' containers, by their label."""
        for wid in getattr(self, "worker_ids", []):
            ids = sh(as_bench(["podman", "ps", "-aq", "--filter", f"label=io.sentinel.worker={wid}"]), check=False).stdout.split()
            if ids:
                sh(as_bench(["podman", "rm", "-f", *ids]), check=False)

    def leaked_containers(self):
        n = 0
        for wid in getattr(self, "worker_ids", []):
            n += len(sh(as_bench(["podman", "ps", "-aq", "--filter", f"label=io.sentinel.worker={wid}"]), check=False).stdout.split())
        return n

    def down(self):
        run_cleanups()


# ---------------------------------------------------------------- scenarios

def burst(d, tenant, refs, workers=None):
    """Fire len(refs) runs at once; every run's own clocks."""
    gate = threading.Barrier(len(refs))

    def one(rs):
        gate.wait()
        return d.fire(tenant, *rs)
    with concurrent.futures.ThreadPoolExecutor(len(refs)) as ex:
        return list(ex.map(one, refs))


def perf(d, a, name, spec, out, stamp_):
    """Steady (one run at a time) or burst (all at once) runs, repeated; one record per repeat."""
    mode, n = spec["mode"], a.runs
    tenant = d.tenants[0]
    d.fire(tenant, *d.make_commits(1)[0])  # warm-up: image, mirror and worker paths; not recorded
    for rep in range(a.repeats):
        settle()
        refs = d.make_commits(n)
        c0, t0 = conditions(), time.time()
        if mode == "burst":
            runs = burst(d, tenant, refs)
        else:
            runs = [d.fire(tenant, *r) for r in refs]
        c1 = conditions()
        runs = [d.enrich(r) for r in runs]
        ok = [r for r in runs if r["state"] == "passed" and "overhead_ns" in r]
        record = {"kind": "perf", "scenario": scenario_desc(name, spec, a), "repeat": rep, "started_at_unix_ms": int(t0 * 1000),
                  "conditions": {"start": c0, "end": c1}, "runs": runs, "passed": len(ok), "failed": len(runs) - len(ok),
                  "summary": {m: distribution([r[m] for r in ok if m in r])
                              for m in ("overhead_ns", "e2e_ns", "steps_ns", "checkout_ns", "container_start_ns",
                                        "finalize_ns", "intake_ack_ns", "queue_wait_ms")}}
        emit(out, stamp_, record)
        s = record["summary"]["overhead_ns"]
        log(f"{name} repeat {rep}: n={s.get('n')} passed={len(ok)}/{len(runs)} overhead p50 {s.get('p50', 0) / 1e6:.0f} ms p95 {s.get('p95', 0) / 1e6:.0f} ms")


def scenario_desc(name, spec, a):
    desc = {"id": name, "workers": spec.get("workers", 1), "mode": spec.get("mode"),
            "runs_per_repeat": a.runs if spec.get("mode") else None, "link": spec.get("link", "direct"),
            "link_shape": LINKS.get(spec.get("link", "direct"), {}), "disk": spec.get("disk", {}),
            "job": {"image": IMAGE, "step": "true", "cpu": "0.25", "memory": "128MiB"}}
    if a.handicap_delay_ms:
        desc["injected_handicap"] = {"delay_ms_each_way": a.handicap_delay_ms}
    return {k: v for k, v in desc.items() if v is not None}


def emit(out, stamp_, record):
    out.write(json.dumps({"schema": SCHEMA, **stamp_, **record}, separators=(",", ":")) + "\n")
    out.flush()


class Checks:
    def __init__(self):
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append({"name": name, "ok": bool(ok), "detail": str(detail)[:300]})
        log(("PASS" if ok else "FAIL"), name, detail)
        return ok

    @property
    def ok(self):
        return all(i["ok"] for i in self.items)


def count_connected(d):
    return [len(log_events(d.wk(i)["log"], "link_connected", d.wk(i)["offset"])[0]) for i in range(1, d.n + 1)]


def wait_reconnect(d, before, timeout=90):
    t0 = time.monotonic_ns()
    got = {}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(got) < d.n:
        for i, c in enumerate(count_connected(d)):
            if c > before[i] and i not in got:
                got[i] = time.monotonic_ns() - t0
        time.sleep(0.02)
    return got


def sleepy(secs, tag="sleep"):
    return pipeline_yaml(f"sleep {secs}")


def r_restart_controller(d, a, name, spec, chk, obs):
    sig = signal.SIGKILL if name.endswith("kill") else signal.SIGTERM
    yml = sleepy(6)
    refs = d.make_commits(20, yml)
    fired, errs = [], []

    def one(rs):
        try:
            fired.append(d.fire(d.tenants[0], *rs, limit_s=240))
        except Exception as e:
            errs.append(repr(e)[:200])
    ex = concurrent.futures.ThreadPoolExecutor(20)
    futs = [ex.submit(one, r) for r in refs]
    t_dispatch = time.monotonic()
    while time.monotonic() - t_dispatch < 60:
        if len(d.tail.runs) >= 20:
            break
        time.sleep(0.05)
    time.sleep(2.5)  # runs are executing
    before = count_connected(d)
    t_kill = time.monotonic_ns()
    d.server.stop(sig, wait=20)
    obs["controller_down_ns"] = time.monotonic_ns() - t_kill
    t_start = time.monotonic_ns()
    d.start_controller()
    obs["controller_restart_to_listening_ns"] = time.monotonic_ns() - t_start
    rec = wait_reconnect(d, before)
    obs["worker_reconnect_ns_after_listening"] = sorted(rec.values())
    chk.check("every worker reconnected", len(rec) == d.n, f"{len(rec)}/{d.n}")
    for f in futs:
        f.result(timeout=300)
    ex.shutdown()
    runs = [d.enrich(r) for r in fired]
    states = {}
    for r in runs:
        states[r["state"]] = states.get(r["state"], 0) + 1
    obs["states"] = states
    obs["attempts_per_run"] = sorted(r.get("attempts", 1) for r in runs)
    chk.check("every run reached a terminal state", len(runs) == 20 and not errs, f"{len(runs)} observed, errors={errs[:2]}")
    chk.check("no run lost its verdict (all passed)", states.get("passed") == 20, states)
    obs["e2e_ns"] = distribution([r["e2e_ns"] for r in runs])
    time.sleep(3)
    chk.check("no leaked containers", d.leaked_containers() == 0, d.leaked_containers())


def r_restart_worker(d, a, name, spec, chk, obs):
    refs = d.make_commits(6, sleepy(8))
    fired, errs = [], []

    def one(rs):
        try:
            fired.append(d.fire(d.tenants[0], *rs, limit_s=420))
        except Exception as e:
            errs.append(repr(e)[:200])
    ex = concurrent.futures.ThreadPoolExecutor(6)
    futs = [ex.submit(one, r) for r in refs]
    t = time.monotonic()
    while time.monotonic() - t < 60 and len(d.tail.runs) < 6:
        time.sleep(0.05)
    time.sleep(3.5)
    w = d.wk(1)
    before = count_connected(d)
    w["proc"].send(signal.SIGKILL)
    w["proc"].p.wait()
    t_kill = time.monotonic_ns()
    d.start_worker(1)
    wait_event(w["log"], "link_connected", timeout=90, offset=w["offset"])
    obs["killed_worker_reconnect_ns"] = time.monotonic_ns() - t_kill
    for f in futs:
        f.result(timeout=480)
    ex.shutdown()
    runs = [d.enrich(r) for r in fired]
    states = {}
    for r in runs:
        states[r["state"]] = states.get(r["state"], 0) + 1
    obs["states"] = states
    obs["attempts_per_run"] = sorted(r.get("attempts", 1) for r in runs)
    obs["e2e_ns"] = distribution([r["e2e_ns"] for r in runs])
    chk.check("every run reached a terminal state", len(runs) == 6 and not errs, f"{len(runs)} observed, errors={errs[:2]}")
    chk.check("runs on the killed worker were retried or settled, none stuck", all(r["state"] in ("passed", "failed", "infra_failed", "canceled") for r in runs), states)
    time.sleep(5)
    chk.check("no leaked containers", d.leaked_containers() == 0, d.leaked_containers())
    probe = d.fire(d.tenants[0], *d.make_commits(1)[0])
    chk.check("the fleet runs new work after the restart", probe["state"] == "passed", probe["state"])


def r_partition(d, a, name, spec, chk, obs):
    net = d.net
    refs = d.make_commits(1, sleepy(12))
    ex = concurrent.futures.ThreadPoolExecutor(1)
    fut = ex.submit(lambda: d.fire(d.tenants[0], *refs[0], limit_s=300))
    while not d.tail.runs:
        time.sleep(0.05)
    time.sleep(3)
    secs = spec["partition_s"]
    before = count_connected(d)
    lost0 = len(log_events(d.wk(1)["log"], "link_lost", d.wk(1)["offset"])[0])
    t = time.monotonic_ns()
    net.partition(1, True)
    time.sleep(secs)
    net.partition(1, False)
    t_heal = time.monotonic_ns()
    obs["partition_ns"] = t_heal - t
    got = wait_reconnect(d, before, timeout=120 if secs > 15 else 20)
    obs["reconnect_after_heal_ns"] = got.get(0)
    r = d.enrich(fut.result(timeout=300))
    ex.shutdown()
    lost = len(log_events(d.wk(1)["log"], "link_lost", d.wk(1)["offset"])[0]) - lost0
    obs["link_lost_events"] = lost
    obs["run"] = {k: r.get(k) for k in ("state", "e2e_ns", "attempts")}
    if secs < 15:
        chk.check("the link held through the partition (no loss, no reconnect)", lost == 0 and 0 not in got, {"lost": lost, "reconnected": got})
        chk.check(f"the run survived a {secs} s partition on its first attempt", r["state"] == "passed" and r.get("attempts", 1) == 1, obs["run"])
    else:
        chk.check("the link was lost and came back by itself", lost > 0 and 0 in got, {"lost": lost, "reconnected": got})
        chk.check(f"the run reached a terminal state after a {secs} s partition", r["state"] in ("passed", "failed", "infra_failed"), obs["run"])
    chk.check("new work runs after the heal", d.fire(d.tenants[0], *d.make_commits(1)[0])["state"] == "passed")


def r_disk_full_worker(d, a, name, spec, chk, obs):
    mp = d.mounts["worker"]
    # Two files: a job's file size limit is its disk reservation (1 GiB), and the disk holds more than that.
    fill = pipeline_yaml("for f in a b; do dd if=/dev/zero of=/workspace/fill-$f bs=1M count=1000 2>&1 | tail -1; done; df -k /workspace | tail -1", timeout="2m")
    loud = pipeline_yaml("yes 0123456789abcdef0123456789abcdef | head -c 400000000", timeout="3m")
    free0 = shutil.disk_usage(mp).free
    r1 = d.enrich(d.fire(d.tenants[0], *d.make_commits(1, fill)[0], limit_s=240))
    obs["fill_job"] = {k: r1.get(k) for k in ("state", "e2e_ns")}
    chk.check("the job that filled the worker's disk reached a terminal state", r1["state"] in ("passed", "failed", "infra_failed"), r1["state"])
    time.sleep(3)
    free1 = shutil.disk_usage(mp).free
    obs["free_bytes"] = {"before": free0, "after_fill_job": free1}
    chk.check("the worker released the workspace (space is back)", free1 > free0 * 0.5, f"{free1}/{free0}")
    r2 = d.enrich(d.fire(d.tenants[0], *d.make_commits(1, loud)[0], limit_s=300))
    obs["loud_job"] = {k: r2.get(k) for k in ("state", "e2e_ns")}
    chk.check("a 400 MB log flood reached a terminal state", r2["state"] in ("passed", "failed", "infra_failed"), r2["state"])
    r3 = d.fire(d.tenants[0], *d.make_commits(1)[0], limit_s=240)
    chk.check("a small job passes after both", r3["state"] == "passed", r3["state"])
    chk.check("the worker stayed connected", d.wk(1)["proc"].alive())
    time.sleep(3)
    chk.check("no leaked containers", d.leaked_containers() == 0, d.leaked_containers())


def r_disk_full_controller(d, a, name, spec, chk, obs):
    mp = d.mounts["controller"]
    keep = d.fire(d.tenants[0], *d.make_commits(1)[0])
    chk.check("a run passes before the disk fills", keep["state"] == "passed", keep["state"])
    free = shutil.disk_usage(mp).free
    ballast = os.path.join(mp, "ballast")
    sh(["fallocate", "-l", str(max(1, free - 100 * 1024 * 1024)), ballast])
    obs["free_after_ballast_bytes"] = shutil.disk_usage(mp).free
    refs = d.make_commits(1)
    t0 = time.monotonic()
    try:
        delivery, *_ = d.intake(d.tenants[0], *refs[0])
        run = d.tail.wait(delivery, timeout=60)
        accepted = True
    except Exception as e:
        accepted, run = False, None
        obs["intake_error"] = repr(e)[:200]
    obs["intake_accepted_while_full"] = accepted
    queue_reason = None
    if run:
        time.sleep(3)
        try:
            q = d.get(f"/queue?tenant={d.tenants[0]}")
            queue_reason = {"placement_paused": q.get("placement_paused"), "reasons": [j.get("reason") for j in q.get("jobs", [])]}
        except urllib.error.HTTPError as e:
            queue_reason = {"error": e.code}
    obs["queue_while_full"] = queue_reason
    paused = bool(queue_reason and (queue_reason.get("placement_paused") or "storage" in json.dumps(queue_reason)))
    chk.check("the controller stayed up and answered", d.server.alive())
    chk.check("placement pause or storage reason is named while below the watermark", paused or not accepted, queue_reason)
    os.unlink(ballast)
    if run:
        final, _ = d.wait_finished(run, 180)
        obs["recovery_ns"] = int((time.monotonic() - t0) * 1e9)
        chk.check("the queued run completes once space is back", final["jobs"][0]["state"] == "passed", final["jobs"][0]["state"])
    con = sqlite3.connect(f"file:{os.path.join(d.ctl, 'metadata.sqlite')}?mode=ro", uri=True, timeout=10)
    chk.check("the metadata database passes integrity_check", con.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
    con.close()
    chk.check("a new run passes after recovery", d.fire(d.tenants[0], *d.make_commits(1)[0])["state"] == "passed")


def r_noisy(d, a, name, spec, chk, obs):
    noisy_on = name == "noisy-tenant"
    quiet, noisy = d.tenants
    heavy = pipeline_yaml("sleep 3", cpu="3", memory="256MiB")
    futs, ex = [], concurrent.futures.ThreadPoolExecutor(80)
    noisy_runs = []
    if noisy_on:
        refs = d.make_commits(40, heavy, prefix="n")
        futs = [ex.submit(lambda rs=rs: noisy_runs.append(d.fire(noisy, *rs, limit_s=400))) for rs in refs]
        time.sleep(4)
    quiet_runs = []
    qrefs = d.make_commits(20, prefix="q")
    for rs in qrefs:
        quiet_runs.append(d.fire(quiet, *rs, limit_s=300))
        time.sleep(0.5)
    for f in futs:
        f.result(timeout=500)
    ex.shutdown()
    quiet_runs = [d.enrich(r) for r in quiet_runs]
    ok = [r for r in quiet_runs if r["state"] == "passed"]
    obs["quiet"] = {m: distribution([r[m] for r in ok if m in r]) for m in ("e2e_ns", "overhead_ns", "queue_wait_ms")}
    obs["noisy_runs"] = len(noisy_runs)
    obs["noisy_states"] = {s: sum(1 for r in noisy_runs if r["state"] == s) for s in {r["state"] for r in noisy_runs}}
    obs["noisy_e2e_ns"] = distribution([r["e2e_ns"] for r in noisy_runs])
    chk.check("every quiet-tenant run passed", len(ok) == 20, f"{len(ok)}/20")
    if noisy_on:
        chk.check("every noisy-tenant run reached a terminal state", len(noisy_runs) == 40, len(noisy_runs))
        qw = obs["quiet"]["queue_wait_ms"].get("p95")
        chk.check("the quiet tenant's p95 queue wait stays under 10 s beside a 40-job backlog", qw is not None and qw < 10_000, qw)


def r_blocked(d, a, name, spec, chk, obs):
    raise Blocked("pinned tailcat v0.6.0 (sha256 d46582137d21f03d...) is not installed on the verification VPS or the workstation, "
                  "and no download source is recorded in the repository; with it, add [tailcat] enabled=true, binary=<path> to the "
                  "server and worker TOML (docs/configuration.md) and rerun: "
                  "python3 bench/b09-harness.py run --scenarios w1-steady --tailcat BINARY")


class Blocked(Exception):
    pass


RELIABILITY = {"restart-controller-kill": r_restart_controller, "restart-controller-term": r_restart_controller,
               "restart-worker-kill": r_restart_worker, "partition": r_partition, "partition-long": r_partition, "disk-full-worker": r_disk_full_worker,
               "disk-full-controller": r_disk_full_controller, "noisy-tenant": r_noisy, "noisy-tenant-control": r_noisy,
               "tailcat-relay": r_blocked}


def run_scenario(a, name, out, stamp_):
    spec = SCENARIOS[name]
    install_lock = None
    if not a.no_lock:
        log(f"{name}: waiting for the exclusive lock {LOCK}")
        install_lock = open(LOCK, "a")
        fcntl.flock(install_lock, fcntl.LOCK_EX)
    try:
        settle()
        if spec["kind"] == "blocked":
            checks, obs = Checks(), {}
            try:
                RELIABILITY[name](None, a, name, spec, checks, obs)
            except Blocked as b:
                emit(out, stamp_, {"kind": "blocked", "scenario": {"id": name}, "blocked_by": str(b)})
                log(f"{name}: Blocked by: {b}")
            return
        hard_cleanup(a.root)
        os.makedirs(a.root, exist_ok=True)
        d = Deploy(a, name, spec)
        d.net = Net(spec.get("workers", 1))
        link = dict(LINKS.get(spec.get("link", "direct"), {}))
        if a.handicap_delay_ms:
            link["delay_ms"] = link.get("delay_ms", 0) + a.handicap_delay_ms
        t_up = time.monotonic()
        try:
            d.up()
            d.net.shape_all(link)
            log(f"{name}: deployment up in {time.monotonic() - t_up:.1f}s")
            if spec["kind"] == "perf":
                perf(d, a, name, spec, out, stamp_)
            else:
                chk, obs = Checks(), {}
                c0 = conditions()
                try:
                    RELIABILITY[name](d, a, name, spec, chk, obs)
                except Exception as e:
                    chk.check("scenario ran to completion", False, repr(e))
                emit(out, stamp_, {"kind": "reliability", "scenario": scenario_desc(name, spec, a),
                                   "conditions": {"start": c0, "end": conditions()}, "ok": chk.ok,
                                   "assertions": chk.items, "observations": obs})
        finally:
            d.down()
    finally:
        if install_lock:
            fcntl.flock(install_lock, fcntl.LOCK_UN)
            install_lock.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("cleanup")
    c.add_argument("--root", required=True)
    r = sub.add_parser("run")
    r.add_argument("--kit", required=True)
    r.add_argument("--root", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--source", required=True, help="the checkout the kit's binary was built from")
    r.add_argument("--scenarios", required=True)
    r.add_argument("--repeats", type=int, default=5)
    r.add_argument("--runs", type=int, default=20, help="runs per perf repeat (at least 20 for a p95)")
    r.add_argument("--handicap-delay-ms", type=int, default=0,
                   help="add this one-way delay on every link: an injected regression for the gate's sensitivity check")
    r.add_argument("--no-lock", action="store_true")
    a = p.parse_args()
    if a.cmd == "list":
        for k, v in SCENARIOS.items():
            print(f"{k:34} {v['kind']:12} workers={v.get('workers', 1)}")
        return
    if os.geteuid() != 0:
        sys.exit("run as root: the scenarios create namespaces, loop devices and mounts")
    install_traps()
    os.chdir(f"/home/{BENCH_USER}")
    if a.cmd == "cleanup":
        hard_cleanup(a.root)
        return
    names = a.scenarios.split(",") if a.scenarios != "all" else list(SCENARIOS)
    for n in names:
        if n not in SCENARIOS:
            sys.exit(f"unknown scenario {n}")
    if a.runs < 20 and any(SCENARIOS[n]["kind"] == "perf" for n in names):
        sys.exit("--runs below 20 makes the nearest-rank p95 the maximum")
    stamp_ = stamp(a.source, os.path.join(a.kit, "sentinel"))
    with open(a.out, "a") as out:
        for n in names:
            try:
                run_scenario(a, n, out, stamp_)
            except Exception as e:
                log(f"{n}: failed: {e!r}")
                emit(out, stamp_, {"kind": "error", "scenario": {"id": n}, "error": repr(e)[:2000]})
            finally:
                run_cleanups()
                hard_cleanup(a.root)


if __name__ == "__main__":
    main()
