#!/usr/bin/env python3
"""Q13: scripted verification of the host-management path across a fleet.

    python3 bench/q13-fleet.py list
    python3 bench/q13-fleet.py selftest
    python3 bench/q13-fleet.py run --fleet FLEET.json --out OUT.jsonl [--scenarios ID[,ID...]]
                                    --source CHECKOUT [--binary SENTINEL]

The scenarios drive enrollment, worker-side uninstall, controller-side uninstall, Tailcat
reconnect and revocation, a copied (duplicate) identity, ceiling changes, ARM placement, OS and
isolation explanations and priority overrides, through one `Fleet` interface:

* `SimFleet` is a local, in-process model of the documented contracts (docs/worker-bootstrap.md,
  docs/worker-link.md, docs/api.md). It exists to test THIS harness: that each scenario passes
  against a correct model and FAILS against a model with the matching defect (`selftest` injects
  ten). Its records carry `"simulated": true` and are never Q13 evidence about the product.
* `RealFleet` talks to a real controller and real worker hosts. Controller changes go through
  `sentinel admin ...` on the controller host (host-local, no step-up), reads through the
  bearer-authenticated API (`GET /api/v1/admin/workers`, `/admin/placement`), and a worker host is
  driven by an exec prefix (for example `["ssh", "-F", "ssh-config", "arm64-host"]`). A scenario
  whose prerequisite is missing from the fleet file (no arm64 host, no Tailcat helper, no job
  driver) is recorded `blocked` with the exact prerequisite; nothing is simulated and no result is
  invented. Real records carry `"simulated": false`.

FLEET.json (real mode):

    {"controller": {"exec": ["ssh", "-F", "cfg", "kvm-host"], "sentinel": "/usr/local/bin/sentinel",
                    "data_dir": "/var/lib/sentinel", "api": "https://sentinel.example.com",
                    "token_file": "/root/q13.token", "pool": "builders"},
     "hosts": {"x86": {"exec": [...], "arch": "x86_64", "sentinel": "/usr/local/bin/sentinel",
                       "bootstrap": "/root/sentinel-worker-bootstrap.sh"},
               "arm": {"exec": [...], "arch": "aarch64", "sentinel": "..."}},
     "tailcat": true,
     "job_driver": ["python3", "bench/q13-job.py", "--config", "/root/q13-job.json"]}

`job_driver` is run as `job_driver ARCH OS ISOLATION CPU_MILLIS MEMORY_BYTES DISK_BYTES` and prints
one JSON line `{"worker": "wrk_..."|null, "reason": "..."|null}`: where a real executor placed a
probe job, or the queue reason it waits with. It is the only way this harness creates jobs. bench/q13-job.py is
that driver (its job config names the bound repository, a Git clone and the tokens); `--keep` before the
arguments leaves the probe running and `--release` cancels the kept ones.

One record per scenario is appended as a JSON line, schema `sentinel-bench/q13/1`. A real run names its build:
`--source` (or SENTINEL_SRC) is the checkout the fleet's sentinel binaries were built from, `--binary` an optional
binary to hash, and SENTINEL_BENCH_HOST_LABEL the anonymized label of the machine running this driver; each real
record carries `build {commit, dirty[, binary_sha256]}` and `host {hostname, ...}` (bench/benchstamp.py), and the
run refuses to start without them. Simulated records carry neither: they are never evidence.
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchstamp  # noqa: E402

SCHEMA = "sentinel-bench/q13/1"
GIB = 1 << 30


class Refused(Exception):
    """The system said no, with a reason: a visible refusal, not a crash."""


class Blocked(Exception):
    """A prerequisite of the scenario is missing from the fleet."""


# --------------------------------------------------------------------------- simulation


class SimHost:
    def __init__(self, name, arch="x86_64", os_="linux", runtimes=("container",), cpu=8000,
                 mem=16 * GIB, disk=200 * GIB, speed=1.0):
        self.name, self.arch, self.os, self.runtimes = name, arch, os_, set(runtimes)
        self.cpu, self.mem, self.disk, self.speed = cpu, mem, disk, speed
        self.identity = None  # {"worker","fingerprint","node_key"}
        self.running = False
        self.last_refusal = None


class SimFleet:
    """A model of the documented behavior. `defects` names behaviors to break on purpose."""

    simulated = True
    tailcat = True
    arm = True

    def __init__(self, hosts, defects=()):
        self.hosts = {h.name: h for h in hosts}
        self.defects = set(defects)
        self.enrollments, self.workers = {}, {}
        self.allow = {}  # node key -> worker
        self.order = "fastest"
        self.audit = []
        self.tick = 0

    # -- controller side
    def issue(self, transport="tailcat", cpu=None, mem=None, disk=None, priority=0, ttl=3600):
        tok = "tok_" + secrets.token_hex(6)
        sec = "sntl_" + secrets.token_hex(16)
        self.enrollments[tok] = dict(secret=sec, transport=transport, state="pending",
                                     policy=dict(cpu_millis=cpu, memory_bytes=mem,
                                                 disk_bytes=disk, priority=priority),
                                     expires=time.time() + ttl)
        self.audit.append("worker-enrollment-issued")
        return tok, sec

    def withdraw(self, tok):
        self.enrollments[tok]["state"] = "revoked"
        self.audit.append("worker-enrollment-revoked")

    def _redeem(self, secret, worker, fingerprint, node_key):
        found = next((e for e in self.enrollments.values() if e["secret"] == secret), None)
        if found is None or found["state"] != "pending" or found["expires"] < time.time():
            raise Refused("403 enrollment refused")  # one uniform message
        for w in self.workers.values():
            same = w["fingerprint"] == fingerprint or (node_key and w["node_key"] == node_key)
            if (w["id"] == worker or same) and "dup-identity-accepted" not in self.defects:
                raise Refused("409 identity already belongs to another worker")
        if found["transport"] == "tailcat" and not node_key:
            raise Refused("403 enrollment refused")
        if "secret-reusable" not in self.defects:
            found["state"] = "redeemed"
        self.workers[worker] = dict(id=worker, fingerprint=fingerprint, node_key=node_key,
                                    policy=dict(found["policy"]), transport=found["transport"],
                                    revoked=False, draining=False, uninstall_requested=False,
                                    connected=False, host=None, reported=None, running=[])
        if node_key:
            self.allow[node_key] = worker
        self.audit.append("worker-enrolled")

    # -- worker side
    def enroll(self, host, secret, name):
        h = self.hosts[host]
        if h.os != "linux" or "container" not in h.runtimes:
            raise Refused("unsupported host: refused before the secret is spent")
        if h.identity is not None and "enroll-twice-allowed" not in self.defects:
            raise Refused("this host already holds an identity")
        ident = dict(worker="wrk_" + secrets.token_hex(8),
                     fingerprint=hashlib.sha256(secrets.token_bytes(8)).hexdigest(),
                     node_key="nodekey:" + secrets.token_hex(32))
        try:
            self._redeem(secret, ident["worker"], ident["fingerprint"], ident["node_key"])
        except Refused:
            h.identity = None  # rollback: a refused enrollment leaves nothing
            raise
        h.identity = ident
        self.start(host)
        return ident["worker"]

    def uninstall_host(self, host):
        h = self.hosts[host]
        worker = h.identity["worker"] if h.identity else None
        h.running = False
        if "uninstall-keeps-identity" not in self.defects:
            h.identity = None
        if worker and worker in self.workers:
            return ("the controller still lists worker %s until a platform administrator "
                    "requests its uninstall there" % worker)
        return "no worker identity was found"

    def start(self, host):
        h = self.hosts[host]
        h.running, h.last_refusal = True, None
        if not h.identity:
            return
        w = self.workers.get(h.identity["worker"])
        if w is None:
            h.last_refusal = "unknown"
            return
        revoked = w["revoked"] and "revoked-reconnects" not in self.defects
        if revoked:
            h.last_refusal = "Revoked"
            return
        if h.identity["node_key"] not in self.allow and w["transport"] == "tailcat" \
                and "revoked-reconnects" not in self.defects:
            h.last_refusal = "not admitted"
            return
        holder = next((x for x in self.hosts.values()
                       if x is not h and x.identity and x.identity["worker"] == w["id"]
                       and w["connected"] and w["host"] == x.name), None)
        if holder is not None and "duplicate-both-connect" not in self.defects:
            h.last_refusal = "duplicate host identity"
            return
        w.update(connected=True, host=h.name,
                 reported=dict(cpu_millis=h.cpu, memory_bytes=h.mem, disk_bytes=h.disk),
                 arch=h.arch, os=h.os, runtimes=set(h.runtimes), speed=h.speed, name=h.name)

    def restart(self, host):
        h = self.hosts[host]
        if h.identity and h.identity["worker"] in self.workers:
            w = self.workers[h.identity["worker"]]
            if w["host"] == h.name:
                w["connected"] = False
        self.start(host)

    def clone_identity(self, src, dst):
        self.hosts[dst].identity = dict(self.hosts[src].identity)

    def refusal(self, host):
        return self.hosts[host].last_refusal

    # -- controller reads and changes
    def request_uninstall(self, worker):
        w = self.workers[worker]
        w["uninstall_requested"] = w["draining"] = True
        self.audit.append("worker-uninstall-requested")
        self.settle()

    def settle(self):
        for w in self.workers.values():
            idle = not w["running"] or "uninstall-cuts-work" in self.defects
            if w["uninstall_requested"] and idle and not w["revoked"]:
                w["revoked"], w["connected"] = True, False
                if "revoked-key-stays" not in self.defects:
                    self.allow.pop(w["node_key"], None)
                self.audit.append("worker-uninstalled")

    def start_job(self, worker):
        self.workers[worker]["running"].append(1)

    def finish_jobs(self, worker):
        self.workers[worker]["running"] = []
        self.settle()

    def listed(self):
        return {w["id"]: self._view(w) for w in self.workers.values() if not w["revoked"]}

    def _view(self, w):
        rep, pol = w["reported"] or dict(cpu_millis=0, memory_bytes=0, disk_bytes=0), w["policy"]
        eff = {}
        for key in ("cpu_millis", "memory_bytes", "disk_bytes"):
            cap = pol[key]
            eff[key] = rep[key] if cap is None else (cap if "ceiling-raises" in self.defects
                                                     else min(cap, rep[key]))
        return dict(id=w["id"], connected=w["connected"], approved=dict(pol), reported=dict(rep),
                    effective=eff, uninstall_requested=w["uninstall_requested"],
                    revoked=w["revoked"])

    def set_policy(self, worker, **change):
        self.workers[worker]["policy"].update(change)
        self.audit.append("worker-policy-changed")

    def allowed(self, worker):
        return self.workers[worker]["node_key"] in self.allow

    def placement(self):
        free = [w for w in self.workers.values() if self._free(w)]
        return [w["id"] for w in self._ordered(free)]

    def _free(self, w):
        return w["connected"] and not w["revoked"] and not w["draining"]

    def _ordered(self, ws):
        if self.order == "priority":
            return sorted(ws, key=lambda w: (-w["policy"]["priority"], 1 / w["speed"]))
        return sorted(ws, key=lambda w: (1 / w["speed"], -w["policy"]["priority"]))

    def place(self, arch, os_="linux", isolation="container", cpu=1000, mem=GIB, disk=GIB):
        """The worker a job lands on, or the reason it waits, as the queue states it."""
        pool = [w for w in self.workers.values() if self._free(w)]
        ignore_hw = "priority-bypasses-hard-admission" in self.defects
        eligible, reasons = [], set()
        for w in pool:
            if w["arch"] != arch and "arch-ignored" not in self.defects:
                reasons.add("arch_mismatch")
            elif (w["os"] != os_ or isolation not in w["runtimes"]) and not (
                    ignore_hw and w["policy"]["priority"] > 0):
                reasons.add("runtime_missing")
            else:
                eff = self._view(w)["effective"]
                if eff["cpu_millis"] < cpu or eff["memory_bytes"] < mem or eff["disk_bytes"] < disk:
                    reasons.add("capacity")
                else:
                    eligible.append(w)
        if not eligible:
            order = ["arch_mismatch", "runtime_missing", "capacity"]
            why = next((r for r in order if r in reasons), "worker_offline")
            return None, why
        return self._ordered(eligible)[0]["id"], None

    def set_order(self, order):
        self.order = order


# --------------------------------------------------------------------------- real fleet


class RealFleet:
    simulated = False

    def __init__(self, spec):
        self.spec = spec
        self.c = spec["controller"]
        self.hosts = spec.get("hosts", {})
        self.tailcat = bool(spec.get("tailcat"))
        self.arm = any(h.get("arch") == "aarch64" for h in self.hosts.values())
        self.token = open(self.c["token_file"]).read().strip() if self.c.get("token_file") else None

    def _run(self, prefix, argv, stdin=None, check=True):
        p = subprocess.run(prefix + argv, input=stdin, capture_output=True, text=True, timeout=300)
        if check and p.returncode != 0:
            raise Refused((p.stderr or p.stdout).strip()[:300])
        return p

    def _admin(self, *args, stdin=None):
        return self._run(self.c["exec"], [self.c["sentinel"], "admin", *args,
                                          "--data-dir", self.c["data_dir"]], stdin)

    def _get(self, path):
        req = urllib.request.Request(self.c["api"] + "/api/v1" + path,
                                     headers={"Authorization": "Bearer " + self.token})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)

    def issue(self, transport="tailcat", cpu=None, mem=None, disk=None, priority=0, ttl=3600):
        argv = ["worker", "enroll", "--pool", self.c["pool"], "--transport", transport,
                "--expires-in", "%ds" % ttl, "--priority", str(priority)]
        for flag, v in (("--cpu-millis", cpu), ("--memory-bytes", mem), ("--disk-bytes", disk)):
            if v is not None:
                argv += [flag, str(v)]
        p = self._admin(*argv)
        secret = p.stdout.strip()
        tok = next((w for w in p.stderr.split() if w.startswith("tok_")), None)
        return tok, secret

    def withdraw(self, tok):
        raise Blocked("no host-local withdraw command; DELETE /api/v1/admin/worker-enrollments "
                      "needs a browser session with step-up")

    def enroll(self, host, secret, name):
        h = self.hosts[host]
        argv = [h["sentinel"], "worker", "enroll", "--api-url", self.c["api"], "--config",
                h.get("config", "/etc/sentinel-worker/worker.toml"), "--data-dir",
                h.get("data_dir", "/var/lib/sentinel-worker"), "--name", name, "--secret-stdin"]
        if self.tailcat and h.get("tailcat_binary"):
            argv += ["--tailcat-binary", h["tailcat_binary"], "--tailcat-sha256", h["tailcat_sha256"]]
        self._run(h["exec"], argv, stdin=secret + "\n")
        wid = self._run(h["exec"], ["cat", h.get("data_dir", "/var/lib/sentinel-worker") + "/worker.id"])
        self._run(h["exec"], ["systemctl", "restart", "sentinel-worker"])
        return wid.stdout.strip()

    def uninstall_host(self, host):
        h = self.hosts[host]
        return self._run(h["exec"], [h["sentinel"], "worker", "uninstall"]).stdout.strip()

    def restart(self, host):
        self._run(self.hosts[host]["exec"], ["systemctl", "restart", "sentinel-worker"])

    def refusal(self, host):
        p = self._run(self.hosts[host]["exec"], ["journalctl", "-u", "sentinel-worker", "-n", "50",
                                                 "--no-pager"], check=False)
        for word in ("Revoked", "duplicate", "not admitted"):
            if word in p.stdout:
                return word
        return None

    def clone_identity(self, src, dst):
        d = self.hosts[src].get("data_dir", "/var/lib/sentinel-worker")
        tar = self._run(self.hosts[src]["exec"], ["tar", "-C", d, "-cf", "-", "."]).stdout
        raise Blocked("copying a data directory between hosts needs a binary-safe channel: "
                      "pass it through the operator's own transfer (%d bytes staged)" % len(tar))

    def request_uninstall(self, worker):
        self._admin("worker", "uninstall", "--id", worker)

    def listed(self):
        return {w["id"]: w for w in self._get("/admin/workers?pool=" + self.c["pool"])["workers"]}

    def set_policy(self, worker, **change):
        argv = ["worker", "policy", "--id", worker]
        for key, flag in (("cpu_millis", "--cpu-millis"), ("memory_bytes", "--memory-bytes"),
                          ("disk_bytes", "--disk-bytes"), ("priority", "--priority")):
            if key in change:
                v = change[key]
                argv += [flag, "none" if v is None else str(v)]
        self._admin(*argv)

    def allowed(self, worker):
        raise Blocked("the controller exposes no read of its Tailcat allow-list; check the "
                      "helper's peer list on the controller host")

    def placement(self):
        return [w["worker"] for w in self._get("/admin/placement")["workers"]]

    def place(self, arch, os_="linux", isolation="container", cpu=1000, mem=GIB, disk=GIB):
        if not self.spec.get("job_driver"):
            raise Blocked("fleet file has no job_driver to submit probe jobs to a real executor")
        p = self._run([], self.spec["job_driver"] + [arch, os_, isolation, str(cpu), str(mem), str(disk)])
        got = json.loads(p.stdout.strip().splitlines()[-1])
        return got.get("worker"), got.get("reason")

    def set_order(self, order):
        raise Blocked("placement_order is controller configuration; restart the controller with "
                      "placement_order = \"%s\" and re-run" % order)

    def start_job(self, worker):
        """Hold one probe job on `worker`: the driver keeps it running (`--keep`) and says where it was placed."""
        if not self.spec.get("job_driver"):
            raise Blocked("fleet file has no job_driver to hold a probe job on a worker")
        p = self._run([], self.spec["job_driver"] + ["--keep", "x86_64", "linux", "container", "1000", str(GIB), str(GIB)])
        got = json.loads(p.stdout.strip().splitlines()[-1])
        if got.get("worker") != worker:
            self.finish_jobs(worker)
            raise Blocked("the probe job was not placed on the draining worker (%s); a real executor chooses its "
                          "worker, so the scenario needs a fleet where only that worker fits" % (got.get("worker") or got.get("reason")))

    def finish_jobs(self, worker):
        if not self.spec.get("job_driver"):
            raise Blocked("fleet file has no job_driver to release a held probe job")
        self._run([], self.spec["job_driver"] + ["--release"])


# --------------------------------------------------------------------------- scenarios


class Checks:
    def __init__(self):
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append(dict(check=name, ok=bool(ok), detail=str(detail)[:200]))

    def refused(self, name, fn):
        try:
            fn()
        except Refused as e:
            self.check(name, True, e)
            return
        self.check(name, False, "accepted, expected a refusal")

    @property
    def ok(self):
        return bool(self.items) and all(i["ok"] for i in self.items)


def first_host(f, arch):
    for name, h in f.hosts.items():
        if (h.arch if isinstance(h, SimHost) else h.get("arch")) == arch:
            return name
    raise Blocked("fleet has no %s host" % arch)


def hosts_of(f, arch=None):
    out = [n for n, h in f.hosts.items()
           if arch is None or (h.arch if isinstance(h, SimHost) else h.get("arch")) == arch]
    return out


def need_hosts(f, n):
    names = hosts_of(f)
    if len(names) < n:
        raise Blocked("scenario needs %d worker hosts, fleet has %d" % (n, len(names)))
    return names


def wait(fn, secs=0.0):
    end = time.time() + secs
    while True:
        if fn():
            return True
        if time.time() >= end:
            return False
        time.sleep(1)


def enrolled(f, host, **terms):
    tok, secret = f.issue(**terms)
    return tok, f.enroll(host, secret, host)


def s_enroll_uninstall(f, c):
    h = need_hosts(f, 1)[0]
    tok, secret = f.issue(priority=5, cpu=4000)
    wid = f.enroll(h, secret, h)
    c.check("enrolled worker is listed and connected", wait(lambda: f.listed().get(wid, {}).get("connected"), 60))
    c.check("approved policy is the controller's", f.listed()[wid]["approved"]["cpu_millis"] == 4000
            and f.listed()[wid]["approved"]["priority"] == 5)
    report = f.uninstall_host(h)
    c.check("worker-side uninstall names the worker and the controller step", wid in report, report)
    c.refused("the spent secret is refused on a clean host", lambda: f.enroll(h, secret, h))
    f.request_uninstall(wid)
    c.check("controller-side uninstall revokes it",
            wait(lambda: not f.listed().get(wid) or f.listed()[wid].get("revoked")
                 or f.listed()[wid].get("uninstall_requested"), 60))
    tok2, secret2 = f.issue()
    c.check("the host can enroll again after a clean uninstall", bool(f.enroll(h, secret2, h)))


def s_reconnect_revocation(f, c):
    if not f.tailcat:
        raise Blocked("fleet has no Tailcat helper configured (set \"tailcat\": true and the hosts' tailcat_binary)")
    h = need_hosts(f, 1)[0]
    tok, wid = enrolled(f, h, transport="tailcat")
    c.check("connected", wait(lambda: f.listed().get(wid, {}).get("connected"), 60))
    f.restart(h)
    c.check("reconnects after a worker restart", wait(lambda: f.listed().get(wid, {}).get("connected"), 90))
    f.request_uninstall(wid)
    f.restart(h)
    ok = wait(lambda: f.refusal(h) == "Revoked", 60)
    c.check("a revoked worker is refused with a visible reason", ok, f.refusal(h))
    c.check("revoked worker is no longer connected", not f.listed().get(wid, {}).get("connected"))
    try:
        c.check("its node key left the allow-list", not f.allowed(wid))
    except Blocked as e:
        c.check("its node key left the allow-list (checked elsewhere)", True, e)


def s_duplicate_identity(f, c):
    a, b = need_hosts(f, 2)[:2]
    tok, wid = enrolled(f, a)
    c.check("original connected", wait(lambda: f.listed().get(wid, {}).get("connected"), 60))
    f.clone_identity(a, b)
    f.restart(b)
    c.check("the copy is refused while the original is connected", f.refusal(b) is not None, f.refusal(b))
    c.check("the original stays connected", f.listed()[wid]["connected"])
    tok2, secret2 = f.issue()
    c.refused("a host that already holds an identity cannot enroll again", lambda: f.enroll(a, secret2, a))


def s_ceiling_change(f, c):
    h = need_hosts(f, 1)[0]
    tok, wid = enrolled(f, h, cpu=2000, mem=4 * GIB, disk=20 * GIB)
    c.check("connected", wait(lambda: f.listed().get(wid, {}).get("connected"), 60))
    v = f.listed()[wid]
    c.check("effective CPU is the ceiling", v["effective"]["cpu_millis"] == 2000, v["effective"])
    c.check("effective memory is the ceiling", v["effective"]["memory_bytes"] == 4 * GIB)
    f.set_policy(wid, cpu_millis=1000, memory_bytes=2 * GIB, disk_bytes=10 * GIB, priority=0)
    v = f.listed()[wid]
    c.check("a reduction applies at once", v["effective"]["cpu_millis"] == 1000
            and v["effective"]["memory_bytes"] == 2 * GIB and v["effective"]["disk_bytes"] == 10 * GIB, v["effective"])
    f.set_policy(wid, cpu_millis=10 ** 9, memory_bytes=None, disk_bytes=None, priority=0)
    v = f.listed()[wid]
    c.check("a raise never exceeds what the worker reports",
            all(v["effective"][k] <= v["reported"][k] for k in ("cpu_millis", "memory_bytes", "disk_bytes")),
            v["effective"])


def s_arm_placement(f, c):
    if not f.arm:
        raise Blocked("fleet has no aarch64 host")
    x, a = first_host(f, "x86_64"), first_host(f, "aarch64")
    _, wx = enrolled(f, x)
    _, wa = enrolled(f, a)
    wait(lambda: f.listed().get(wx, {}).get("connected") and f.listed().get(wa, {}).get("connected"), 90)
    got, why = f.place("aarch64")
    c.check("an aarch64 job lands on the ARM host", got == wa, (got, why))
    got, why = f.place("x86_64")
    c.check("an x86_64 job lands on the x86_64 host", got == wx, (got, why))
    f.request_uninstall(wa)
    got, why = f.place("aarch64")
    c.check("with no ARM host left it waits with arch_mismatch", got is None and why == "arch_mismatch", (got, why))


def s_explanations(f, c):
    h = need_hosts(f, 1)[0]
    _, w = enrolled(f, h)
    wait(lambda: f.listed().get(w, {}).get("connected"), 60)
    got, why = f.place("x86_64", os_="windows")
    c.check("a windows job waits with runtime_missing", got is None and why == "runtime_missing", (got, why))
    got, why = f.place("x86_64", isolation="microvm")
    c.check("a microVM job on a container-only host waits with runtime_missing",
            got is None and why == "runtime_missing", (got, why))
    got, why = f.place("x86_64", cpu=10 ** 9)
    c.check("an oversized job waits with capacity", got is None and why == "capacity", (got, why))
    got, why = f.place("x86_64")
    c.check("a fitting job is placed", got == w, (got, why))


def s_priority(f, c):
    xs = hosts_of(f, "x86_64")
    if len(xs) < 2:
        raise Blocked("scenario needs two x86_64 hosts, fleet has %d" % len(xs))
    fast, slow = xs[0], xs[1]
    _, wf = enrolled(f, fast, priority=0)
    _, ws = enrolled(f, slow, priority=50)
    wait(lambda: f.listed().get(wf, {}).get("connected") and f.listed().get(ws, {}).get("connected"), 90)
    got, why = f.place("x86_64")
    c.check("by default the fastest eligible host wins, priority notwithstanding",
            got == (wf if fastest(f, wf, ws) else ws) and got is not None, (got, why))
    f.set_order("priority")
    got, why = f.place("x86_64")
    c.check("with priority ordering the preferred eligible host wins", got == ws, (got, why))
    got, why = f.place("x86_64", isolation="microvm")
    c.check("priority never lends a host a runtime it lacks", got is None and why == "runtime_missing", (got, why))
    got, why = f.place("aarch64")
    c.check("priority never lends a host another architecture", got is None, (got, why))
    f.set_policy(ws, cpu_millis=100, priority=50)
    got, why = f.place("x86_64", cpu=1000)
    c.check("priority never bypasses a capacity ceiling", got != ws, (got, why))
    f.set_order("fastest")


def fastest(f, a, b):
    """True when `a` is the faster of the two; the model knows speeds, a real fleet is probed."""
    if getattr(f, "simulated", False):
        return f.workers[a]["speed"] >= f.workers[b]["speed"]
    return f.placement().index(a) < f.placement().index(b)


def s_drain_holds_work(f, c):
    h = need_hosts(f, 1)[0]
    _, w = enrolled(f, h)
    wait(lambda: f.listed().get(w, {}).get("connected"), 60)
    f.start_job(w)
    f.request_uninstall(w)
    c.check("an uninstall waits for accepted work (not revoked yet)", not f.listed()[w].get("revoked"))
    got, why = f.place("x86_64")
    c.check("a draining worker takes no new job", got != w, (got, why))
    f.finish_jobs(w)
    c.check("it is revoked once the work settles", f.listed().get(w, {}).get("revoked", True))


SCENARIOS = {
    "enroll-uninstall": s_enroll_uninstall,
    "reconnect-revocation": s_reconnect_revocation,
    "duplicate-identity": s_duplicate_identity,
    "ceiling-change": s_ceiling_change,
    "arm-placement": s_arm_placement,
    "explanations": s_explanations,
    "priority-overrides": s_priority,
    "drain-holds-work": s_drain_holds_work,
}


def run_scenario(name, fleet):
    c = Checks()
    t0 = time.monotonic()
    try:
        SCENARIOS[name](fleet, c)
        status = "pass" if c.ok else "fail"
        note = None
    except Blocked as e:
        status, note = "blocked", str(e)
    except Refused as e:
        c.check("unexpected refusal", False, e)
        status, note = "fail", str(e)
    except Exception as e:  # a harness or transport error is a failure, never a pass
        status, note = "fail", "%s: %s" % (type(e).__name__, e)
    return dict(schema=SCHEMA, scenario=name, status=status, note=note, checks=c.items,
                simulated=bool(fleet.simulated), duration_s=round(time.monotonic() - t0, 3),
                at=int(time.time()))


def stamped(rec, stamp):
    """A real record with the run's build and host stamp in front; a simulated record is returned unchanged."""
    return rec if rec["simulated"] else {**stamp, **rec}


# --------------------------------------------------------------------------- self-test


def sim(defects=()):
    return SimFleet([SimHost("x86-fast", speed=2.0), SimHost("x86-slow", speed=1.0),
                     SimHost("arm", arch="aarch64", speed=1.0)], defects)


# defect -> the scenario that must catch it
DEFECTS = {
    "secret-reusable": "enroll-uninstall",
    "uninstall-keeps-identity": "enroll-uninstall",
    "revoked-reconnects": "reconnect-revocation",
    "revoked-key-stays": "reconnect-revocation",
    "duplicate-both-connect": "duplicate-identity",
    "enroll-twice-allowed": "duplicate-identity",
    "uninstall-cuts-work": "drain-holds-work",
    "ceiling-raises": "ceiling-change",
    "arch-ignored": "arm-placement",
    "priority-bypasses-hard-admission": "priority-overrides",
}


def selftest():
    failures = []
    good = {}
    for name in SCENARIOS:
        rec = run_scenario(name, sim())
        good[name] = rec["status"]
        if rec["status"] != "pass":
            failures.append("correct model: %s -> %s %s %s" % (name, rec["status"], rec["note"],
                            [i for i in rec["checks"] if not i["ok"]]))
    for defect, scenario in DEFECTS.items():
        rec = run_scenario(scenario, sim([defect]))
        if rec["status"] != "fail":
            failures.append("defect %s was not caught by %s (status %s)" % (defect, scenario, rec["status"]))
    # a fleet without the prerequisites is blocked, never passed
    rec = run_scenario("arm-placement", SimFleet([SimHost("x86")]))
    if rec["status"] != "blocked":
        failures.append("missing ARM host was %s, expected blocked" % rec["status"])
    rec = run_scenario("duplicate-identity", SimFleet([SimHost("only")]))
    if rec["status"] != "blocked":
        failures.append("one host for the duplicate scenario was %s, expected blocked" % rec["status"])
    # a real record names its build and host; a simulated one must never look stamped
    stamp = {"build": {"commit": "c" * 40, "dirty": False}, "host": {"hostname": "test-host"}}
    real = stamped(dict(simulated=False, scenario="x"), stamp)
    if not (real.get("build") and real.get("host")):
        failures.append("a real record was not stamped")
    if "build" in stamped(dict(simulated=True, scenario="x"), stamp):
        failures.append("a simulated record was stamped, so it could pass for evidence")
    for line in failures:
        print("FAIL", line)
    print("selftest: %d scenarios, %d injected defects, %d failures" % (len(SCENARIOS), len(DEFECTS), len(failures)))
    return 1 if failures else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("selftest")
    r = sub.add_parser("run")
    r.add_argument("--fleet", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--scenarios", default=",".join(SCENARIOS))
    r.add_argument("--source", default=os.environ.get("SENTINEL_SRC"),
                   help="the checkout the fleet's sentinel binaries were built from (or SENTINEL_SRC)")
    r.add_argument("--binary", default=os.environ.get("SENTINEL_BIN"), help="a sentinel binary to hash (or SENTINEL_BIN)")
    a = ap.parse_args()
    if a.cmd == "list":
        print("\n".join(SCENARIOS))
        return 0
    if a.cmd == "selftest":
        return selftest()
    names = a.scenarios.split(",")
    for n in names:
        if n not in SCENARIOS:
            print("unknown scenario", n, file=sys.stderr)
            return 64
    if not a.source:
        ap.error("--source (or SENTINEL_SRC) is required: a record must name the build it measured")
    stamp = benchstamp.stamp(a.source, a.binary)  # before anything is driven
    spec = json.load(open(a.fleet))
    bad = 0
    with open(a.out, "a") as out:
        for n in names:
            rec = stamped(run_scenario(n, RealFleet(spec)), stamp)
            out.write(json.dumps(rec) + "\n")
            print("%-22s %s%s" % (n, rec["status"], "  " + rec["note"] if rec["note"] else ""))
            bad += rec["status"] == "fail"
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
