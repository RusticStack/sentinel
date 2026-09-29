#!/usr/bin/env python3
"""B03: measure the plan's latency budgets on a real controller and worker.

    python3 bench/b03-latency.py ROOT OUT [--first N] [--logs N] [--cancel N]
                                           [--failure N] [--queries N] [--cache N]

ROOT is a deployment bench/b03-setup.sh started. Every sample is a real push
to one of the fixture's branches and a real intake event; nothing is
simulated. Clocks: the worker, controller and this driver share one host,
so wall-clock differences between them are meaningful at millisecond
resolution (the store's timestamps are milliseconds). One JSON line per
sample is appended to OUT; a summary goes to stderr.

Budgets (plan.md section 12):
  intake_ack         POST /intake -> 202, client-timed (every sample)
  ready_to_offer     attempts.offered_ms - jobs.queued_ms, idle capacity
  offer_to_ack       attempts.acked_ms - attempts.offered_ms
  ready_to_first     the first user process's own clock - jobs.queued_ms
  log_visible        a line's capture time -> received by a follow client
  cancel_to_end      POST cancel -> the job terminal (wait API)
  failure_query      GET /attempts/{id}/failure on a 100 MiB log
  cache_prepare      lookup + lock wait + clone of a fixed 64 MiB fixture
"""
import argparse
import json
import math
import os
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

IDENT = ["-c", "user.name=sentinel-bench", "-c", "user.email=bench@sentinel.invalid"]


class Deployment:
    def __init__(self, root):
        self.root = root
        read = lambda name: open(os.path.join(root, name)).read().strip()
        self.api = f"http://{read('api.addr')}/api/v1"
        self.token = read("token")
        self.hook = read("hook")
        self.repo = read("repo")
        self.work = os.path.join(root, "work")
        self.bare = os.path.join(root, "git", "probe")
        self.db = os.path.join(root, "controller", "metadata.sqlite")

    def call(self, method, path, body=None, token=None, timeout=60):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.api + path, data=data, method=method)
        req.add_header("authorization", f"Bearer {token or self.token}")
        if data is not None:
            req.add_header("content-type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, raw

    def get(self, path, timeout=60):
        return json.loads(self.call("GET", path, timeout=timeout)[1])

    def settle(self, below=2.0, limit=600):
        for _ in range(limit // 5):
            line = next(l for l in open("/proc/pressure/cpu") if l.startswith("some"))
            avg60 = float(line.split()[2].split("=")[1])
            if avg60 < below:
                return avg60
            time.sleep(5)
        raise SystemExit("the host did not settle")

    def git(self, *args):
        return subprocess.run(["git", *IDENT, "-C", self.work, *args], check=True,
                              capture_output=True, text=True).stdout.strip()

    def push(self, branch):
        """A fresh commit on `branch`, pushed; the intake event, timed."""
        self.git("checkout", "-q", branch)
        old = subprocess.run(["git", "-C", self.bare, "rev-parse", f"refs/heads/{branch}"],
                             check=True, capture_output=True, text=True).stdout.strip()
        self.git("commit", "-q", "--allow-empty", "-m", f"b03 {branch}")
        self.git("push", "-q", "bench", f"{branch}:{branch}")
        new = self.git("rev-parse", "HEAD")
        body = {"delivery_id": f"b03-{time.time_ns()}", "ref": f"refs/heads/{branch}",
                "old_sha": old, "new_sha": new}
        t0 = time.monotonic_ns()
        status, raw = self.call("POST", f"/intake/{self.repo}", body, token=self.hook)
        ack_ns = time.monotonic_ns() - t0
        if status != 202:
            raise SystemExit(f"intake answered {status}")
        delivery = json.loads(raw)["delivery"]
        return delivery, ack_ns, time.time_ns()

    def run_of(self, delivery, limit_s=60):
        """The run the intake lane dispatched for `delivery` (server log)."""
        log = os.path.join(self.root, "server.log")
        deadline = time.monotonic() + limit_s
        while time.monotonic() < deadline:
            with open(log, errors="replace") as f:
                for line in f:
                    if delivery in line and "dispatched:run_" in line:
                        return line.split("dispatched:")[1].split('"')[0]
            time.sleep(0.02)
        raise SystemExit(f"no run for {delivery}")

    def wait_finished(self, run, limit_s=1800):
        since, deadline = None, time.monotonic() + limit_s
        while time.monotonic() < deadline:
            q = f"/runs/{run}/wait?timeout_ms=25000" + (f"&since={since}" if since else "")
            body = self.get(q, timeout=40)
            if body["finished"]:
                return body["run"]
            since = body["version"]
        raise SystemExit(f"run {run} did not finish")

    def wait_state(self, run, states, limit_s=300):
        since, deadline = None, time.monotonic() + limit_s
        while time.monotonic() < deadline:
            q = f"/runs/{run}/wait?timeout_ms=25000" + (f"&since={since}" if since else "")
            body = self.get(q, timeout=40)
            job = body["run"]["jobs"][0]
            if job["state"] in states:
                return body["run"]
            since = body["version"]
        raise SystemExit(f"run {run} never reached {states}")

    def stamps(self, run):
        """queued_ms, offered_ms, acked_ms of the run's (only) job."""
        con = sqlite3.connect(f"file:{self.db}?mode=ro", uri=True, timeout=10)
        try:
            row = con.execute(
                """SELECT j.queued_ms, a.offered_ms, a.acked_ms
                   FROM jobs j JOIN runs r ON r.id = j.run_id
                   JOIN attempts a ON a.job_id = j.id
                   WHERE r.id = ? ORDER BY a.fence DESC LIMIT 1""",
                (run_bytes(run),)).fetchone()
        finally:
            con.close()
        return row


def run_bytes(run):
    """`run_<uuid>` as the 16 bytes the store keys it by."""
    return bytes.fromhex(run.removeprefix("run_").replace("-", ""))


def emit(out, **record):
    out.write(json.dumps({"schema": "sentinel-bench/b03/1", **record}, separators=(",", ":")) + "\n")
    out.flush()


def logs_of(d, attempt, step=None):
    frames, after = [], None
    while True:
        q = f"/attempts/{attempt}/logs?limit=500" + (f"&after={after}" if after is not None else "")
        body = d.get(q)
        frames += body["frames"]
        if body.get("next_after") is None:
            return frames
        after = body["next_after"]


def first(d, out, n):
    for i in range(n):
        pressure = d.settle()
        delivery, ack_ns, _ = d.push("first")
        run = d.run_of(delivery)
        done = d.wait_finished(run)
        job = done["jobs"][0]
        queued, offered, acked = d.stamps(run)
        text = "".join(f["text"] for f in logs_of(d, job["attempt"]))
        first_ns = int(next(l for l in text.splitlines() if l.strip().isdigit()))
        emit(out, budget="first", sample=i, run=run, state=job["state"], cpu_pressure_avg60=pressure,
             intake_ack_ns=ack_ns, queued_ms=queued, offered_ms=offered, acked_ms=acked,
             ready_to_offer_ms=offered - queued, offer_to_ack_ms=acked - offered,
             ready_to_first_ms=first_ns / 1e6 - queued)
        print(f"first {i}: offer {offered - queued} ms, ack {acked - offered} ms, first process {first_ns / 1e6 - queued:.0f} ms", file=sys.stderr)


def logs(d, out, n):
    for i in range(n):
        pressure = d.settle()
        delivery, ack_ns, _ = d.push("logs")
        run = d.run_of(delivery)
        running = d.wait_state(run, {"running", "preparing", "finalizing", "passed", "failed"})
        attempt = running["jobs"][0]["attempt"]
        lat, after, complete = [], None, False
        while not complete:
            q = f"/attempts/{attempt}/logs?wait=1&limit=500" + (f"&after={after}" if after is not None else "")
            try:
                body = d.get(q, timeout=40)
            except urllib.error.HTTPError as e:
                # The attempt's log does not exist until its first frame;
                # lines captured meanwhile count as visible later.
                if e.code != 404:
                    raise
                time.sleep(0.02)
                continue
            now = time.time_ns()
            for f in body["frames"]:
                for line in f["text"].splitlines():
                    if line.startswith("t="):
                        lat.append((now - int(line[2:])) / 1e6)
            complete = body.get("complete", False)
            after = body.get("next_after") if body.get("next_after") is not None else (
                body["frames"][-1]["seq"] if body["frames"] else after)
        d.wait_finished(run)
        emit(out, budget="logs", sample=i, run=run, cpu_pressure_avg60=pressure, intake_ack_ns=ack_ns,
             lines=len(lat), log_visible_ms=lat)
        print(f"logs {i}: {len(lat)} lines, median {sorted(lat)[len(lat) // 2]:.1f} ms", file=sys.stderr)


def cancel(d, out, n):
    for i in range(n):
        pressure = d.settle()
        delivery, ack_ns, _ = d.push("cancel")
        run = d.run_of(delivery)
        d.wait_state(run, {"running"})
        time.sleep(1)  # the step is under way
        t0 = time.monotonic_ns()
        d.call("POST", f"/runs/{run}/cancel", {})
        done = d.wait_finished(run)
        took = (time.monotonic_ns() - t0) / 1e6
        emit(out, budget="cancel", sample=i, run=run, state=done["jobs"][0]["state"],
             cpu_pressure_avg60=pressure, intake_ack_ns=ack_ns, cancel_to_end_ms=took)
        print(f"cancel {i}: {took:.0f} ms -> {done['jobs'][0]['state']}", file=sys.stderr)


def failure(d, out, n, queries):
    for i in range(n):
        pressure = d.settle()
        delivery, ack_ns, _ = d.push("failure")
        run = d.run_of(delivery)
        done = d.wait_finished(run)
        attempt = done["jobs"][0]["attempt"]
        lat, sizes, text_bytes = [], [], []
        for _ in range(queries):
            t0 = time.monotonic_ns()
            status, raw = d.call("GET", f"/attempts/{attempt}/failure")
            lat.append((time.monotonic_ns() - t0) / 1e6)
            sizes.append(len(raw))
            body = json.loads(raw)
            text_bytes.append(len(json.dumps(body.get("tail") or "")))
        found = "the needle" in raw.decode(errors="replace")
        emit(out, budget="failure", sample=i, run=run, state=done["jobs"][0]["state"],
             cpu_pressure_avg60=pressure, intake_ack_ns=ack_ns, failure_query_ms=lat,
             response_bytes=sizes, tail_text_bytes=text_bytes, found_the_failure=found)
        print(f"failure {i}: median {sorted(lat)[len(lat) // 2]:.1f} ms, {max(sizes)} bytes, found={found}", file=sys.stderr)


def cache(d, out, n):
    for i in range(n + 1):
        pressure = d.settle()
        delivery, ack_ns, _ = d.push("cache")
        run = d.run_of(delivery)
        done = d.wait_finished(run)
        attempt = done["jobs"][0]["attempt"]
        summary = d.get(f"/attempts/{attempt}/summary")
        c = summary["caches"][0]
        prep = (c.get("lookup_ns") or 0) + (c.get("lock_wait_ns") or 0) + (c.get("clone_ns") or 0)
        emit(out, budget="cache", sample=i, seed=i == 0, run=run, state=done["jobs"][0]["state"],
             cpu_pressure_avg60=pressure, intake_ack_ns=ack_ns, outcome=c["outcome"],
             cache_prepare_ms=prep / 1e6, files=c.get("files"), bytes=c.get("bytes"),
             reflink=c.get("reflink"), cache=c)
        print(f"cache {i}: {c['outcome']} {prep / 1e6:.1f} ms, {c.get('files')} files, reflink={c.get('reflink')}", file=sys.stderr)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("out")
    for name, default in [("first", 200), ("logs", 10), ("cancel", 30), ("failure", 3), ("queries", 50), ("cache", 30)]:
        p.add_argument(f"--{name}", type=int, default=default)
    a = p.parse_args()
    d = Deployment(a.root)
    with open(a.out, "a") as out:
        first(d, out, a.first)
        logs(d, out, a.logs)
        cancel(d, out, a.cancel)
        cache(d, out, a.cache)
        failure(d, out, a.failure, a.queries)
    print("b03 done", file=sys.stderr)


if __name__ == "__main__":
    main()
