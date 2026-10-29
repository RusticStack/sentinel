#!/usr/bin/env python3
"""The job driver bench/q13-fleet.py's fleet file names (`job_driver`): it creates the harness's only jobs.

    python3 bench/q13-job.py --config JOB.json ARCH OS ISOLATION CPU_MILLIS MEMORY_BYTES DISK_BYTES [--keep]
    python3 bench/q13-job.py --config JOB.json --release

It pushes a one-job probe pipeline whose `runs_on` and `resources` are the arguments to a bound repository, posts
the intake delivery, and answers where the run was placed. It prints one JSON line

    {"worker": "wrk_..."|null, "reason": "..."|null}

`worker` is the worker that took the probe (the one whose `held_attempts` grew in `GET /workers`), `reason` the queue
reason (`GET /queue`) the probe waits with when nothing takes it within `wait_s`. Every API or Git failure exits 2
with one line on stderr and prints nothing: an unreachable controller is never reported as "no worker". A probe that
was placed is cancelled again unless `--keep` (the harness's drain scenario keeps one running); `--release` cancels
every kept probe. A probe whose placement cannot be told, or whose `--keep` cannot be recorded, is cancelled before the
failure is reported, so a `sleep` job never starts later and holds a worker in the next scenario. Git's own messages
are printed with any `user:secret@` part of a URL removed.

JOB.json: {"api": "https://controller.example/api/v1", "token_file": "...", "hook_token_file": "...",
           "tenant": "slug", "repo_id": "repo_...", "repo_name": "probe", "git_work": "/path/to/clone",
           "git_remote": "bench", "image": "docker.io/library/busybox@sha256:...", "wait_s": 20, "hold_s": 300,
           "state_file": "/path/to/kept-runs.json"}
The tokens are read from files and never printed. The Git clone must have the repository's remote configured.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
IDENT = ["-c", "user.name=q13-job", "-c", "user.email=q13-job@example.invalid", "-c", "commit.gpgsign=false"]
MIB = 1 << 20


class Failure(Exception):
    pass


CREDENTIAL_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]*@")


def redact(text):
    """Git echoes the remote it failed on, and a remote may carry `user:secret@`: drop everything before the `@`."""
    return CREDENTIAL_URL.sub(lambda m: m.group(1) + "***@", text)


def need(cfg, *keys):
    missing = [k for k in keys if not cfg.get(k)]
    if missing:
        raise Failure(f"job config lacks {', '.join(missing)}")


def read_token(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        raise Failure(f"cannot read a token file: {e.strerror}")


def call(cfg, method, path, body=None, token_key="token_file", token=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(cfg["api"].rstrip("/") + path, data=data, method=method)
    req.add_header("authorization", "Bearer " + (token or read_token(cfg[token_key])))
    if data is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raise Failure(f"{method} {path.split('?')[0]} answered {e.code}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise Failure(f"{method} {path.split('?')[0]} failed: {type(e).__name__}")


def pipeline(cfg, arch, os_, isolation, cpu, mem, disk):
    if arch not in ARCH:
        raise Failure(f"unknown arch {arch!r} (x86_64 or aarch64)")
    cpu_s = f"{int(cpu) / 1000:g}"
    return (f"schema: 1\non: [push]\njobs:\n  probe:\n    image: {cfg['image']}\n"
            f"    runs_on: {{arch: {ARCH[arch]}, os: {os_}, isolation: {isolation}}}\n"
            f"    resources: {{ cpu: \"{cpu_s}\", memory: {max(1, int(mem) // MIB)}MiB, disk: {max(1, int(disk) // MIB)}MiB }}\n"
            f"    timeout: 10m\n    steps:\n      - id: hold\n        run: sleep {int(cfg.get('hold_s', 300))}\n")


def git(cfg, *args, stdin=None):
    r = subprocess.run(["git", *IDENT, "-C", cfg["git_work"], *args], input=stdin, capture_output=True, text=True)
    if r.returncode != 0:
        raise Failure(f"git {args[0]} failed: {redact(r.stderr.strip())[:200]}")
    return r.stdout.strip()


def push_probe(cfg, yml):
    """A commit on its own ref carrying `yml` as the pipeline, pushed to the bound remote; returns (ref, sha)."""
    work = cfg["git_work"]
    idx = os.path.join(work, ".git", f"q13-index-{uuid.uuid4().hex[:8]}")
    env = dict(os.environ, GIT_INDEX_FILE=idx)
    try:
        def plumb(*a, stdin=None):
            r = subprocess.run(["git", *IDENT, "-C", work, *a], input=stdin, capture_output=True, text=True, env=env)
            if r.returncode != 0:
                raise Failure(f"git {a[0]} failed: {redact(r.stderr.strip())[:200]}")
            return r.stdout.strip()
        plumb("read-tree", "HEAD")
        blob = plumb("hash-object", "-w", "--stdin", stdin=yml)
        plumb("update-index", "--add", "--cacheinfo", f"100644,{blob},.sentinel.yml")
        tree = plumb("write-tree")
    finally:
        if os.path.exists(idx):
            os.unlink(idx)
    base = git(cfg, "rev-parse", "HEAD")
    sha = git(cfg, "commit-tree", tree, "-p", base, "-m", "q13 probe")
    ref = f"refs/heads/q13-{uuid.uuid4().hex[:10]}"
    git(cfg, "update-ref", ref, sha)
    try:
        git(cfg, "push", "-q", cfg["git_remote"], f"{ref}:{ref}")
    finally:
        subprocess.run(["git", "-C", work, "update-ref", "-d", ref], capture_output=True)
    return ref, sha


def held(cfg):
    _s, body = call(cfg, "GET", f"/workers?tenant={cfg['tenant']}")
    return {w["id"]: int(w.get("held_attempts") or 0) for w in body.get("workers", []) if "id" in w}


def lookup_run(cfg, sha):
    _s, body = call(cfg, "GET", f"/tenants/{cfg['tenant']}/repos/{cfg['repo_name']}/runs?sha={sha}&limit=1")
    runs = body.get("runs") or []
    return runs[0]["id"] if runs else None


def cancel_quietly(cfg, run):
    """Best effort on a failure path: the original failure is what gets reported, not a failed clean-up."""
    try:
        call(cfg, "POST", f"/runs/{run}/cancel", {})
    except Failure:
        pass


def find_run(cfg, sha, wait_s):
    deadline = time.monotonic() + wait_s
    while True:
        run = lookup_run(cfg, sha)
        if run:
            return run
        if time.monotonic() > deadline:
            raise Failure("the intake delivery produced no run within the wait")
        time.sleep(0.25)


def place(cfg, arch, os_, isolation, cpu, mem, disk, keep=False):
    need(cfg, "api", "token_file", "hook_token_file", "tenant", "repo_id", "repo_name", "git_work", "git_remote", "image")
    wait_s = float(cfg.get("wait_s", 20))
    before = held(cfg)
    ref, sha = push_probe(cfg, pipeline(cfg, arch, os_, isolation, cpu, mem, disk))
    call(cfg, "POST", f"/intake/{cfg['repo_id']}", {"delivery_id": f"q13-{uuid.uuid4().hex}", "ref": ref,
                                                     "old_sha": "0" * 40, "new_sha": sha}, token_key="hook_token_file")
    try:
        run = find_run(cfg, sha, wait_s)
    except Failure:
        # The delivery may still produce the run after the wait: one last look, so a late probe does not hold a worker.
        try:
            late = lookup_run(cfg, sha)
        except Failure:
            late = None
        if late:
            cancel_quietly(cfg, late)
        raise
    settled = False  # the probe is kept (recorded for --release) or cancelled; anything else cancels it below
    try:
        out = placement(cfg, run, before, wait_s)
        if keep:
            record_kept(cfg, run)
        else:
            call(cfg, "POST", f"/runs/{run}/cancel", {})
        settled = True
        return out
    finally:
        if not settled:
            cancel_quietly(cfg, run)


def placement(cfg, run, before, wait_s):
    deadline = time.monotonic() + wait_s
    worker = reason = None
    while time.monotonic() < deadline:
        now = held(cfg)
        grown = [w for w, n in now.items() if n > before.get(w, 0)]
        if grown:
            worker = sorted(grown)[0]
            break
        time.sleep(0.25)
    if worker is None:
        _s, q = call(cfg, "GET", f"/queue?tenant={cfg['tenant']}&limit=500")
        mine = [j for j in q.get("jobs", []) if j.get("run") == run]
        if not mine:
            raise Failure("the probe is neither on a worker nor in the queue; its placement cannot be told")
        r = mine[0].get("reason")
        reason = r.get("code") if isinstance(r, dict) else r
    return {"worker": worker, "reason": reason}


def record_kept(cfg, run):
    kept = []
    path = cfg.get("state_file")
    if not path:
        raise Failure("--keep needs state_file in the job config, so --release can find the run")
    try:
        with open(path) as f:
            kept = json.load(f)
    except (OSError, ValueError):
        pass
    try:
        with open(path, "w") as f:
            json.dump(kept + [run], f)
    except OSError as e:
        raise Failure(f"cannot record the kept run: {e.strerror}") from None


def release(cfg):
    need(cfg, "api", "token_file", "state_file")
    try:
        with open(cfg["state_file"]) as f:
            kept = json.load(f)
    except (OSError, ValueError):
        kept = []
    for run in kept:
        call(cfg, "POST", f"/runs/{run}/cancel", {})
    with open(cfg["state_file"], "w") as f:
        json.dump([], f)
    return {"released": len(kept)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True)
    ap.add_argument("--release", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("probe", nargs="*", help="ARCH OS ISOLATION CPU_MILLIS MEMORY_BYTES DISK_BYTES")
    a = ap.parse_args(argv)
    try:
        with open(a.config) as f:
            cfg = json.load(f)
        if a.release:
            out = release(cfg)
        else:
            if len(a.probe) != 6:
                ap.error("expected ARCH OS ISOLATION CPU_MILLIS MEMORY_BYTES DISK_BYTES")
            out = place(cfg, *a.probe, keep=a.keep)
    except (OSError, ValueError) as e:
        print(f"q13-job: cannot read the job config: {e}", file=sys.stderr)
        return 2
    except Failure as e:
        print(f"q13-job: {e}", file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
