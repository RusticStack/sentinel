#!/usr/bin/env python3
"""B03b: where does the durable webhook ACK spend its time?

    python3 bench/b03b-ack.py ROOT OUT --source CHECKOUT [--binary SENTINEL] [-n N]

ROOT is a deployment bench/b03-setup.sh started (controller and worker idle).
Each probe is timed on one raw socket in phases, on the monotonic clock:
connect, send, first response byte, whole response. Probes, interleaved in
a shuffled order so drift does not align with a kind:

  intake_new     POST /intake/{repo} with a new delivery, a fresh connection
  intake_keep    the same on one kept-alive connection
  intake_dup     the same delivery again (a duplicate: no commit, no wake)
  refused        POST /intake/{repo} with a wrong secret (401: no store write)
  ready          GET /api/v1/ready (a store read and a commit probe)
  health         GET /api/v1/health (no store)

The deliveries use refs that match no branch the fixture has a pipeline for,
so the controller resolves and drops them; the worker stays idle.
"""
import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util

spec = importlib.util.spec_from_file_location("b03", os.path.join(os.path.dirname(os.path.abspath(__file__)), "b03-latency.py"))
b03 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b03)


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def dist(xs):
    return {"n": len(xs), "min": min(xs), "p50": pct(xs, .5), "p95": pct(xs, .95), "p99": pct(xs, .99), "max": max(xs)}


def request(sock, host, method, path, token, body):
    head = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {token}\r\n"
    data = b""
    if body is not None:
        data = json.dumps(body).encode()
        head += f"Content-Type: application/json\r\nContent-Length: {len(data)}\r\n"
    msg = head.encode() + b"\r\n" + data
    t0 = time.monotonic_ns()
    sock.sendall(msg)
    t1 = time.monotonic_ns()
    buf = sock.recv(65536)
    t2 = time.monotonic_ns()
    while True:
        end = buf.find(b"\r\n\r\n")
        if end >= 0:
            lines = buf[:end].decode().split("\r\n")
            length = 0
            for l in lines[1:]:
                k, _, v = l.partition(":")
                if k.lower() == "content-length":
                    length = int(v)
            if len(buf) - end - 4 >= length:
                break
        buf += sock.recv(65536)
    t3 = time.monotonic_ns()
    return int(lines[0].split()[1]), t1 - t0, t2 - t1, t3 - t2


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root")
    p.add_argument("out")
    p.add_argument("--source", required=True)
    p.add_argument("--binary")
    p.add_argument("-n", type=int, default=100)
    a = p.parse_args()
    b03.STAMP.update(b03.stamp(a.source, a.binary))
    d = b03.Deployment(a.root)
    host = d.api.split("//")[1].split("/")[0]
    h, port = host.rsplit(":", 1)
    base = "/api/v1"
    zero = "0" * 40

    def body(tag):
        return {"delivery_id": f"b03b-{tag}-{time.time_ns()}", "ref": "refs/heads/b03b-none",
                "old_sha": zero, "new_sha": "1" * 40}

    def connect():
        t0 = time.monotonic_ns()
        s = socket.create_connection((h, int(port)))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s, time.monotonic_ns() - t0

    keep, _ = connect()
    kinds = ["intake_new", "intake_keep", "intake_dup", "refused", "ready", "health"]
    samples = {k: [] for k in kinds}
    order = [k for k in kinds for _ in range(a.n)]
    random.Random(7).shuffle(order)
    pressure_start = d.settle()
    start = open("/proc/pressure/cpu").read(), open("/proc/loadavg").read()
    dup_body = body("dup")
    for kind in order:
        if kind == "intake_keep":
            s, conn = keep, 0
        else:
            s, conn = connect()
        if kind in ("intake_new", "intake_keep"):
            status, send, first, rest = request(s, host, "POST", f"{base}/intake/{d.repo}", d.hook, body(kind))
            want = 202
        elif kind == "intake_dup":
            status, send, first, rest = request(s, host, "POST", f"{base}/intake/{d.repo}", d.hook, dup_body)
            want = 202
        elif kind == "refused":
            status, send, first, rest = request(s, host, "POST", f"{base}/intake/{d.repo}", "x" * 20, body(kind))
            want = 401
        elif kind == "ready":
            status, send, first, rest = request(s, host, "GET", f"{base}/ready", d.token, None)
            want = 200
        else:
            status, send, first, rest = request(s, host, "GET", f"{base}/health", d.token, None)
            want = 200
        if status != want:
            raise SystemExit(f"{kind}: status {status}")
        if s is not keep:
            s.close()
        samples[kind].append({"connect_ns": conn, "send_ns": send, "first_byte_ns": first, "rest_ns": rest,
                              "total_ns": conn + send + first + rest})
        time.sleep(0.05)
    end = open("/proc/pressure/cpu").read(), open("/proc/loadavg").read()
    out = open(a.out, "a")
    summary = {}
    for k, rows in samples.items():
        summary[k] = {f: dist([r[f] / 1e6 for r in rows]) for f in ("connect_ns", "first_byte_ns", "total_ns")}
        b03.emit(out, budget="ack_phases", kind=k, samples=rows,
                 cpu_pressure_avg60_start=pressure_start,
                 host_load={"start": {"cpu_psi": start[0], "loadavg": start[1]}, "end": {"cpu_psi": end[0], "loadavg": end[1]}})
        t = summary[k]["total_ns"]
        print(f"{k:12s} n={t['n']} total ms p50 {t['p50']:.2f} p95 {t['p95']:.2f} p99 {t['p99']:.2f} max {t['max']:.2f}"
              f" | first byte p50 {summary[k]['first_byte_ns']['p50']:.2f} connect p50 {summary[k]['connect_ns']['p50']:.2f}", file=sys.stderr)


if __name__ == "__main__":
    main()
