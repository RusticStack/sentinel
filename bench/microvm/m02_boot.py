#!/usr/bin/env python3
"""M02: microVM boot, restore and memory on the KVM host (plan 16.8, TODO M02).

    m02_boot.py image   --store-env IMAGE OUT.ext4    the job image as an ext4 file (podman unshare + mkfs.ext4 -d)
    m02_boot.py initrd  AGENT OUT.cpio                 the initramfs with the agent as /init
    m02_boot.py run     --vmm firecracker|cloud-hypervisor --mode cold|restore --sandbox bare|unshare
                        --kernel K --initrd I --rootfs R --bin VMM [--n 200] [--out records.jsonl]
    m02_boot.py memory  --vmm ... --count N ...        N VMs booted together, their VMM processes' PSS

A sample is spawn-of-the-VMM-process -> the guest agent's `Ready` over vsock (Firecracker's and Cloud
Hypervisor's hybrid vsock: a Unix socket, `CONNECT <port>`), for a cold boot; for a restore, the same from a
snapshot of a booted guest. Every record carries the host block and the binaries' SHA-256.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

AGENT_PORT = 1024
CPU_SET = os.environ.get("M02_CPUS", "")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def host():
    def first(p):
        try:
            return open(p).read().strip()
        except OSError:
            return None
    model = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), None)
    return {"hostname": os.environ.get("SENTINEL_BENCH_HOST_LABEL") or None,
            "kernel": platform.release(), "cpu_model": model,
            "cpus_online": os.cpu_count(), "governor": first("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
            "loadavg": first("/proc/loadavg"), "cpu_pressure": first("/proc/pressure/cpu")}


# ---------------------------------------------------------------- artefacts

def cpio(agent, out):
    data = open(agent, "rb").read()
    buf = bytearray()
    ino = 1

    def entry(name, mode, body=b""):
        nonlocal ino
        fields = [ino, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name) + 1, 0]
        ino += 1
        buf.extend(b"070701" + b"".join(b"%08x" % f for f in fields) + name.encode() + b"\0")
        while len(buf) % 4:
            buf.append(0)
        buf.extend(body)
        while len(buf) % 4:
            buf.append(0)
    for d in ("dev", "proc", "sys", "lower", "scratch", "job"):
        entry(d, 0o040755)
    entry("init", 0o100755, data)
    entry("TRAILER!!!", 0)
    open(out, "wb").write(bytes(buf))


def image(name, out):
    script = ('set -e; m=$(podman image mount -- "$1"); trap \'podman image unmount -- "$1" >/dev/null\' EXIT; '
              'size=$(du -sm --apparent-size "$m" | cut -f1); truncate -s $(( size * 5 / 4 + 256 ))M "$2"; '
              'mkfs.ext4 -q -F -m 0 -L sentinel-image -E root_owner=0:0 -d "$m" "$2"')
    subprocess.run(["podman", "unshare", "sh", "-c", script, "sh", name, out], check=True)


def copy_sparse(src, dst):
    # A 1 GiB scratch disk is mostly holes: copying them as data would write a gigabyte per boot.
    subprocess.run(["cp", "--sparse=always", "--reflink=auto", src, dst], check=True)


def scratch(path, size=1 << 30):
    with open(path, "wb") as f:
        f.truncate(size)
    subprocess.run(["mkfs.ext4", "-q", "-F", "-m", "0", "-E", "root_owner=0:0", path], check=True)


# ---------------------------------------------------------------- the agent

def frame(body):
    return struct.pack("<I", len(body)) + body


HELLO = frame(b"\x00\x01")  # Request::Hello { version: 1 } in postcard


def agent_ready(sock_path, deadline, alive):
    while True:
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(sock_path)
            s.sendall(b"CONNECT %d\n" % AGENT_PORT)
            line = b""
            while not line.endswith(b"\n"):
                c = s.recv(1)
                if not c:
                    raise OSError("closed")
                line += c
            if not line.startswith(b"OK "):
                raise OSError(line)
            s.sendall(HELLO)
            hdr = s.recv(4, socket.MSG_WAITALL)
            (n,) = struct.unpack("<I", hdr)
            body = s.recv(n, socket.MSG_WAITALL)
            if body[:1] != b"\x00":
                raise OSError("not Ready")
            return s
        except OSError:
            try:
                s.close()
            except Exception:
                pass
            if not alive():
                raise RuntimeError("the VMM exited before the agent answered")
            if time.monotonic() > deadline:
                raise RuntimeError("the agent did not answer")
            time.sleep(0.002)


# ---------------------------------------------------------------- VMMs

def wrap(argv, sandbox):
    pin = ["taskset", "-c", CPU_SET] if CPU_SET else []
    if sandbox == "unshare":
        return pin + ["podman", "unshare", "unshare", "--net", "--fork", "--"] + argv
    return pin + argv


def fc_config(a, d, scratch_path):
    return {
        "boot-source": {"kernel_image_path": a.kernel, "initrd_path": a.initrd,
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off i8042.noaux i8042.nomux i8042.dumbkbd quiet"},
        "drives": [{"drive_id": "image", "path_on_host": a.rootfs, "is_root_device": False, "is_read_only": True},
                   {"drive_id": "scratch", "path_on_host": scratch_path, "is_root_device": False, "is_read_only": False}],
        "machine-config": {"vcpu_count": a.vcpus, "mem_size_mib": a.mem, "smt": False, "track_dirty_pages": a.mode == "restore"},
        "vsock": {"guest_cid": 3, "uds_path": os.path.join(d, "v.sock")},
    }


def api(sock, method, path, body=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock)
    data = json.dumps(body).encode() if body is not None else b""
    s.sendall(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
              f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
    resp = s.recv(65536)
    s.close()
    status = int(resp.split(b" ", 2)[1])
    if status >= 300:
        raise RuntimeError(f"{method} {path}: {resp[:300]!r}")


def wait_file(path, deadline):
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise RuntimeError(f"{path} never appeared")
        time.sleep(0.001)


def boot_fc(a, d):
    sp = os.path.join(d, "scratch.ext4")
    if not os.path.exists(sp):
        copy_sparse(a.scratch_template, sp)
    api_sock = os.path.join(d, "api.sock")
    log = open(os.path.join(d, "console.log"), "ab")
    cfg = os.path.join(d, "vm.json")
    json.dump(fc_config(a, d, sp), open(cfg, "w"))
    argv = [a.bin, "--api-sock", api_sock, "--config-file", cfg]
    t0 = time.monotonic()
    p = subprocess.Popen(wrap(argv, a.sandbox), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    s = agent_ready(os.path.join(d, "v.sock"), t0 + 60, lambda: p.poll() is None)
    return p, s, time.monotonic() - t0


def boot_ch(a, d):
    sp = os.path.join(d, "scratch.ext4")
    if not os.path.exists(sp):
        copy_sparse(a.scratch_template, sp)
    argv = [a.bin, "--kernel", a.kernel, "--initramfs", a.initrd,
            "--cmdline", "console=ttyS0 reboot=k panic=1 quiet",
            "--cpus", f"boot={a.vcpus}", "--memory", f"size={a.mem}M",
            "--disk", f"path={a.rootfs},readonly=on", f"path={sp}",
            "--vsock", f"cid=3,socket={os.path.join(d, 'v.sock')}",
            "--console", "off", "--serial", f"file={os.path.join(d, 'console.log')}",
            "--api-socket", f"path={os.path.join(d, 'api.sock')}"]
    log = open(os.path.join(d, "vmm.log"), "ab")
    t0 = time.monotonic()
    p = subprocess.Popen(wrap(argv, a.sandbox), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    s = agent_ready(os.path.join(d, "v.sock"), t0 + 60, lambda: p.poll() is None)
    return p, s, time.monotonic() - t0


def stop(p):
    p.kill()
    p.wait()


def snapshot_fc(a, work):
    d = os.path.join(work, "base")
    os.makedirs(d)
    p, s, _ = boot_fc(a, d)
    s.close()
    sock = os.path.join(d, "api.sock")
    api(sock, "PATCH", "/vm", {"state": "Paused"})
    snap, mem = os.path.join(work, "vm.snap"), os.path.join(work, "vm.mem")
    api(sock, "PUT", "/snapshot/create", {"snapshot_type": "Full", "snapshot_path": snap, "mem_file_path": mem})
    stop(p)
    return snap, mem, d


def run(a):
    out = open(a.out, "a") if a.out else sys.stdout
    common = {"schema": "sentinel-bench/m02/1", "vmm": a.vmm, "mode": a.mode, "sandbox": a.sandbox,
              "vcpus": a.vcpus, "mem_mib": a.mem, "host": host(),
              "binaries": {"vmm": sha(a.bin), "kernel": sha(a.kernel), "initrd": sha(a.initrd), "rootfs": sha(a.rootfs)}}
    with tempfile.TemporaryDirectory(dir=a.workdir) as work:
        a.scratch_template = os.path.join(work, "scratch-template.ext4")
        scratch(a.scratch_template)
        if a.mode == "restore":
            if a.vmm != "firecracker":
                raise SystemExit("restore is measured for Firecracker (Cloud Hypervisor restore: M06/M07)")
            snap, mem, base = snapshot_fc(a, work)
        samples = []
        for i in range(a.n):
            d = os.path.join(work, f"vm{i}")
            os.makedirs(d)
            if a.mode == "restore":
                # The snapshot names the base VM's paths: its scratch and vsock socket must exist again there.
                for f in ("v.sock", "api.sock"):
                    try:
                        os.unlink(os.path.join(base, f))
                    except FileNotFoundError:
                        pass
                p, s, t = boot_fc_restore(a, base, snap, mem)
            elif a.vmm == "firecracker":
                p, s, t = boot_fc(a, d)
            else:
                p, s, t = boot_ch(a, d)
            s.close()
            stop(p)
            shutil.rmtree(d, ignore_errors=True)
            samples.append(t)
        note = "every restore reuses the base VM's scratch file and paths; boot timing only" if a.mode == "restore" else None
        rec = dict(common, kind="distribution", n=len(samples), seconds=samples, note=note,
                   p50=statistics.median(samples), p95=sorted(samples)[max(0, -(-95 * len(samples) // 100) - 1)],
                   min=min(samples), max=max(samples))
        print(json.dumps(rec), file=out, flush=True)
        print(f"{a.vmm} {a.mode} {a.sandbox}: n={len(samples)} p50={rec['p50']*1000:.1f} ms p95={rec['p95']*1000:.1f} ms "
              f"min={rec['min']*1000:.1f} max={rec['max']*1000:.1f}", file=sys.stderr)


def boot_fc_restore(a, base, snap, mem):
    api_sock = os.path.join(base, "api.sock")
    log = open(os.path.join(base, "console.log"), "ab")
    t0 = time.monotonic()
    p = subprocess.Popen(wrap([a.bin, "--api-sock", api_sock], a.sandbox), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    wait_file(api_sock, t0 + 30)
    api(api_sock, "PUT", "/snapshot/load", {"snapshot_path": snap, "mem_backend": {"backend_type": "File", "backend_path": mem}, "resume_vm": True})
    s = agent_ready(os.path.join(base, "v.sock"), t0 + 60, lambda: p.poll() is None)
    return p, s, time.monotonic() - t0


def pss(pid):
    total = 0
    try:
        for l in open(f"/proc/{pid}/smaps_rollup"):
            if l.startswith("Pss:"):
                total += int(l.split()[1]) * 1024
    except OSError:
        pass
    return total


def descendants(pid):
    out, todo = [], [pid]
    while todo:
        p = todo.pop()
        out.append(p)
        try:
            for t in os.listdir(f"/proc/{p}/task"):
                for c in open(f"/proc/{p}/task/{t}/children").read().split():
                    todo.append(int(c))
        except OSError:
            pass
    return out


def memory(a):
    out = open(a.out, "a") if a.out else sys.stdout
    with tempfile.TemporaryDirectory(dir=a.workdir) as work:
        a.scratch_template = os.path.join(work, "scratch-template.ext4")
        scratch(a.scratch_template)
        vms = []
        for i in range(a.count):
            d = os.path.join(work, f"vm{i}")
            os.makedirs(d)
            p, s, _ = boot_fc(a, d) if a.vmm == "firecracker" else boot_ch(a, d)
            vms.append((p, s))
        time.sleep(5)
        per = [sum(pss(q) for q in descendants(p.pid)) for p, _ in vms]
        for p, s in vms:
            s.close()
            stop(p)
        rec = {"schema": "sentinel-bench/m02/1", "kind": "idle_memory", "vmm": a.vmm, "sandbox": a.sandbox,
               "vcpus": a.vcpus, "mem_mib": a.mem, "count": a.count, "pss_bytes": per,
               "pss_median": statistics.median(per), "host": host()}
        print(json.dumps(rec), file=out, flush=True)
        print(f"{a.vmm} idle x{a.count}: PSS median {statistics.median(per)/2**20:.1f} MiB per VM", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("image")
    i.add_argument("name")
    i.add_argument("out")
    r = sub.add_parser("initrd")
    r.add_argument("agent")
    r.add_argument("out")
    for name in ("run", "memory"):
        p = sub.add_parser(name)
        p.add_argument("--vmm", choices=["firecracker", "cloud-hypervisor"], required=True)
        p.add_argument("--mode", choices=["cold", "restore"], default="cold")
        p.add_argument("--sandbox", choices=["bare", "unshare"], default="bare")
        p.add_argument("--bin", required=True)
        p.add_argument("--kernel", required=True)
        p.add_argument("--initrd", required=True)
        p.add_argument("--rootfs", required=True)
        p.add_argument("--vcpus", type=int, default=1)
        p.add_argument("--mem", type=int, default=512)
        p.add_argument("--n", type=int, default=200)
        p.add_argument("--count", type=int, default=10)
        p.add_argument("--workdir", default=None)
        p.add_argument("--out")
    a = ap.parse_args()
    if a.cmd == "image":
        image(a.name, a.out)
    elif a.cmd == "initrd":
        cpio(a.agent, a.out)
    elif a.cmd == "run":
        run(a)
    else:
        memory(a)


if __name__ == "__main__":
    main()
