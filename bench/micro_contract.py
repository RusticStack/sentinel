#!/usr/bin/env python3
"""Runner for in-process micro benchmarks (`sentinel.bench-micro-contract/1`).

A micro contract names one bench, the arguments it is frozen to, how it orders its cases, which seed it records,
the lock it takes and the record it appends. It sits beside `sentinel.bench-contract/1` (container lanes, run by
`sentinel-bench`); the two share the field names `format`, `id`, `revision`, `reference_host` and the 5 percent
start-pressure bound, but an in-process bench has no image, source or lane to pin.

    bench/micro-run.sh bench/contracts/micro/<id>.json [--smoke] [--out FILE] [--dir DIR] [-- extra bench args]
    python3 bench/micro_contract.py check bench/contracts/micro/<id>.json     validate; on a measured run also the host

A measured run, in this order, and nothing is measured when a step refuses:
  1. the contract validates (exit 2 names the field);
  2. the build and host are stamped (`benchstamp.py`: a commit and an anonymized host label are required);
  3. this host matches `reference_host` (when the contract names one);
  4. the shared verification lock is held (`SENTINEL_VERIFY_LOCK`, default /var/tmp/sentinel-verify.lock; a
     descriptor Python opens is not inherited by the bench or anything it leaves behind, the property a shell lock gets from its close-on-exec option);
  5. CPU pressure (avg60) is below `quiet_start.max_cpu_pressure_avg60`;
  6. the bench runs (a script harness whose contract has `record.from_stdout` true prints its records on stdout like a binary, and the
     runner stamps and appends them; any other script writes its own records and the runner only brackets it; a contract with `record.own_stamp` true names a bench that stamps its own build and host, like
     sentinel-bench, whose `build` the runner then leaves alone); only when it exits 0 and prints schema-matching JSON lines are they appended to the record
     file, each with `build`, `host`, `contract {id, revision, sha256}`, `ordering`, `conditions {start, end}` and
     `lock {path, waited_ns}`. The record file is appended to, never truncated.

A smoke run (`--smoke`) proves the harness with tiny parameters and needs no quiet host: it runs under nice/ionice
in a scratch directory, never takes the lock (it exits 75, "pending", when CPU pressure avg10 is above 25 or a
measurement holds the lock), writes records marked `"smoke": true` and refuses an output path inside the
repository's bench/ directory, so a smoke record cannot be committed by accident. Exit 75 is never a pass.

Test seams: SENTINEL_PRESSURE_FILE replaces /proc/pressure/cpu; SENTINEL_VERIFY_LOCK_HELD=1 says the caller already
holds the verification lock (the verification helper does), so a smoke run does not report it as someone else's.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

try:
    import fcntl
except ImportError:  # not Linux: the lock and the pressure checks need a verification host
    fcntl = None

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import benchstamp  # noqa: E402

FORMAT = "sentinel.bench-micro-contract/1"
DEFAULT_LOCK = "/var/tmp/sentinel-verify.lock"
PENDING = 75
SMOKE_MAX_PRESSURE_AVG10 = 25.0
SCHEMES = ("abba", "shuffle", "single")


class Refused(Exception):
    """The run must not start; `code` is the exit status (2 usage/contract, 3 host, 1 other, 75 pending)."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


def lock_path(environ=None):
    return (os.environ if environ is None else environ).get("SENTINEL_VERIFY_LOCK") or DEFAULT_LOCK


# -- contract -------------------------------------------------------------------------------------------------

def _need(obj, key, kind, where):
    if not isinstance(obj, dict) or key not in obj:
        raise Refused(f"contract field {where}{key} is missing")
    if not isinstance(obj[key], kind) or isinstance(obj[key], bool) and kind is not bool:
        raise Refused(f"contract field {where}{key} must be {kind.__name__}")
    return obj[key]


def load(path):
    """(contract, sha256 hex of the file bytes). Raises Refused naming the first bad field."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
        c = json.loads(raw)
    except (OSError, ValueError) as e:
        raise Refused(f"cannot read contract {path}: {e}")
    if not isinstance(c, dict):
        raise Refused("contract must be a JSON object")
    if c.get("format") != FORMAT:
        raise Refused(f"contract field format must be {FORMAT}")
    ident = _need(c, "id", str, "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", ident):
        raise Refused("contract field id must be lower-case letters, digits and hyphens")
    _need(c, "revision", int, "")
    h = _need(c, "harness", dict, "")
    if ("example" in h) == ("script" in h):
        raise Refused("contract field harness needs exactly one of example, script")
    for k in ("example", "script", "build", "target_path"):
        if k in h and not isinstance(h[k], str):
            raise Refused(f"contract field harness.{k} must be str")
    run = _need(c, "run", dict, "")
    for k in ("args", "smoke_args"):
        v = _need(run, k, list, "run.")
        if not all(isinstance(x, str) for x in v):
            raise Refused(f"contract field run.{k} must hold strings only")
    if "dir" in run and not isinstance(run["dir"], bool):
        raise Refused("contract field run.dir must be bool")
    o = _need(c, "ordering", dict, "")
    if _need(o, "scheme", str, "ordering.") not in SCHEMES:
        raise Refused(f"contract field ordering.scheme must be one of {', '.join(SCHEMES)}")
    if "seed" not in o:
        raise Refused("contract field ordering.seed is missing (write null when the order is fixed)")
    seed = o["seed"]
    if o["scheme"] == "shuffle":
        _need(seed if isinstance(seed, dict) else {}, "env", str, "ordering.seed.")
        _need(seed, "recorded_as", str, "ordering.seed.")
    elif seed is not None:
        raise Refused("contract field ordering.seed must be null unless ordering.scheme is shuffle")
    rec = _need(c, "record", dict, "")
    _need(rec, "schema", str, "record.")
    _need(rec, "out", str, "record.")
    q = _need(c, "quiet_start", dict, "")
    if not isinstance(q.get("max_cpu_pressure_avg60"), (int, float)) or isinstance(q.get("max_cpu_pressure_avg60"), bool):
        raise Refused("contract field quiet_start.max_cpu_pressure_avg60 must be a number")
    if "reference_host" in c:
        _need(c, "reference_host", dict, "")
    return c, hashlib.sha256(raw).hexdigest()


# -- host conditions ------------------------------------------------------------------------------------------

def pressure(window="avg60"):
    """CPU 'some' pressure for `avg10|avg60`, or None when the kernel does not expose it."""
    path = os.environ.get("SENTINEL_PRESSURE_FILE") or "/proc/pressure/cpu"
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("some"):
                    for part in line.split():
                        if part.startswith(window + "="):
                            return float(part.split("=", 1)[1])
    except (OSError, ValueError):
        pass
    return None


def steal_ns():
    """Cumulative CPU time stolen by the hypervisor, in nanoseconds, or None."""
    try:
        with open("/proc/stat") as f:
            fields = f.readline().split()
        return int(fields[8]) * (1_000_000_000 // os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, IndexError):
        return None


def conditions():
    c = {"cpu_pressure_avg10": pressure("avg10"), "cpu_pressure_avg60": pressure("avg60"), "steal_ns": steal_ns()}
    try:
        with open("/proc/loadavg") as f:
            c["loadavg1"] = float(f.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return {k: v for k, v in c.items() if v is not None}


def check_reference_host(c):
    ref = c.get("reference_host")
    if not ref:
        return
    problems = []
    cpu = benchstamp.field("/proc/cpuinfo", "model name")
    if "cpu_model" in ref and (cpu is None or ref["cpu_model"] not in cpu):
        problems.append(f"cpu model {cpu!r} does not contain {ref['cpu_model']!r}")
    if "cpus_online" in ref and os.cpu_count() != ref["cpus_online"]:
        problems.append(f"{os.cpu_count()} CPUs online, the contract is frozen on {ref['cpus_online']}")
    mem = benchstamp.field("/proc/meminfo", "MemTotal")
    if "mem_total_kib_min" in ref and (mem is None or int(mem.split()[0]) < ref["mem_total_kib_min"]):
        problems.append(f"memory {mem} is below {ref['mem_total_kib_min']} kB")
    if problems:
        raise Refused("this host is not the contract's reference host: " + "; ".join(problems), 3)


def under_bench_dir(path):
    real = os.path.realpath(path)
    bench = os.path.realpath(os.path.join(REPO, "bench"))
    return real == bench or real.startswith(bench + os.sep)


# -- lock -----------------------------------------------------------------------------------------------------

def take_lock(path):
    """Exclusive lock on `path`; (fd, waited_ns). Python opens the descriptor non-inheritable, so the bench and
    whatever it leaves behind never hold the lock after this process exits."""
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o666)
    except OSError as e:
        # Typically a lock file another account created 0644 (flock(1) opens it read-only): name the lock, not a traceback.
        raise Refused(f"the shared verification lock {path} cannot be opened ({e.strerror or type(e).__name__})", 3) from None
    t0 = time.monotonic_ns()
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd, time.monotonic_ns() - t0


def lock_is_free(path):
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o666)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


# -- running --------------------------------------------------------------------------------------------------

def resolve_bin(c, args):
    h = c["harness"]
    if "script" in h:
        p = h["script"] if os.path.isabs(h["script"]) else os.path.join(REPO, h["script"])
        if not os.path.isfile(p):
            raise Refused(f"harness script {h['script']} does not exist")
        return p
    binp = args.bin or os.environ.get("SENTINEL_BIN")
    if not binp:
        target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target")
        cand = os.path.join(target, h.get("target_path") or f"release/examples/{h['example']}")
        binp = cand if os.path.isfile(cand) else None
    if not binp or not os.path.isfile(binp):
        how = h.get("build", "build the example")
        raise Refused(f"the bench binary is missing; set SENTINEL_BIN to the binary built from SENTINEL_SRC ({how})")
    return binp


def bench_command(c, args, binp, smoke, scratch):
    run = c["run"]
    h = c["harness"]
    if "script" in h:
        # Checked-out scripts are not guaranteed an executable bit: run them by their interpreter.
        runner = ["bash"] if binp.endswith(".sh") else [sys.executable] if binp.endswith(".py") else []
        return runner + [binp] + list(run["smoke_args"] if smoke else run["args"]) + args.extra
    cmd = [binp] + list(run["smoke_args"] if smoke else run["args"])
    if run.get("dir"):
        d = scratch if smoke else (args.dir or os.environ.get("DIR"))
        if not d:
            raise Refused("this bench measures a file system: set DIR (or --dir) to a directory on the one under test")
        cmd += ["--dir", d]
    return cmd + args.extra


def merge_record(line, c, sha, stamp, ordering, cond_start, cond_end, lock, smoke):
    rec = json.loads(line)
    if not isinstance(rec, dict):
        raise ValueError("a record line must be a JSON object")
    schema = c["record"]["schema"]
    if rec.get("schema") != schema:
        raise ValueError(f"record schema {rec.get('schema')!r} is not the contract's {schema!r}")
    if not c["record"].get("own_stamp"):
        # The runner's stamp names the build and host; anything the bench printed under those names is kept apart.
        if "host" in rec:
            rec["bench_host"] = rec.pop("host")
        rec.pop("build", None)
        if stamp:
            rec["build"] = stamp["build"]
            rec["host"] = stamp["host"]
    rec["contract"] = {"id": c["id"], "revision": c["revision"], "sha256": sha}
    rec["ordering"] = ordering
    rec["conditions"] = {"start": cond_start, "end": cond_end}
    if lock:
        rec["lock"] = lock
    if smoke:
        rec["smoke"] = True
    return json.dumps(rec, separators=(",", ":"))


def run_contract(args):
    c, sha = load(args.contract)
    smoke = args.smoke
    scratch = None
    binp = resolve_bin(c, args)
    if smoke:
        out = args.out
        if out and under_bench_dir(out):
            raise Refused("a smoke run never writes into bench/: its records prove the harness, not a number", 2)
        p10 = pressure("avg10")
        lp = lock_path()
        if p10 is not None and p10 > SMOKE_MAX_PRESSURE_AVG10:
            raise Refused(f"pending: cpu pressure avg10={p10} is above {SMOKE_MAX_PRESSURE_AVG10}; the host is busy", PENDING)
        if os.environ.get("SENTINEL_VERIFY_LOCK_HELD") != "1" and not lock_is_free(lp):
            raise Refused(f"pending: a measurement holds {lp}", PENDING)
        base = "/var/tmp" if os.path.isdir("/var/tmp") else None
        scratch = tempfile.mkdtemp(prefix=f"micro-smoke-{c['id']}-", dir=base)
        out = out or os.path.join(scratch, "smoke.jsonl")
        stamp = None
        lock = None
        lock_fd = None
    else:
        out = args.out or os.environ.get("OUT") or os.path.join(REPO, c["record"]["out"])
        measured = binp if "example" in c["harness"] else (args.bin or os.environ.get("SENTINEL_BIN"))
        stamp = benchstamp.stamp(args.source or os.environ.get("SENTINEL_SRC") or _need_src(), measured)
        check_reference_host(c)
        lp = lock_path()
        lock_fd, waited = take_lock(lp)
        lock = {"path": lp, "waited_ns": waited}
        p60 = pressure("avg60")
        limit = c["quiet_start"]["max_cpu_pressure_avg60"]
        if p60 is None:
            os.close(lock_fd)
            raise Refused("cpu pressure is not readable on this host: cannot prove a quiet start", 3)
        if p60 >= limit:
            os.close(lock_fd)
            raise Refused(f"the host is not quiet: cpu pressure avg60={p60} is at or above {limit}", 3)
    try:
        env = dict(os.environ)
        ordering = {"scheme": c["ordering"]["scheme"], "seed": None}
        sd = c["ordering"]["seed"]
        if sd:
            seed = env.get(sd["env"]) or secrets.token_hex(8)
            env[sd["env"]] = seed
            ordering["seed"] = seed
            ordering["recorded_as"] = sd["recorded_as"]
        if "script" in c["harness"]:
            if smoke:
                for k, v in c["run"].get("smoke_env", {}).items():
                    env[k] = v.replace("{scratch}", scratch)
                env["DIR"] = scratch
            env["OUT"] = out
            if not smoke and args.dir:
                env["DIR"] = args.dir
        cmd = bench_command(c, args, binp, smoke, scratch)
        polite = []
        if smoke:
            if shutil.which("nice"):
                polite += ["nice", "-n", "19"]
            if shutil.which("ionice"):
                polite += ["ionice", "-c3"]
        cond_start = conditions()
        proc = subprocess.run(polite + cmd, env=env, stdout=subprocess.PIPE, text=True)
        cond_end = conditions()
        if proc.returncode == PENDING:
            # A script harness that skipped itself (a test that needs hardware this host lacks) measured nothing.
            raise Refused("pending: the bench reported that it measured nothing (exit 75); nothing was appended", PENDING)
        if proc.returncode != 0:
            raise Refused(f"the bench exited {proc.returncode}; nothing was appended", proc.returncode if 0 < proc.returncode < 64 else 1)
        if "script" in c["harness"] and not c["record"].get("from_stdout"):
            # A script that writes its own stamped records (f07, k02): the runner adds the lock, the start check and the conditions.
            sys.stdout.write(proc.stdout)
            print(f"micro-run {c['id']}: script finished; start {cond_start}, end {cond_end}", file=sys.stderr)
            return 0
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")]
        if not lines:
            raise Refused("the bench printed no record; nothing was appended", 1)
        try:
            merged = [merge_record(ln, c, sha, stamp, ordering, cond_start, cond_end, lock, smoke) for ln in lines]
        except ValueError as e:
            raise Refused(f"unusable bench output ({e}); nothing was appended", 1)
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "a") as f:
            f.write("\n".join(merged) + "\n")
        print(f"micro-run {c['id']}: {len(merged)} record(s) appended to {out}" + (" (smoke)" if smoke else ""), file=sys.stderr)
        return 0
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if scratch and not args.keep:
            shutil.rmtree(scratch, ignore_errors=True)


def _need_src():
    raise Refused("set SENTINEL_SRC to the checkout the measured build came from (and SENTINEL_BIN to its binary)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    ck = sub.add_parser("check")
    ck.add_argument("contract")
    ck.add_argument("--host", action="store_true", help="also compare this host with reference_host")
    rn = sub.add_parser("run")
    rn.add_argument("contract")
    rn.add_argument("--smoke", action="store_true")
    rn.add_argument("--out")
    rn.add_argument("--dir")
    rn.add_argument("--bin")
    rn.add_argument("--source")
    rn.add_argument("--keep", action="store_true", help="keep the smoke scratch directory")
    rn.add_argument("extra", nargs="*")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "check":
            c, sha = load(args.contract)
            if args.host:
                check_reference_host(c)
            print(f"{c['id']} revision {c['revision']} sha256 {sha}")
            return 0
        return run_contract(args)
    except Refused as e:
        print(f"micro-run: {e}", file=sys.stderr)
        return e.code
    except SystemExit as e:  # benchstamp refusals carry their reason as the exit message
        if isinstance(e.code, str):
            print(f"micro-run: {e.code}", file=sys.stderr)
            return 3
        raise


if __name__ == "__main__":
    sys.exit(main())
