"""Hygiene checks for the benchmark scripts and committed records (RW10).

    python3 -m unittest bench/test_bench_hygiene.py        (run on a verification host, see docs/benchmarking.md)

Four rules, each with its exceptions written down here:
  * a script under bench/ or scripts/ that takes the benchmark lock uses `flock -o`, so the command it starts does
    not inherit the lock, and no script names its lock under /srv/sentinel (the production tree);
  * every committed record under bench/*.jsonl carries `build.commit` and an anonymized `host.hostname`,
    except the files in LEGACY_UNSTAMPED, which are kept as measured;
  * every record writer that exists today names the stamp it uses;
  * the Python writers refuse to run without a source commit and an anonymized host label (benchstamp.py).
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import benchstamp  # noqa: E402

# Committed before the build and host stamp existed (or, for GitHub-collected baselines and the
# development-host files, measuring nothing Sentinel built), or written by a tool that records its source in
# a shape of its own (the M01, K07 microVM, U08, U09, U14 and V01 records), so they cannot be stamped after the
# fact without inventing the commit. The set is exact: a file that gains a stamp must leave it.
LEGACY_UNSTAMPED = {
    "b01-isolation.jsonl": "taken before the stamp; host label present, no build",
    "b01a-github-cli-cached-tests.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-cli.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-gson.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b01a-github-ripgrep.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b02-github-runner.jsonl": "GitHub-collected baseline; no Sentinel build is measured",
    "b02-sentinel.jsonl": "taken before the stamp (commit null in the tracker)",
    "b02-woodpecker.jsonl": "Woodpecker baseline; no Sentinel build is measured",
    "b03-before-fixes.jsonl": "the pre-fix run; the build it ran is not recoverable",
    "b03-latency.jsonl": "taken before the stamp; superseded by b03-rerun*.jsonl",
    "b04-pipeline-fetch.jsonl": "taken before the stamp",
    "b04-transfer-copies.jsonl": "taken before the stamp",
    "b11-dryrun-records.jsonl": "dry-run output of the paired harness; no measured build",
    "b11-dryrun-samples.jsonl": "dry-run samples of the paired harness; no measured build",
    "c02-engines.jsonl": "taken before the stamp",
    "f05-noop-baseline.jsonl": "taken before the stamp (host label present)",
    "f05-noop-vps.jsonl": "taken before the stamp (host label present)",
    "f06-legacy-go-ci-runs.jsonl": "legacy Go CI runs; no Sentinel build is measured",
    "f07-storage.jsonl": "taken before the stamp",
    "k02-cache-clone.jsonl": "taken before the stamp",
    "k07-recipes.jsonl": "taken before the stamp",
    "k07-recipes-microvm.jsonl": "recorded by the microVM recipe test: no commit, no host block",
    "k09-before-after.jsonl": "taken before the stamp",
    "m01-detection.jsonl": "detection notes with a short `commit` and a `host` label, no build or host block",
    "m02-boot.jsonl": "taken before the stamp (host label present)",
    "q09-fleet-load.jsonl": "taken before the stamp; a `code` field names the build in prose",
    "r04-backup-drill.jsonl": "taken before the stamp",
    "r06-idle.jsonl": "taken before the stamp",
    "u08-web-baseline.jsonl": "web-bench.mjs record: a short `code` hash and a `host_label`, no build or host block",
    "u09-web-spikes.jsonl": "validator size spike: a short `code` hash and a `host_label`, no build or host block",
    "u14-web-start.jsonl": "web-bench.mjs record: a short `code` hash and a `host_label`, no build or host block",
    "u01-log-view.jsonl": "taken before the stamp",
    "v01-release-profile.jsonl": "measure-profile.sh record: a `source` block with git_commit, no build or host block",
}

# Writers that stamp, and the marker that shows how.
STAMPED_WRITERS = {
    "b02-sentinel.sh": '"build"',
    "b03-latency.py": "def stamp(",
    "auth-cost.sh": "micro-run.sh",
    "noop-interleave.sh": "micro-run.sh",
    "store-cost.sh": "micro-run.sh",
    "spawn-cost.sh": "micro-run.sh",
    "backup-rehash.sh": "micro-run.sh",
    "c02-engines.sh": "stamp.sh",
    "checks-lane.sh": "micro-run.sh",
    "f07-storage.sh": "stamp.sh",
    "k02-cache-clone.sh": "stamp.sh",
    "k07-recipes.sh": "stamp.sh",
    "m01-detect.sh": "stamp.sh",
    "k09-before-after.sh": "stamp.sh",
    "log-ack.sh": "micro-run.sh",
    "b05-cache.sh": "stamp.sh",
    "b05-workloads.sh": "stamp.sh",
    "b05-timed.sh": "B05_STAMP",
    "microvm/m02_boot.py": "benchstamp.build(",
    "p14-pilot.sh": '"build"',
    "q13-fleet.py": "benchstamp.stamp(",
    "r06-idle.sh": "stamp.sh",
    "s3-hash.sh": "micro-run.sh",
}

HOST_LABEL, IPV4 = benchstamp.HOST_LABEL, benchstamp.IPV4  # one definition, shared with the writers


def records(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def stamp_problems(rec):
    out = []
    build, host = rec.get("build"), rec.get("host")
    if not isinstance(build, dict) or not build.get("commit"):
        out.append("build.commit missing or null")
    if not isinstance(host, dict) or not host.get("hostname"):
        out.append("host.hostname missing")
    elif not HOST_LABEL.match(host["hostname"]) or IPV4.search(host["hostname"]):
        out.append(f"host.hostname {host['hostname']!r} is not an anonymized label")
    return out


def flock_offenders(text, python=False):
    """(line number, line) of every `flock` that locks a file or runs a command without `-o`, so the started
    process would inherit the lock. `flock FD` / `flock -n FD` hold a descriptor the shell owns and fork nothing.
    A `flock` inside a quoted assignment (`locked="flock -x $lock"`) is found like any other."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line if python else line.split("#", 1)[0]
        m = re.search(r"(?<![\w./-])flock\s+(.*)", code)
        if not m:
            continue
        args = m.group(1).replace('"', " ").replace("'", " ").split()
        positional = [a for a in args if not a.startswith("-")]
        if len(positional) == 1 and positional[0].isdigit():
            continue
        if not positional:
            continue
        flags = " ".join(a for a in args if a.startswith("-"))
        if not re.search(r"(^|\s)-\w*o\w*(\s|$)|--close", flags):
            out.append((n, line.strip()))
    return out


def lock_scripts():
    """Every script that can take the benchmark lock: bench/ (recursively) and scripts/, except this test."""
    paths = []
    for root, exts in ((HERE, (".sh", ".py")), (os.path.join(REPO, "scripts"), (".sh", ".py"))):
        for dirpath, _dirs, files in os.walk(root):
            paths += [os.path.join(dirpath, f) for f in files if f.endswith(exts)]
    skip = {os.path.abspath(__file__), os.path.join(HERE, "test_micro_contract.py")}  # the runner's tests probe the lock on purpose
    return sorted(p for p in paths if os.path.abspath(p) not in skip)


class LockHandling(unittest.TestCase):
    def test_every_flock_on_a_command_uses_o(self):
        offenders = []
        for path in lock_scripts():
            with open(path, encoding="utf-8") as f:
                for n, line in flock_offenders(f.read(), path.endswith(".py")):
                    offenders.append(f"{os.path.relpath(path, REPO)}:{n}: {line}")
        self.assertEqual(offenders, [], "flock without -o lets the started command inherit the benchmark lock")

    def test_the_detector_sees_what_it_should(self):
        self.assertTrue(flock_offenders('locked="flock -x $lock"'), "a lock held in a variable")
        self.assertTrue(flock_offenders("flock -x /var/tmp/l cargo test"))
        self.assertTrue(flock_offenders("flock -s /var/tmp/l true"))
        self.assertEqual(flock_offenders('locked="flock -x -o $lock"'), [])
        self.assertEqual(flock_offenders("flock -x -o /var/tmp/l cargo test"), [])
        self.assertEqual(flock_offenders("flock -n 9"), [], "a descriptor the shell owns")
        self.assertEqual(flock_offenders("# flock -x /var/tmp/l true"), [])

    def test_no_script_locks_a_file_in_the_production_tree(self):
        offenders = []
        for path in lock_scripts():
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    code = line.split("#", 1)[0]
                    # The lock path, or a flock on a path under /srv/sentinel (qualify.sh only refuses that tree).
                    if re.search(r"\bLOCK\w*\s*=.*?/srv/sentinel/|flock\b.*?/srv/sentinel/|[\"\x27]/srv/sentinel/runs/p14", code):
                        offenders.append(f"{os.path.relpath(path, REPO)}:{n}: {line.strip()}")
        self.assertEqual(offenders, [], "the benchmark lock is /var/tmp/sentinel-verify.lock (SENTINEL_VERIFY_LOCK)")

    def test_the_benchmark_writers_share_one_lock_file(self):
        for name in ("b05-cache.sh", "b05-workloads.sh", "b09-harness.py", os.path.join("..", "scripts", "qualify", "qualify.sh")):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("SENTINEL_VERIFY_LOCK", text, name)
            self.assertIn("/var/tmp/sentinel-verify.lock", text, name)

    def test_the_known_lock_users_still_take_it(self):
        for name in ("b05-cache.sh", "b05-workloads.sh"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                self.assertRegex(f.read(), r"flock -x -o ", name)
        with open(os.path.join(REPO, "scripts", "qualify", "qualify.sh"), encoding="utf-8") as f:
            self.assertRegex(f.read(), r"flock -x -o ", "qualify.sh")

    @unittest.skipUnless(shutil.which("flock") and shutil.which("sh"), "needs flock")
    def test_a_process_a_locked_command_leaves_behind_does_not_keep_the_lock(self):
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "lock")
            held = subprocess.run(["flock", "-x", "-o", lock, "sh", "-c", "sleep 20 & echo $! > pid"], cwd=d)
            self.assertEqual(held.returncode, 0)
            try:
                free = subprocess.run(["flock", "-n", lock, "true"])
                self.assertEqual(free.returncode, 0, "the orphan kept the lock: -o is what releases it")
            finally:
                with open(os.path.join(d, "pid")) as f:
                    subprocess.run(["kill", f.read().strip()])
            inherited = subprocess.run(["flock", "-x", lock, "sh", "-c", "sleep 20 & echo $! > pid2"], cwd=d)
            try:
                self.assertEqual(inherited.returncode, 0)
                self.assertNotEqual(subprocess.run(["flock", "-n", lock, "true"]).returncode, 0,
                                    "without -o the orphan inherits the lock (the failure this guards against)")
            finally:
                with open(os.path.join(d, "pid2")) as f:
                    subprocess.run(["kill", f.read().strip()])

    def test_b01a_names_the_reference_host(self):
        with open(os.path.join(HERE, "b01a-github.py"), encoding="utf-8") as f:
            doc = f.read().split('"""')[1]
        self.assertIn("reference host", doc)
        self.assertNotIn("verification VPS", doc)


class RecordStamps(unittest.TestCase):
    def files(self):
        return sorted(glob.glob(os.path.join(HERE, "*.jsonl")))

    def test_legacy_table_names_only_existing_files_that_are_still_unstamped(self):
        names = {os.path.basename(p) for p in self.files()}
        self.assertEqual(sorted(set(LEGACY_UNSTAMPED) - names), [], "exception for a file that does not exist")
        now_clean = [n for n in LEGACY_UNSTAMPED
                     if all(not stamp_problems(r) for r in records(os.path.join(HERE, n)))]
        self.assertEqual(now_clean, [], "fully stamped now: remove from LEGACY_UNSTAMPED")

    def test_every_other_file_is_stamped_on_every_record(self):
        bad = []
        for path in self.files():
            name = os.path.basename(path)
            if name in LEGACY_UNSTAMPED:
                continue
            for n, rec in enumerate(records(path), 1):
                for p in stamp_problems(rec):
                    bad.append(f"{name}:{n}: {p}")
        self.assertEqual(bad[:10], [], f"{len(bad)} unstamped records outside LEGACY_UNSTAMPED")

    def test_no_record_names_a_host_by_address(self):
        # Kernel versions look like addresses (6.18.33.2), so only host.hostname is checked.
        for path in self.files():
            for n, rec in enumerate(records(path), 1):
                host = rec.get("host")
                if not isinstance(host, dict):
                    continue
                self.assertIsNone(IPV4.search(str(host.get("hostname", ""))), f"{os.path.basename(path)}:{n}")

    def test_stamp_detection_rejects_what_it_should(self):
        ok = {"build": {"commit": "a" * 40}, "host": {"hostname": "reference-host"}}
        self.assertEqual(stamp_problems(ok), [])
        self.assertTrue(stamp_problems({**ok, "build": {"commit": None}}))
        self.assertTrue(stamp_problems({**ok, "host": {"hostname": "10.0.0.1"}}))
        self.assertTrue(stamp_problems({**ok, "host": {"hostname": "Node.example.com"}}))
        self.assertTrue(stamp_problems({"host": ok["host"]}))

    def test_writers_carry_their_stamp(self):
        for name, marker in STAMPED_WRITERS.items():
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                # A comment that mentions the stamp is not the stamp.
                code = "\n".join(l for l in f.read().splitlines() if not l.lstrip().startswith("#"))
            self.assertIn(marker, code, name)


def run_bash(script, *args, **env):
    """Runs `script` with SENTINEL_SRC, SENTINEL_BIN, SENTINEL_BENCH_HOST_LABEL and SHUF_SEED removed from the environment unless given."""
    base = {k: v for k, v in os.environ.items() if k not in ("SENTINEL_SRC", "SENTINEL_BIN", "SENTINEL_BENCH_HOST_LABEL", "SHUF_SEED")}
    return subprocess.run(["bash", "-c", script, "bash", *args], capture_output=True, text=True, env={**base, **env})


@unittest.skipUnless(shutil.which("bash") and shutil.which("shuf") and shutil.which("git"), "needs bash, shuf and git")
class StampHelpers(unittest.TestCase):
    STAMP = os.path.join(HERE, "stamp.sh")

    def order(self, seed):
        r = run_bash('. "$1"; seq 1 40 | shuffle_lines "$2" | tr "\\n" " "', self.STAMP, seed)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_a_seed_replays_the_same_order_and_another_seed_differs(self):
        self.assertEqual(self.order("s/ext4/1"), self.order("s/ext4/1"))
        self.assertEqual(sorted(self.order("s/ext4/1").split(), key=int), [str(i) for i in range(1, 41)])
        self.assertNotEqual(self.order("s/ext4/1"), self.order("s/ext4/2"))

    def test_shuffle_init_keeps_a_given_seed_and_makes_one_otherwise(self):
        script = '. "$1"; shuffle_init; echo "$SHUF_SEED"'
        self.assertEqual(run_bash(script, self.STAMP, SHUF_SEED="fixed-7").stdout.strip(), "fixed-7")
        self.assertTrue(run_bash(script, self.STAMP).stdout.strip())

    def test_stamp_needs_the_source_and_ignores_untracked_files(self):
        self.assertNotEqual(run_bash('. "$1"; stamp_init', self.STAMP).returncode, 0,
                            "no SENTINEL_SRC must not produce a stamp")
        with tempfile.TemporaryDirectory() as d:
            def git(*a):
                return subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                                       "-c", "commit.gpgsign=false", *a], capture_output=True, text=True)

            def write(name, text):
                with open(os.path.join(d, name), "w") as f:
                    f.write(text)

            def dirty():
                r = run_bash('bash "$1"', self.STAMP, SENTINEL_SRC=d, SENTINEL_BENCH_HOST_LABEL="test-host")
                self.assertEqual(r.returncode, 0, r.stderr)
                return json.loads(r.stdout)["build"]["dirty"]

            git("init", "-q")
            write("a", "1")
            git("add", "a")
            self.assertEqual(git("commit", "-q", "-m", "i").returncode, 0)
            self.assertIs(dirty(), False)
            write("scratch", "x")
            self.assertIs(dirty(), False, "an untracked file is not dirty")
            write("a", "2")
            self.assertIs(dirty(), True, "a tracked edit is dirty")

    def test_stamp_sed_survives_slashes_and_ampersands(self):
        script = ('. "$1"; STAMP_BODY=\'"a":"x/y&z"\'; echo "{}" | sed "s/^{/{$(stamp_sed),/"')
        r = run_bash(script, self.STAMP)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), '{"a":"x/y&z",}')

    def test_shuffling_writers_record_the_seed(self):
        for name in ("k02-cache-clone.sh", "f07-storage.sh"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                text = f.read()
            self.assertNotRegex(text, r"\|\s*shuf\b", f"{name} shuffles without the recorded seed")
            self.assertIn("shuffle_seed", text, name)


def make_repo(d):
    """A one-commit git checkout in `d`; returns its HEAD."""
    def git(*a):
        return subprocess.run(["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                               "-c", "commit.gpgsign=false", *a], capture_output=True, text=True)

    git("init", "-q")
    with open(os.path.join(d, "a"), "w") as f:
        f.write("1")
    git("add", "a")
    assert git("commit", "-q", "-m", "i").returncode == 0
    return git("rev-parse", "HEAD").stdout.strip()


def run_py(*args, **env):
    """Runs a bench script with the build and host variables removed from the environment unless given."""
    base = {k: v for k, v in os.environ.items()
            if k not in ("SENTINEL_SRC", "SENTINEL_BIN", "SENTINEL_BENCH_HOST_LABEL", "B05_STAMP")}
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, env={**base, **env})


class HostLabel(unittest.TestCase):
    def test_a_missing_or_malformed_label_is_refused(self):
        self.assertIsNone(benchstamp.label_problem("reference-host"))
        self.assertTrue(benchstamp.label_problem(""), "unset")
        self.assertTrue(benchstamp.label_problem("10.0.0.7"), "an address")
        self.assertTrue(benchstamp.label_problem("Node.example.com"), "a real host name")
        self.assertTrue(benchstamp.label_problem("host_1"), "outside lower-case letters, digits and hyphens")

    def test_host_label_exits_with_the_reason(self):
        with self.assertRaises(SystemExit) as caught:
            benchstamp.host_label({})
        self.assertIn("SENTINEL_BENCH_HOST_LABEL", str(caught.exception))
        self.assertEqual(benchstamp.host_label({"SENTINEL_BENCH_HOST_LABEL": "kvm-host"}), "kvm-host")

    def test_the_command_line_check_reports_through_the_exit_status(self):
        script = os.path.join(HERE, "benchstamp.py")
        self.assertEqual(run_py(script, "--check-label").returncode, 1)
        self.assertEqual(run_py(script, "--check-label", SENTINEL_BENCH_HOST_LABEL="192.0.2.1").returncode, 1)
        self.assertEqual(run_py(script, "--check-label", SENTINEL_BENCH_HOST_LABEL="kvm-host").returncode, 0)


@unittest.skipUnless(shutil.which("git"), "needs git")
class SourceState(unittest.TestCase):
    def test_a_directory_that_is_not_a_checkout_is_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(SystemExit) as caught:
            benchstamp.build(d)
        self.assertIn("cannot read the source commit", str(caught.exception))

    def test_an_unreadable_dirty_state_is_refused_not_recorded_as_null(self):
        with tempfile.TemporaryDirectory() as d:
            head = make_repo(d)
            real = subprocess.run

            def fail_status(argv, *a, **kw):
                if "status" in argv:
                    return subprocess.CompletedProcess(argv, 128, "", "fatal")
                return real(argv, *a, **kw)

            with mock.patch.object(benchstamp.subprocess, "run", fail_status), self.assertRaises(SystemExit) as caught:
                benchstamp.build(d)
            self.assertIn("tracked-change state", str(caught.exception))
            self.assertEqual(benchstamp.build(d), {"commit": head, "dirty": False})


@unittest.skipUnless(shutil.which("git"), "needs git")
class WriterRefusals(unittest.TestCase):
    """Each Python writer stops before its first sample without a source commit or a host label."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.head = make_repo(self.dir.name)

    def test_stamp_carries_build_and_host(self):
        with mock.patch.dict(os.environ, {"SENTINEL_BENCH_HOST_LABEL": "kvm-host"}):
            s = benchstamp.stamp(self.dir.name)
        self.assertEqual(stamp_problems(s), [])
        self.assertEqual(s["build"]["commit"], self.head)
        self.assertIs(s["build"]["dirty"], False)

    def test_stamp_refuses_without_a_label(self):
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("SENTINEL_BENCH_HOST_LABEL", None)
            with self.assertRaises(SystemExit):
                benchstamp.stamp(self.dir.name)

    def vmm_args(self):
        return [os.path.join(HERE, "microvm", "m02_boot.py"), "run", "--vmm", "firecracker", "--bin", "x",
                "--kernel", "x", "--initrd", "x", "--rootfs", "x"]

    def test_m02_needs_a_source_and_a_label_before_booting_anything(self):
        no_source = run_py(*self.vmm_args(), SENTINEL_BENCH_HOST_LABEL="kvm-host")
        self.assertNotEqual(no_source.returncode, 0)
        self.assertIn("--source", no_source.stderr)
        no_label = run_py(*self.vmm_args(), SENTINEL_SRC=self.dir.name)
        self.assertNotEqual(no_label.returncode, 0)
        self.assertIn("SENTINEL_BENCH_HOST_LABEL", no_label.stderr)
        address = run_py(*self.vmm_args(), SENTINEL_SRC=self.dir.name, SENTINEL_BENCH_HOST_LABEL="192.0.2.9")
        self.assertNotEqual(address.returncode, 0)
        self.assertIn("anonymized label", address.stderr)

    def test_q13_run_needs_a_source_and_a_label_and_its_selftest_still_passes(self):
        q13 = os.path.join(HERE, "q13-fleet.py")
        fleet = os.path.join(self.dir.name, "fleet.json")
        with open(fleet, "w") as f:
            f.write("{}")
        out = os.path.join(self.dir.name, "q13.jsonl")
        no_source = run_py(q13, "run", "--fleet", fleet, "--out", out, SENTINEL_BENCH_HOST_LABEL="kvm-host")
        self.assertNotEqual(no_source.returncode, 0)
        self.assertIn("--source", no_source.stderr)
        no_label = run_py(q13, "run", "--fleet", fleet, "--out", out, SENTINEL_SRC=self.dir.name)
        self.assertNotEqual(no_label.returncode, 0)
        self.assertIn("SENTINEL_BENCH_HOST_LABEL", no_label.stderr)
        self.assertFalse(os.path.exists(out), "nothing is written before the stamp is known")
        selftest = run_py(q13, "selftest")
        self.assertEqual(selftest.returncode, 0, selftest.stdout + selftest.stderr)

    def test_b03_refuses_a_run_without_a_label(self):
        b03 = os.path.join(HERE, "b03-latency.py")
        r = run_py(b03, "--source", self.dir.name, "--print-stamp")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SENTINEL_BENCH_HOST_LABEL", r.stderr)
        ok = run_py(b03, "--source", self.dir.name, "--print-stamp", SENTINEL_BENCH_HOST_LABEL="kvm-host")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(stamp_problems(json.loads(ok.stdout)), [])

    def test_b03b_replays_its_shuffle_from_a_recorded_seed(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("b03b_ack", os.path.join(HERE, "b03b-ack.py"))
        b03b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(b03b)
        kinds = ["intake_new", "refused", "ready", "health"]
        first = b03b.probe_order(kinds, 25, "seed-a")
        self.assertEqual(first, b03b.probe_order(kinds, 25, "seed-a"))
        self.assertNotEqual(first, b03b.probe_order(kinds, 25, "seed-b"))
        self.assertEqual(sorted(first), sorted(k for k in kinds for _ in range(25)))
        with open(os.path.join(HERE, "b03b-ack.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("Random(7)", text, "a fixed seed gives every run the same order")
        self.assertIn("shuffle_seed", text)
        self.assertIn('"seq"', text)

    def test_the_stamp_sh_helper_refuses_without_a_label(self):
        stamp_sh = os.path.join(HERE, "stamp.sh")
        r = run_bash('. "$1"; stamp_init', stamp_sh, SENTINEL_SRC=self.dir.name)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SENTINEL_BENCH_HOST_LABEL", r.stderr)
        address = run_bash('. "$1"; stamp_init', stamp_sh, SENTINEL_SRC=self.dir.name,
                           SENTINEL_BENCH_HOST_LABEL="10.1.2.3")
        self.assertNotEqual(address.returncode, 0)

    def test_the_shell_pilots_check_the_stamp_before_their_first_sample(self):
        for name in ("b02-sentinel.sh", "p14-pilot.sh"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                self.assertIn("benchstamp.py", f.read(), name)


@unittest.skipUnless(shutil.which("bash") and shutil.which("git"), "needs bash and git")
class B05Records(unittest.TestCase):
    TIMED = os.path.join(HERE, "b05-timed.sh")

    def test_a_timed_record_carries_the_common_stamp(self):
        with tempfile.TemporaryDirectory() as d:
            head = make_repo(d)
            out, log = os.path.join(d, "out.jsonl"), os.path.join(d, "log")
            script = ('. "$1"; stamp_init || exit 9; export B05_STAMP="$STAMP_BODY"; '
                      'bash "$2" "$3" \'"workload":"go"\' "$4" -- true')
            r = run_bash(script, os.path.join(HERE, "stamp.sh"), self.TIMED, out, log,
                         SENTINEL_SRC=d, SENTINEL_BENCH_HOST_LABEL="reference-host")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as f:
                rec = json.loads(f.readline())
            self.assertEqual(stamp_problems(rec), [])
            self.assertEqual(rec["build"]["commit"], head)
            self.assertIs(rec["build"]["dirty"], False, "a boolean, not the string the old script wrote")
            self.assertEqual((rec["record"], rec["workload"], rec["rc"]), ("b05-rebuild", "go", 0))

    def test_without_the_stamp_nothing_is_run_or_written(self):
        with tempfile.TemporaryDirectory() as d:
            out, marker = os.path.join(d, "out.jsonl"), os.path.join(d, "ran")
            r = run_bash('bash "$1" "$2" \'"w":1\' "$3" -- touch "$4"', self.TIMED, out, os.path.join(d, "log"), marker)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse(os.path.exists(out) or os.path.exists(marker))

    def test_the_cache_driver_refuses_to_start_without_the_stamp(self):
        with open(os.path.join(REPO, "crates", "sentinel-cache", "examples", "b05-cache.rs"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("B05_STAMP", text)
        self.assertNotIn("B05_COMMIT", text, "the short commit and string dirty flag are gone")
        self.assertNotIn("let _ = writeln!(out", text, "a failed record write must fail the cell")

    def test_a_failed_cell_fails_the_matrix(self):
        with open(os.path.join(HERE, "b05-cache.sh"), encoding="utf-8") as f:
            text = f.read()
        self.assertIn("FAILED=$((FAILED + 1))", text)
        self.assertRegex(text, r'\[ "\$FAILED" -gt 0 \]')


class MicroContracts(unittest.TestCase):
    """Every in-process micro bench has a contract and runs through bench/micro-run.sh (docs/benchmarking.md)."""

    def contracts(self):
        paths = sorted(glob.glob(os.path.join(HERE, "contracts", "micro", "*.json")))
        out = []
        for p in paths:
            with open(p, encoding="utf-8") as f:
                out.append((p, json.load(f)))
        return out

    def test_each_contract_names_its_runner_and_a_record_under_bench(self):
        found = self.contracts()
        self.assertTrue(found)
        for path, c in found:
            name = os.path.basename(path)[:-5]
            self.assertEqual(c["id"], name, path)
            self.assertEqual(c["format"], "sentinel.bench-micro-contract/1", path)
            self.assertRegex(c["record"]["out"], r"^bench/[a-z0-9-]+\.jsonl$", path)
            self.assertTrue(c["ordering"]["scheme"] in ("abba", "shuffle", "single") and "seed" in c["ordering"], path)
            if "script" in c["harness"]:
                self.assertTrue(os.path.isfile(os.path.join(REPO, c["harness"]["script"])), f"{name}: missing script")
            else:
                wrapper = os.path.join(HERE, name + ".sh")
                self.assertTrue(os.path.isfile(wrapper), f"{name}: no bench/{name}.sh wrapper")
                with open(wrapper, encoding="utf-8") as f:
                    self.assertIn("micro-run.sh", f.read(), f"{name}: the wrapper bypasses the runner (no lock, no quiet check)")

    def test_a_shuffled_contract_names_the_seed_it_records(self):
        for path, c in self.contracts():
            if c["ordering"]["scheme"] == "shuffle":
                self.assertEqual(sorted(c["ordering"]["seed"]), ["env", "recorded_as"], path)
            else:
                self.assertIsNone(c["ordering"]["seed"], path)

    def test_the_runner_does_not_hand_its_lock_to_the_bench(self):
        with open(os.path.join(HERE, "micro_contract.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("pass_fds", text)
        self.assertNotIn("close_fds=False", text)
        self.assertNotIn("set_inheritable", text)

    def test_no_committed_record_is_a_smoke_or_simulated_one(self):
        for path in sorted(glob.glob(os.path.join(HERE, "*.jsonl"))):
            for n, rec in enumerate(records(path), 1):
                for key in ("smoke", "simulated", "rehearsal"):
                    self.assertIsNot(rec.get(key), True, f"{os.path.basename(path)}:{n} is marked {key}: harness checks never become baselines")

    def test_a_record_that_names_a_contract_names_its_ordering_and_lock(self):
        for path in sorted(glob.glob(os.path.join(HERE, "*.jsonl"))):
            for n, rec in enumerate(records(path), 1):
                if isinstance(rec.get("contract"), dict) and rec["contract"].get("sha256") and "revision" in rec["contract"] and "conditions" in rec:
                    self.assertIn("ordering", rec, f"{os.path.basename(path)}:{n}")
                    self.assertIn("lock", rec, f"{os.path.basename(path)}:{n}")


class ErrorLinesAreStamped(unittest.TestCase):
    """A clone mode that fails still writes a record, and it names its build and host like every other line."""

    def test_the_failure_branch_of_k02_and_f07_splices_the_stamp(self):
        for name in ("k02-cache-clone.sh", "f07-storage.sh"):
            with open(os.path.join(HERE, name), encoding="utf-8") as f:
                lines = [l for l in f if '\\"error\\"' in l]
            self.assertTrue(lines, f"{name} has no error record")
            for l in lines:
                self.assertIn("$STAMP_BODY", l, f"{name}: an unstamped error line")
                self.assertNotIn("$STAMP_SED", l, "STAMP_SED is escaped for sed and would leave backslashes in an echo")
                self.assertIn("tr -d '\\n\"\\\\'", l, f"{name}: a backslash in the probe's stderr would break the JSON")


if __name__ == "__main__":
    unittest.main()
