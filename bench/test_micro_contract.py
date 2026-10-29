"""Tests of the micro-bench contract runner (bench/micro_contract.py, bench/micro-run.sh).

    python3 -m unittest bench/test_micro_contract.py        (Linux verification host: needs flock(2) and /proc)

The bench under test is a shell stub printing one JSON line, so the runner's own behavior is what fails or passes:
refusals before anything is measured, the lock, the quiet-start check, the append-only record, the smoke rules.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RUNNER = os.path.join(HERE, "micro_contract.py")
sys.path.insert(0, HERE)
import micro_contract  # noqa: E402

LINUX = sys.platform.startswith("linux") and shutil.which("flock") and shutil.which("sh")

FAKE_BENCH = """#!/bin/sh
# stub bench: prints one record; FAKE_RC makes it fail, FAKE_SCHEMA changes the schema, FAKE_EXTRA adds raw JSON members
state=held
flock -n "$SENTINEL_VERIFY_LOCK" true && state=free
if [ -n "$FAKE_PIDFILE" ]; then sleep 30 >/dev/null 2>&1 & echo $! > "$FAKE_PIDFILE"; fi
printf '{"schema":"%s","lock_state":"%s","args":"%s","seed_env":"%s"%s}\\n' "${FAKE_SCHEMA:-sentinel-bench/fake/1}" "$state" "$*" "$SHUF_SEED" "${FAKE_EXTRA:-}"
exit "${FAKE_RC:-0}"
"""


def contract(**over):
    c = {
        "format": "sentinel.bench-micro-contract/1", "id": "fake", "revision": 3,
        "harness": {"example": "fake-bench", "build": "cargo build"},
        "run": {"args": ["--full", "1"], "smoke_args": ["--tiny", "1"]},
        "ordering": {"scheme": "abba", "seed": None},
        "quiet_start": {"max_cpu_pressure_avg60": 5.0},
        "record": {"schema": "sentinel-bench/fake/1", "out": "bench/fake.jsonl"},
    }
    c.update(over)
    return c


@unittest.skipUnless(LINUX, "needs Linux, flock and sh")
class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.bench = os.path.join(self.d, "fake-bench")
        with open(self.bench, "w") as f:
            f.write(FAKE_BENCH)
        os.chmod(self.bench, 0o755)
        self.lock = os.path.join(self.d, "lock")
        self.pressure = os.path.join(self.d, "pressure")
        self.set_pressure(0.5, 0.5)
        self.out = os.path.join(self.d, "out.jsonl")

    def set_pressure(self, avg10, avg60):
        with open(self.pressure, "w") as f:
            f.write(f"some avg10={avg10:.2f} avg60={avg60:.2f} avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")

    def write(self, c):
        path = os.path.join(self.d, "contract.json")
        with open(path, "w") as f:
            json.dump(c, f)
        return path

    def env(self, **extra):
        base = {k: v for k, v in os.environ.items() if not k.startswith(("SENTINEL_", "SHUF_", "FAKE_", "OUT", "DIR"))}
        base.update(SENTINEL_VERIFY_LOCK=self.lock, SENTINEL_PRESSURE_FILE=self.pressure, SENTINEL_BIN=self.bench,
                    SENTINEL_SRC=REPO, SENTINEL_BENCH_HOST_LABEL="test-host", DIR=os.path.join(self.d, "dir"))
        base.update(extra)
        return base

    def run_runner(self, c, *args, env=None):
        return subprocess.run([sys.executable, RUNNER, "run", self.write(c), *args], capture_output=True, text=True,
                              env=env or self.env())

    def lines(self, path=None):
        p = path or self.out
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(l, object_pairs_hook=self.no_dupes) for l in f if l.strip()]

    @staticmethod
    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        assert len(keys) == len(set(keys)), f"duplicate keys in {keys}"
        return dict(pairs)

    # -- contract validation ---------------------------------------------------------------------------------

    def test_a_contract_with_a_missing_or_wrong_field_exits_2_naming_it(self):
        for name, mutate, field in (
            ("format", lambda c: c.update(format="sentinel.bench-contract/1"), "format"),
            ("id", lambda c: c.pop("id"), "id"),
            ("seed", lambda c: c["ordering"].pop("seed"), "ordering.seed"),
            ("scheme", lambda c: c["ordering"].update(scheme="random"), "ordering.scheme"),
            ("args", lambda c: c["run"].update(args="--x"), "run.args"),
            ("harness", lambda c: c["harness"].update(script="x"), "harness"),
            ("pressure", lambda c: c["quiet_start"].update(max_cpu_pressure_avg60="5"), "quiet_start.max_cpu_pressure_avg60"),
            ("seed on abba", lambda c: c["ordering"].update(seed={"env": "S", "recorded_as": "s"}), "ordering.seed"),
        ):
            with self.subTest(name):
                c = contract()
                mutate(c)
                r = self.run_runner(c, "--out", self.out)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn(field, r.stderr)
        self.assertEqual(self.lines(), [])

    def test_every_committed_micro_contract_validates(self):
        paths = sorted(glob.glob(os.path.join(HERE, "contracts", "micro", "*.json")))
        self.assertTrue(paths)
        for p in paths:
            with self.subTest(p):
                c, sha = micro_contract.load(p)
                self.assertEqual(os.path.basename(p), c["id"] + ".json")
                self.assertEqual(len(sha), 64)

    # -- refusals before anything is measured ----------------------------------------------------------------

    def test_a_host_that_is_not_the_reference_host_is_refused_and_nothing_is_written(self):
        c = contract(reference_host={"mem_total_kib_min": 1 << 60})
        r = self.run_runner(c, "--out", self.out)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("reference host", r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_busy_host_is_refused_at_the_contract_bound(self):
        self.set_pressure(0.0, 5.0)
        r = self.run_runner(contract(), "--out", self.out)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("not quiet", r.stderr)
        self.assertEqual(self.lines(), [])
        self.set_pressure(0.0, 4.99)
        self.assertEqual(self.run_runner(contract(), "--out", self.out).returncode, 0)

    def test_unreadable_pressure_cannot_prove_a_quiet_start(self):
        r = self.run_runner(contract(), "--out", self.out, env=self.env(SENTINEL_PRESSURE_FILE=os.path.join(self.d, "none")))
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_missing_or_malformed_host_label_refuses_before_the_bench_runs(self):
        marker = os.path.join(self.d, "ran")
        with open(self.bench, "w") as f:
            f.write(f"#!/bin/sh\ntouch {marker}\n")
        for label in ("", "10.0.0.1", "Has Space"):
            with self.subTest(label):
                r = self.run_runner(contract(), "--out", self.out, env=self.env(SENTINEL_BENCH_HOST_LABEL=label))
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertFalse(os.path.exists(marker))
                self.assertEqual(self.lines(), [])

    def test_a_missing_source_refuses(self):
        env = self.env()
        env.pop("SENTINEL_SRC")
        r = self.run_runner(contract(), "--out", self.out, env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("SENTINEL_SRC", r.stderr)

    def test_a_missing_binary_names_the_build_command(self):
        env = self.env(SENTINEL_BIN=os.path.join(self.d, "absent"))
        r = self.run_runner(contract(), "--out", self.out, env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("SENTINEL_BIN", r.stderr)
        self.assertIn("cargo build", r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_file_system_bench_needs_dir(self):
        c = contract()
        c["run"]["dir"] = True
        env = self.env()
        env.pop("DIR")
        r = self.run_runner(c, "--out", self.out, env=env)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("DIR", r.stderr)

    # -- a measured run --------------------------------------------------------------------------------------

    def test_a_measured_run_appends_one_stamped_record_and_keeps_earlier_lines(self):
        with open(self.out, "w") as f:
            f.write('{"earlier":true}\n')
        c = contract()
        c["run"]["dir"] = True
        r = self.run_runner(c, "--out", self.out, "--", "--extra", "7")
        self.assertEqual(r.returncode, 0, r.stderr)
        recs = self.lines()
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0], {"earlier": True})
        rec = recs[1]
        self.assertEqual(rec["build"]["commit"], subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip())
        self.assertIsInstance(rec["build"]["dirty"], bool)
        self.assertEqual(rec["host"]["hostname"], "test-host")
        self.assertEqual(rec["contract"]["id"], "fake")
        self.assertEqual(rec["contract"]["revision"], 3)
        with open(os.path.join(self.d, "contract.json"), "rb") as f:
            import hashlib
            self.assertEqual(rec["contract"]["sha256"], hashlib.sha256(f.read()).hexdigest())
        self.assertEqual(rec["ordering"], {"scheme": "abba", "seed": None})
        self.assertEqual(rec["lock"]["path"], self.lock)
        self.assertIsInstance(rec["lock"]["waited_ns"], int)
        self.assertEqual(set(rec["conditions"]), {"start", "end"})
        self.assertEqual(rec["lock_state"], "held", "the bench ran while the runner held the lock")
        self.assertTrue(rec["args"].startswith("--full 1 --dir "), rec["args"])
        self.assertTrue(rec["args"].endswith("--extra 7"), rec["args"])
        self.assertNotIn("smoke", rec)

    def test_the_wait_for_the_lock_is_recorded(self):
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT)
        micro_contract.fcntl.flock(fd, micro_contract.fcntl.LOCK_EX)
        threading.Timer(0.6, lambda: os.close(fd)).start()
        r = self.run_runner(contract(), "--out", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertGreater(self.lines()[0]["lock"]["waited_ns"], 300_000_000)

    def test_a_bench_that_fails_appends_nothing(self):
        r = self.run_runner(contract(), "--out", self.out, env=self.env(FAKE_RC="1"))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("nothing was appended", r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_bench_that_reports_it_measured_nothing_is_pending_and_appends_nothing(self):
        r = self.run_runner(contract(), "--out", self.out, env=self.env(FAKE_RC="75"))
        self.assertEqual(r.returncode, 75, r.stderr)
        self.assertIn("pending", r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_record_of_another_schema_is_not_appended(self):
        r = self.run_runner(contract(), "--out", self.out, env=self.env(FAKE_SCHEMA="sentinel-bench/other/1"))
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_record_that_already_names_a_host_ends_with_one_host_key(self):
        r = self.run_runner(contract(), "--out", self.out, env=self.env(FAKE_EXTRA=',"host":{"hostname":"bench-says"},"build":{"commit":"x"}'))
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.lines()[0]  # no_dupes fails the load on a duplicate key
        self.assertEqual(rec["host"]["hostname"], "test-host")
        self.assertEqual(rec["bench_host"], {"hostname": "bench-says"})
        self.assertNotEqual(rec["build"]["commit"], "x")

    def test_a_bench_that_stamps_itself_keeps_its_own_build_and_host(self):
        c = contract()
        c["record"]["own_stamp"] = True
        r = self.run_runner(c, "--out", self.out, env=self.env(FAKE_EXTRA=',"host":{"hostname":"bench-says"},"build":{"commit":"x"}'))
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.lines()[0]
        self.assertEqual(rec["build"], {"commit": "x"})
        self.assertEqual(rec["host"], {"hostname": "bench-says"})
        self.assertEqual(rec["contract"]["id"], "fake")

    def test_a_shuffled_bench_gets_and_records_one_seed(self):
        c = contract(ordering={"scheme": "shuffle", "seed": {"env": "SHUF_SEED", "recorded_as": "shuffle_seed"}})
        r = self.run_runner(c, "--out", self.out, env=self.env(SHUF_SEED="replay-1"))
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.lines()[0]
        self.assertEqual(rec["ordering"], {"scheme": "shuffle", "seed": "replay-1", "recorded_as": "shuffle_seed"})
        self.assertEqual(rec["seed_env"], "replay-1", "the bench saw the seed the record names")
        r = self.run_runner(c, "--out", self.out)
        fresh = self.lines()[1]
        self.assertTrue(fresh["ordering"]["seed"])
        self.assertEqual(fresh["seed_env"], fresh["ordering"]["seed"])

    @unittest.skipUnless(shutil.which("flock"), "needs flock")
    def test_a_process_the_bench_leaves_behind_does_not_keep_the_lock(self):
        pidfile = os.path.join(self.d, "pid")
        r = self.run_runner(contract(), "--out", self.out, env=self.env(FAKE_PIDFILE=pidfile))
        self.assertEqual(r.returncode, 0, r.stderr)
        try:
            self.assertEqual(subprocess.run(["flock", "-n", self.lock, "true"]).returncode, 0,
                             "the orphan kept the benchmark lock after the runner returned")
        finally:
            with open(pidfile) as f:
                subprocess.run(["kill", f.read().strip()])

    # -- smoke -----------------------------------------------------------------------------------------------

    def test_a_smoke_run_uses_the_tiny_arguments_marks_the_record_and_needs_no_quiet_host(self):
        self.set_pressure(10.0, 90.0)  # busy by the measured bound, below the smoke bound of 25 on avg10
        c = contract()
        c["run"]["dir"] = True
        r = self.run_runner(c, "--smoke", "--out", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.lines()[0]
        self.assertIs(rec["smoke"], True)
        self.assertTrue(rec["args"].startswith("--tiny 1 --dir "), rec["args"])
        self.assertNotIn("build", rec, "a smoke record names no commit")
        self.assertEqual(rec["lock_state"], "free", "a smoke run never takes the lock")
        self.assertNotIn("lock", rec)

    def test_a_smoke_run_cleans_its_scratch_directory(self):
        c = contract()
        c["run"]["dir"] = True
        r = self.run_runner(c, "--smoke", "--out", self.out)
        self.assertEqual(r.returncode, 0, r.stderr)
        scratch = self.lines()[0]["args"].split("--dir ")[1]
        self.assertFalse(os.path.exists(scratch))
        self.assertTrue(scratch.startswith("/var/tmp/micro-smoke-fake-") or "micro-smoke-fake-" in scratch)

    def test_a_smoke_run_is_pending_when_a_measurement_holds_the_lock(self):
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT)
        micro_contract.fcntl.flock(fd, micro_contract.fcntl.LOCK_EX)
        try:
            r = self.run_runner(contract(), "--smoke", "--out", self.out)
            self.assertEqual(r.returncode, 75, r.stderr)
            self.assertIn("pending", r.stderr)
            self.assertEqual(self.lines(), [])
            held = self.run_runner(contract(), "--smoke", "--out", self.out, env=self.env(SENTINEL_VERIFY_LOCK_HELD="1"))
            self.assertEqual(held.returncode, 0, "the caller that holds the lock says so")
        finally:
            os.close(fd)

    def test_a_smoke_run_is_pending_on_a_loaded_host(self):
        self.set_pressure(26.0, 1.0)
        r = self.run_runner(contract(), "--smoke", "--out", self.out)
        self.assertEqual(r.returncode, 75, r.stderr)
        self.assertEqual(self.lines(), [])

    def test_a_smoke_record_cannot_be_written_into_bench(self):
        target = os.path.join(HERE, "smoke-must-not-exist.jsonl")
        try:
            r = self.run_runner(contract(), "--smoke", "--out", target)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse(os.path.exists(target))
            link = os.path.join(self.d, "into-bench")
            os.symlink(HERE, link)
            r = self.run_runner(contract(), "--smoke", "--out", os.path.join(link, "smoke-must-not-exist.jsonl"))
            self.assertEqual(r.returncode, 2, "a symlink into bench/ is bench/")
            self.assertFalse(os.path.exists(target))
        finally:
            if os.path.exists(target):
                os.remove(target)

    def test_a_script_harness_gets_the_scratch_and_smoke_environment(self):
        script = os.path.join(self.d, "script.sh")
        with open(script, "w") as f:
            f.write('#!/bin/sh\nprintf \'%s %s %s\\n\' "$OUT" "$FILES" "$DIR" > "$SCRIPT_REPORT"\n')
        os.chmod(script, 0o755)
        report = os.path.join(self.d, "report")
        c = contract(harness={"script": script}, ordering={"scheme": "shuffle", "seed": {"env": "SHUF_SEED", "recorded_as": "shuffle_seed"}})
        c["run"]["smoke_env"] = {"FILES": "4", "EXT4": "{scratch}/ext4"}
        r = self.run_runner(c, "--smoke", "--out", self.out, env=self.env(SCRIPT_REPORT=report))
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(report) as f:
            out, files, dirp = f.read().split()
        self.assertEqual((out, files), (self.out, "4"))
        self.assertIn("micro-smoke-fake-", dirp)

    def test_a_script_that_prints_its_records_on_stdout_gets_them_stamped_and_appended(self):
        script = os.path.join(self.d, "printer.sh")
        with open(script, "w") as f:
            f.write('#!/bin/sh\necho \'{"schema":"sentinel-bench/fake/1","from":"script"}\'\n')
        os.chmod(script, 0o755)
        c = contract(harness={"script": script})
        c["record"]["from_stdout"] = True
        r = self.run_runner(c, "--out", self.out, env=self.env())
        self.assertEqual(r.returncode, 0, r.stderr)
        rec = self.lines()[0]
        self.assertEqual(rec["from"], "script")
        self.assertIn("build", rec)
        self.assertIn("lock", rec)
        self.assertEqual(rec["contract"]["id"], "fake")
        c["record"].pop("from_stdout")
        r = self.run_runner(c, "--out", self.out + "2", env=self.env())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(self.out + "2"), "without from_stdout the script is its own writer and nothing is appended")


@unittest.skipUnless(LINUX, "needs Linux, flock and sh")
class LockRefusal(unittest.TestCase):
    def test_a_lock_that_cannot_be_opened_is_a_refusal_naming_it_not_a_traceback(self):
        path = os.path.join(tempfile.gettempdir(), "no-such-dir-micro", "verify.lock")
        with self.assertRaises(micro_contract.Refused) as caught:
            micro_contract.take_lock(path)
        self.assertEqual(caught.exception.code, 3)
        self.assertIn(path, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
