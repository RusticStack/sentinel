"""bench/m06-start.sh and bench/m01-detect.sh against stand-ins for `cargo` and `sentinel`."""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
LINUX = sys.platform.startswith("linux")

FAKE_CARGO = r"""#!/usr/bin/env bash
{ echo "tests=${SENTINEL_MICROVM_TESTS-unset} bench=${SENTINEL_MICROVM_BENCH-unset}"; echo "args=$*"; } >> "$FAKE_LOG"
case "${FAKE_MODE:-ok}" in
  ok)
    printf '%s\n' '{"schema":"sentinel-bench/m06/1","mode":"cold","samples":3}' '{"schema":"sentinel-bench/m06/1","mode":"restore","samples":3}' > "$SENTINEL_MICROVM_BENCH_OUT"
    echo 'test result: ok. 1 passed; 0 failed; 0 ignored' ;;
  skip) echo 'skipped: set SENTINEL_MICROVM_BENCH=<samples per path> on a quiet KVM host' >&2; echo 'test result: ok. 1 passed; 0 failed; 0 ignored' ;;
  fail) echo 'test result: FAILED. 0 passed; 1 failed'; exit 101 ;;
  one) printf '%s\n' '{"schema":"sentinel-bench/m06/1","mode":"cold"}' > "$SENTINEL_MICROVM_BENCH_OUT"; echo 'test result: ok. 1 passed; 0 failed' ;;
esac
"""

FAKE_SENTINEL = r"""#!/usr/bin/env bash
echo "$*" >> "$FAKE_LOG"
case "${FAKE_MODE:-ok}" in
  ok) echo 'worker check passed'; echo 'runtime: kvm=true nested=false default=microvm capabilities=kvm,isolation.container,isolation.microvm,os.linux' ;;
  noline) echo 'worker check passed' ;;
  fail) echo 'bad config' >&2; exit 1 ;;
esac
"""


def script(path, text):
    with open(path, "w", newline="\n") as f:
        f.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


@unittest.skipUnless(LINUX, "needs Linux and bash")
class Scripts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="m-scripts-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        script(os.path.join(self.bin, "cargo"), FAKE_CARGO)
        self.sentinel = os.path.join(self.bin, "sentinel")
        script(self.sentinel, FAKE_SENTINEL)
        self.log = os.path.join(self.tmp, "log")

    def run_script(self, name, *argv, mode="ok"):
        env = dict(os.environ, PATH=self.bin + os.pathsep + os.environ["PATH"], FAKE_LOG=self.log, FAKE_MODE=mode,
                   TMPDIR=self.tmp, SENTINEL_SRC=REPO, SENTINEL_BIN=self.sentinel, SENTINEL_BENCH_HOST_LABEL="test-host")
        return subprocess.run(["bash", os.path.join(HERE, name), *argv], capture_output=True, text=True, env=env)

    def calls(self):
        with open(self.log) as f:
            return f.read()

    def test_m06_prints_the_cold_and_restore_records_and_opts_in_to_the_vm_test(self):
        r = self.run_script("m06-start.sh", "--samples", "3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([json.loads(l)["mode"] for l in r.stdout.splitlines()], ["cold", "restore"])
        self.assertIn("tests=1 bench=3", self.calls())
        self.assertIn("--exact", self.calls())
        self.assertEqual(os.listdir(self.tmp).count("m06-start"), 0)
        self.assertFalse([d for d in os.listdir(self.tmp) if d.startswith("m06-start.")], "the scratch directory is removed")

    def test_m06_is_pending_when_the_test_skipped_itself(self):
        r = self.run_script("m06-start.sh", mode="skip")
        self.assertEqual(r.returncode, 75)
        self.assertEqual(r.stdout, "")

    def test_m06_keeps_the_failure_status_and_refuses_a_partial_result(self):
        r = self.run_script("m06-start.sh", mode="fail")
        self.assertEqual((r.returncode, r.stdout), (101, ""))
        r = self.run_script("m06-start.sh", mode="one")
        self.assertEqual((r.returncode, r.stdout), (2, ""))
        for bad in (("--samples", "0"), ("--samples", "x"), ("--bogus",)):
            self.assertEqual(self.run_script("m06-start.sh", *bad).returncode, 2, bad)

    def test_m01_states_what_the_check_printed_with_the_stamp(self):
        cfg = os.path.join(self.tmp, "worker.toml")
        open(cfg, "w").close()
        r = self.run_script("m01-detect.sh", f"controller link and [microvm] setup configured={cfg}", "no controller, no [microvm]=")
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [json.loads(l) for l in r.stdout.splitlines()]
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["schema"], "sentinel-detection/m01/1")
        self.assertEqual((rows[0]["kvm"], rows[0]["nested"], rows[0]["default"]), (True, False, "microvm"))
        self.assertEqual(rows[0]["capabilities"], ["kvm", "isolation.container", "isolation.microvm", "os.linux"])
        self.assertIs(rows[0]["benchmark"], False)
        self.assertEqual(rows[0]["host"]["hostname"], "test-host")
        self.assertRegex(rows[0]["build"]["commit"], r"^[0-9a-f]{7,40}$")
        self.assertIn(f"worker --check --config {cfg}", self.calls())
        self.assertTrue(re.search(r"^worker --check$", self.calls(), re.M), "the second configuration runs the check bare")

    def test_m01_writes_nothing_for_a_check_that_failed_or_printed_no_runtime_line(self):
        for mode in ("fail", "noline"):
            r = self.run_script("m01-detect.sh", "x=", mode=mode)
            self.assertNotEqual(r.returncode, 0, mode)
            self.assertEqual(r.stdout, "", mode)
        self.assertEqual(self.run_script("m01-detect.sh", "not-a-pair").returncode, 2)


if __name__ == "__main__":
    unittest.main()
