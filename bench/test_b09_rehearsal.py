"""The B09 harness and its gate run end to end against a fake (bench/fake/b09): a fake `sentinel` and shims for the
host commands the harness runs as root. No root, no namespaces, no containers, no network beyond loopback.

    python3 -m unittest bench/test_b09_rehearsal.py        (Linux verification host; about ten minutes)

What this proves: the harness's orchestration (provisioning order, the records it writes, the assertions it makes),
that its cleanup undoes everything it created and survives a SIGKILL of the harness, that the fleet leg drives its
hosts through the exec prefix and releases them, and that the assertions can fail (a fake defect turns each named one
false). What it cannot prove: anything about Sentinel, or any duration. Every record is marked simulated and
rehearsal, and the gate refuses such a record.
"""
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
HARNESS = os.path.join(HERE, "b09-harness.py")
GATE = os.path.join(HERE, "b09-gate.py")
FAKE = os.path.join(HERE, "fake", "b09")
SHIMMED = ["ip", "tc", "losetup", "dmsetup", "blockdev", "modprobe", "mkfs.ext4", "mount", "umount", "chown", "runuser",
           "nsenter", "id", "podman", "fallocate"]
LINUX = sys.platform.startswith("linux") and shutil.which("flock") and shutil.which("git") and shutil.which("openssl")


def free_port_base():
    for base in range(31000 + (os.getpid() * 7) % 3000, 38000, 11):
        socks = []
        try:
            for p in (base, base + 1, base + 2):
                s = socket.socket()
                s.bind(("127.0.0.1", p))
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                s.close()
    raise RuntimeError("no free port range")


def read(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


@unittest.skipUnless(LINUX, "needs Linux, flock, git and openssl")
class Rehearsal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = self.d = self.tmp.name
        # A checkout does not promise executable bits: the kit and the shims are used from copies that have them.
        self.kit = os.path.join(d, "kit")
        shutil.copytree(os.path.join(FAKE, "kit"), self.kit)
        for name in os.listdir(self.kit):
            os.chmod(os.path.join(self.kit, name), 0o755)
        self.shims = os.path.join(d, "shims")
        os.makedirs(self.shims)
        for name in SHIMMED:
            shutil.copy(os.path.join(FAKE, "shim"), os.path.join(self.shims, name))
            os.chmod(os.path.join(self.shims, name), 0o755)
        self.state, self.log = os.path.join(d, "state"), os.path.join(d, "calls.log")
        self.root, self.out = os.path.join(d, "root"), os.path.join(d, "b09.jsonl")
        self.home = os.path.join(d, "home")
        os.makedirs(self.home)
        self.lock = os.path.join(d, "lock")
        self.base = free_port_base()
        self.procs = []
        self.addCleanup(self.reap)

    def reap(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        subprocess.run([sys.executable, HARNESS, "cleanup", "--root", self.root], env=self.env(), capture_output=True)

    def env(self, **extra):
        e = {k: v for k, v in os.environ.items() if not k.startswith(("FAKE_", "B09_", "SENTINEL_"))}
        e.update(PATH=self.shims + os.pathsep + os.environ["PATH"], B09_REHEARSAL="1", FAKE_STATE=self.state,
                 FAKE_LOG=self.log, B09_PORT_BASE=str(self.base), B09_BENCH_HOME=self.home,
                 SENTINEL_BENCH_HOST_LABEL="smoke-host", SENTINEL_VERIFY_LOCK=self.lock, B09_TIMEOUT_CAP="20",
                 FAKE_TIME_SCALE="0.1")
        e.update(extra)
        return e

    def args(self, scenarios, *more, out=None):
        return [sys.executable, HARNESS, "run", "--kit", self.kit, "--root", self.root, "--out", out or self.out,
                "--source", REPO, "--scenarios", scenarios, *more]

    def run_harness(self, scenarios, *more, timeout=600, **env):
        r = subprocess.run(self.args(scenarios, *more), capture_output=True, text=True, env=self.env(**env), timeout=timeout)
        return r

    def calls(self):
        if not os.path.exists(self.log):
            return []
        with open(self.log) as f:
            return f.read().splitlines()

    def leftovers(self):
        out = {}
        for sub in ("netns", "links", "qdisc", "loops", "dm", "mounts"):
            p = os.path.join(self.state, sub)
            out[sub] = sorted(os.listdir(p)) if os.path.isdir(p) else []
        return {k: v for k, v in out.items() if v}

    def only(self, kind=None):
        recs = read(self.out)
        return [r for r in recs if kind is None or r["kind"] == kind]

    # -- performance scenarios -------------------------------------------------------------------------------

    def test_steady_gives_one_perf_record_per_repeat_with_every_run_accounted_for(self):
        r = self.run_harness("w1-steady", "--repeats", "3", "--runs", "20", "--no-lock")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        recs = self.only()
        self.assertEqual([x["kind"] for x in recs], ["perf"] * 3)
        want = hashlib.sha256(open(os.path.join(self.kit, "sentinel"), "rb").read()).hexdigest()
        for i, rec in enumerate(recs):
            self.assertEqual(rec["schema"], "sentinel-bench/b09/1")
            self.assertEqual(rec["repeat"], i)
            self.assertEqual((rec["passed"], rec["failed"]), (20, 0))
            self.assertEqual(rec["summary"]["overhead_ns"]["n"], 20)
            self.assertIs(rec["summary"]["overhead_ns"]["p95_is_max"], False)
            self.assertEqual(rec["build"]["binary_sha256"], want, "the record names the kit's binary")
            self.assertEqual(rec["build"]["commit"], subprocess.run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip())
            self.assertEqual(rec["host"]["hostname"], "smoke-host")
            self.assertIs(rec["simulated"], True)
            self.assertIs(rec["rehearsal"], True)
            self.assertEqual(rec["scenario"]["id"], "w1-steady")
            self.assertEqual(len({r["run"] for r in rec["runs"]}), 20)

    def test_a_burst_spreads_over_every_worker_and_all_runs_pass(self):
        r = self.run_harness("w3-burst", "--repeats", "1", "--runs", "20", "--no-lock", FAKE_SLOTS="3")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        rec = self.only("perf")[0]
        self.assertEqual((rec["passed"], rec["failed"]), (20, 0))
        import sqlite3
        con = sqlite3.connect(os.path.join(self.root, "run", "w3-burst", "controller", "metadata.sqlite"))
        workers = con.execute("SELECT COUNT(DISTINCT worker_id) FROM attempts").fetchone()[0]
        con.close()
        self.assertEqual(workers, 3, "the 20 runs were placed on all three workers")

    def test_link_shaping_and_an_injected_handicap_reach_both_ends_of_the_link(self):
        r = self.run_harness("link-loss-5pct-steady", "--repeats", "1", "--runs", "20", "--no-lock", "--handicap-delay-ms", "10")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        calls = self.calls()
        for dev in ("b09n1", "b09h1"):
            self.assertTrue(any(c.startswith(f"tc qdisc replace dev {dev} root netem delay 10ms 0ms loss 5.0%") for c in calls), (dev, [c for c in calls if c.startswith("tc")]))
        rec = self.only("perf")[0]
        self.assertEqual(rec["scenario"]["injected_handicap"], {"delay_ms_each_way": 10})
        self.assertEqual(rec["scenario"]["link_shape"], {"loss_pct": 5.0})
        self.assertEqual(self.leftovers(), {}, "the shaping went with the links")

    def test_a_429_is_waited_out_and_counted(self):
        r = self.run_harness("w1-steady", "--repeats", "1", "--runs", "20", "--no-lock", FAKE_429_EVERY="3")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        rec = self.only("perf")[0]
        self.assertEqual(rec["passed"], 20)
        self.assertGreater(sum(x["retries_429"] for x in rec["runs"]), 0)

    def test_slow_disks_create_and_remove_every_loop_device_dm_target_and_mount(self):
        r = self.run_harness("disk-slow-worker-steady,disk-slow-controller-steady", "--repeats", "1", "--runs", "20", "--no-lock")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        self.assertEqual([x["kind"] for x in self.only()], ["perf", "perf"])
        calls = self.calls()
        for made in ("losetup -f --show", "dmsetup create", "mount /dev/mapper/", "ip netns add", "ip link add b09br"):
            self.assertTrue(any(c.startswith(made) for c in calls), made)
        self.assertTrue(any(c.startswith("dmsetup remove") for c in calls))
        self.assertTrue(any(c.startswith("umount ") for c in calls))
        self.assertEqual(self.leftovers(), {}, "everything the harness created was removed")
        self.assertFalse(os.path.exists(os.path.join(self.root, "img")) and os.listdir(os.path.join(self.root, "img")))

    # -- reliability scenarios -------------------------------------------------------------------------------

    def reliability(self, name, **env):
        r = self.run_harness(name, "--no-lock", **dict({"FAKE_SLOTS": "30", "FAKE_TIME_SCALE": "1.0"}, **env))
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        recs = self.only("reliability")
        self.assertEqual(len(recs), 1, [x["kind"] for x in self.only()])
        return recs[0], {a["name"]: a["ok"] for a in recs[0]["assertions"]}

    def test_a_worker_kill_a_controller_kill_and_a_partition_all_hold(self):
        for name in ("restart-worker-kill", "restart-controller-kill", "partition"):
            with self.subTest(name):
                if os.path.exists(self.out):
                    os.remove(self.out)
                rec, asserts = self.reliability(name)
                self.assertIs(rec["ok"], True, rec["assertions"])
                self.assertTrue(asserts)
                self.assertTrue(all(asserts.values()), asserts)
                if name != "partition":
                    self.assertIn("passed", rec["observations"]["states"])
                    self.assertTrue(any(a > 1 for a in rec["observations"]["attempts_per_run"]),
                                    "something was in flight when the fault hit (a run needed a second attempt)")
                else:
                    self.assertEqual(rec["observations"]["link_lost_events"], 0)
                    self.assertTrue(any(c.startswith("tc qdisc replace dev b09n1 root netem loss 100%") for c in self.calls()))
                    self.assertTrue(any(c.startswith("tc qdisc del dev b09n1 root") for c in self.calls()), "the partition was healed")
                self.assertEqual(self.leftovers(), {})

    def test_losing_runs_across_a_controller_restart_makes_the_named_assertion_false(self):
        rec, asserts = self.reliability("restart-controller-kill", FAKE_DEFECT="lose-run-on-restart")
        self.assertIs(rec["ok"], False)
        self.assertIs(asserts["no run lost its verdict (all passed)"], False)
        self.assertIs(asserts["every worker reconnected"], True)

    def test_workers_that_never_reconnect_make_the_named_assertion_false(self):
        rec, asserts = self.reliability("restart-controller-kill", FAKE_DEFECT="never-reconnect")
        self.assertIs(rec["ok"], False)
        self.assertIs(asserts["every worker reconnected"], False)

    def test_the_scenarios_that_would_fill_a_real_file_system_or_need_tailcat_are_recorded_blocked(self):
        r = self.run_harness("disk-full-controller,disk-full-worker,tailcat-relay", "--no-lock")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        recs = self.only()
        self.assertEqual([(x["kind"], x["scenario"]["id"]) for x in recs],
                         [("blocked", "disk-full-controller"), ("blocked", "disk-full-worker"), ("blocked", "tailcat-relay")])
        self.assertIn("shimmed", recs[0]["blocked_by"])
        self.assertFalse([c for c in self.calls() if c.startswith("fallocate")], "no filler ran")
        self.assertEqual(self.leftovers(), {})

    # -- the guards around the rehearsal ---------------------------------------------------------------------

    def test_a_rehearsal_record_is_not_evidence_for_the_gate(self):
        self.assertEqual(self.run_harness("w1-steady", "--repeats", "1", "--runs", "20", "--no-lock").returncode, 0)
        g = subprocess.run([sys.executable, GATE, self.out, self.out], capture_output=True, text=True)
        self.assertEqual(g.returncode, 2, g.stdout + g.stderr)
        self.assertIn("simulated", g.stderr)

    def test_the_output_may_not_be_inside_bench(self):
        target = os.path.join(HERE, "b09-rehearsal-must-not-exist.jsonl")
        try:
            r = subprocess.run(self.args("w1-steady", "--no-lock", out=target), capture_output=True, text=True, env=self.env())
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("inside bench/", r.stderr)
            self.assertFalse(os.path.exists(target))
        finally:
            if os.path.exists(target):
                os.remove(target)

    def test_without_the_shims_the_rehearsal_refuses_to_start(self):
        env = self.env()
        env["PATH"] = os.environ["PATH"]
        r = subprocess.run(self.args("w1-steady", "--no-lock"), capture_output=True, text=True, env=env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not the fake shim", r.stderr)
        self.assertFalse(os.path.exists(self.out))

    def test_a_missing_host_label_refuses_before_any_scenario(self):
        r = self.run_harness("w1-steady", "--no-lock", SENTINEL_BENCH_HOST_LABEL="")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(read(self.out), [])
        self.assertEqual(self.calls(), [], "nothing was provisioned")

    def test_the_second_run_waits_for_the_lock_and_proceeds_when_it_is_released(self):
        import fcntl
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT)
        fcntl.flock(fd, fcntl.LOCK_EX)
        p = subprocess.Popen(self.args("w1-steady", "--repeats", "1", "--runs", "20"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, env=self.env())
        self.procs.append(p)
        try:
            time.sleep(3)
            self.assertIsNone(p.poll(), "the run went ahead without the lock")
            self.assertEqual(read(self.out), [])
            self.assertEqual(self.calls(), [], "nothing was provisioned while the lock was held elsewhere")
        finally:
            os.close(fd)
        _out, err = p.communicate(timeout=300)
        self.assertEqual(p.returncode, 0, err[-3000:])
        self.assertIn("waiting for the exclusive lock", err)
        self.assertEqual(len(self.only("perf")), 1)

    # -- cleanup ---------------------------------------------------------------------------------------------

    def test_a_harness_killed_mid_scenario_leaves_nothing_after_cleanup_and_cleanup_is_idempotent(self):
        p = subprocess.Popen(self.args("restart-worker-kill", "--no-lock"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env=self.env(FAKE_SLOTS="30", FAKE_TIME_SCALE="1.0"))
        self.procs.append(p)
        pids_dir = os.path.join(self.root, "pids")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if os.path.isdir(pids_dir) and {"server", "worker1", "worker3"} <= set(os.listdir(pids_dir)):
                break
            time.sleep(0.2)
        else:
            self.fail("the scenario never started its processes")
        time.sleep(1)
        children = [int(open(os.path.join(pids_dir, f)).read()) for f in os.listdir(pids_dir)]
        self.assertTrue(all(alive(c) for c in children), "the controller, workers and Git fixture are running")
        self.assertTrue(self.leftovers().get("netns"), "the namespaces exist")
        p.send_signal(signal.SIGKILL)
        p.wait()
        self.assertTrue(any(alive(c) for c in children), "a SIGKILLed harness runs no cleanup of its own")
        for _ in range(2):
            c = subprocess.run([sys.executable, HARNESS, "cleanup", "--root", self.root], capture_output=True, text=True, env=self.env())
            self.assertEqual(c.returncode, 0, c.stderr)
        time.sleep(0.5)
        self.assertEqual([c for c in children if alive(c)], [], "cleanup killed every recorded process group")
        self.assertEqual(self.leftovers(), {})
        self.assertEqual(os.listdir(pids_dir), [])
        self.assertFalse(os.path.exists(os.path.join(self.root, "img")))

    # -- fleet mode ------------------------------------------------------------------------------------------

    def test_a_fleet_scenario_drives_its_hosts_through_the_exec_prefix_and_releases_them(self):
        # One work_dir per host, as on a real fleet: hosts that shared one would write each other's worker config,
        # enrollment and identity files (the slot numbers restart at 1 on every host).
        works = {lb: os.path.join(self.d, f"fleetwork-{lb}") for lb in ("alpha", "beta", "gamma")}
        for w in works.values():
            os.makedirs(w)
        fleet = {"controller": {"address": "127.0.0.1", "worker_bootstrap": {"release_url": "https://r.example.test/x", "release_sums": "/etc/SUMS"}},
                 "hosts": [{"label": lb, "exec": ["env"], "sentinel": os.path.join(self.kit, "sentinel"), "work_dir": works[lb],
                            "api_url": f"http://127.0.0.1:{self.base + 1}", "identities": 1} for lb in ("alpha", "beta", "gamma")]}
        path = os.path.join(self.d, "fleet.json")
        with open(path, "w") as f:
            json.dump(fleet, f)
        r = self.run_harness("fleet-w3-burst", "--fleet", path, "--repeats", "1", "--runs", "20", "--no-lock", FAKE_SLOTS="3")
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        recs = self.only()
        self.assertEqual([x["kind"] for x in recs], ["perf"], recs)
        rec = recs[0]
        self.assertEqual(rec["passed"], 20)
        self.assertEqual(sorted(rec["fleet_hosts"]), ["alpha", "beta", "gamma"])
        self.assertEqual(sum(rec["runs_by_host"].values()), 20)
        self.assertEqual(sorted(rec["runs_by_host"]), ["alpha", "beta", "gamma"], "every host ran something")
        self.assertEqual(sorted(rec["summary_by_host"]), ["alpha", "beta", "gamma"])
        self.assertIn("fleet", rec["scenario"])
        for lb, w in works.items():
            self.assertFalse(os.path.exists(os.path.join(w, "b09-fleet-w3-burst")), f"host {lb} was released")
        self.assertEqual(os.listdir(os.path.join(self.root, "fleet")), [])
        self.assertEqual(self.leftovers(), {})
        leaked = subprocess.run(["pgrep", "-f", os.path.join(self.kit, "fake-sentinel.py") + " worker"], capture_output=True, text=True)
        self.assertEqual(leaked.stdout.split(), [], "no fake worker survives the release")


if __name__ == "__main__":
    unittest.main()
