"""Unit tests for the B09 fleet mode: the fleet file, the identity plan, and the remote cleanup guarantees.

Run on the verification host: python3 bench/test_b09_fleet.py. Nothing here needs root or a real fleet; the
"remote host" of the cleanup tests is this machine reached through `env` as the exec prefix.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest

if "fcntl" not in sys.modules:
    try:
        import fcntl  # noqa: F401
    except ImportError:  # the harness runs on Linux; the planning tests also run elsewhere
        sys.modules["fcntl"] = types.ModuleType("fcntl")

HERE = os.path.dirname(__file__)
spec = importlib.util.spec_from_file_location("b09_harness", os.path.join(HERE, "b09-harness.py"))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

GIB = 1 << 30


def host(label, **over):
    base = {"label": label, "exec": ["env"], "sentinel": "/usr/local/bin/sentinel", "work_dir": "/var/tmp/w",
            "api_url": "https://ci.example.test", "identities": 1, "ceilings": None, "priority": 0, "arch": None}
    base.update(over)
    return base


def write_fleet(tmp, hosts, **controller):
    c = {"address": "192.0.2.10", "worker_bootstrap": {"release_url": "https://r.example.test/x", "release_sums": "/etc/SUMS"}}
    c.update(controller)
    path = os.path.join(tmp, "fleet.json")
    with open(path, "w") as f:
        json.dump({"controller": c, "hosts": hosts}, f)
    return path


class FleetFile(unittest.TestCase):
    def load(self, hosts, **controller):
        with tempfile.TemporaryDirectory() as tmp:
            return h.load_fleet(write_fleet(tmp, hosts, **controller))

    def refused(self, hosts, needle, **controller):
        with self.assertRaises(SystemExit) as cm:
            self.load(hosts, **controller)
        self.assertIn(needle, str(cm.exception))

    def test_valid_file_loads(self):
        f = self.load([host("a", identities=4, ceilings={"cpu_millis": 4000}, priority=5), host("b")])
        self.assertEqual([x["label"] for x in f["hosts"]], ["a", "b"])
        self.assertEqual(f["hosts"][0]["priority"], 5)

    def test_refusals(self):
        self.refused([host("a")], "reachable from the worker hosts", address="127.0.0.1")
        self.refused([host("a")], "controller.address", address="ci.example.test")
        self.refused([host("a"), host("a")], "unique")
        self.refused([host("A")], "lower-case")
        self.refused([host("a", exec=[])], "exec")
        self.refused([host("a", sentinel="sentinel")], "absolute path")
        self.refused([host("a", identities=0)], "identities")
        self.refused([host("a", identities=11)], "identities")
        self.refused([host("a", ceilings={"cpu_millis": 0})], "ceilings")
        self.refused([host("a", ceilings={"gpu": 1})], "ceilings")
        self.refused([host("a", priority=101)], "priority")
        self.refused([host("a"), host("b", api_url="https://other.example.test")], "same api_url")
        self.refused([host("a")], "worker_bootstrap", worker_bootstrap={})
        self.refused([], "at least one")


class Plan(unittest.TestCase):
    def fleet(self, *hosts):
        return {"controller": {"address": "192.0.2.10"}, "hosts": list(hosts)}

    def test_one_three_ten_over_three_hosts(self):
        hs = [dict(host(l, identities=4, ceilings={"cpu_millis": 4000, "memory_bytes": 8 * GIB, "disk_bytes": 40 * GIB},
                        priority=p), ceilings={"cpu_millis": 4000, "memory_bytes": 8 * GIB, "disk_bytes": 40 * GIB})
              for l, p in (("a", 0), ("b", 0), ("c", 10))]
        for x in hs:
            x["arch"] = None
        f = self.fleet(*hs)
        self.assertEqual([p["host"] for p in h.plan_fleet(f, 1)], ["a"])
        self.assertEqual(sorted(p["host"] for p in h.plan_fleet(f, 3)), ["a", "b", "c"])
        ten = h.plan_fleet(f, 10)
        per_host = {l: sum(1 for p in ten if p["host"] == l) for l in "abc"}
        self.assertEqual(sorted(per_host.values()), [3, 3, 4])
        self.assertEqual([p["index"] for p in ten], list(range(1, 11)))
        self.assertEqual(len({p["name"] for p in ten}), 10)
        for label, count in per_host.items():
            mine = [p for p in ten if p["host"] == label]
            # the identities of one host together never exceed the host's approved ceiling
            for key, total in (("cpu_millis", 4000), ("memory_bytes", 8 * GIB), ("disk_bytes", 40 * GIB)):
                self.assertLessEqual(sum(p["ceilings"][key] for p in mine), total)
            self.assertEqual(mine[0]["ceilings"]["cpu_millis"], 4000 // count)
        self.assertEqual({p["priority"] for p in ten if p["host"] == "c"}, {10})

    def test_single_identity_hosts_keep_the_whole_ceiling(self):
        a = dict(host("a", ceilings={"cpu_millis": 2000}), arch=None)
        p = h.plan_fleet(self.fleet(a), 1)[0]
        self.assertEqual(p["ceilings"], {"cpu_millis": 2000})

    def test_no_ceilings_on_a_single_identity_host_means_none_approved(self):
        a = dict(host("a"), ceilings=None)
        self.assertIsNone(h.plan_fleet(self.fleet(a), 1)[0]["ceilings"])

    def test_blocked_without_capacity(self):
        a, b = dict(host("a"), ceilings=None), dict(host("b"), ceilings=None)
        with self.assertRaises(h.Blocked) as cm:
            h.plan_fleet(self.fleet(a, b), 3)
        self.assertIn("allows 2", str(cm.exception))

    def test_blocked_when_a_shared_host_has_no_ceilings(self):
        a = dict(host("a", identities=3), ceilings=None)
        with self.assertRaises(h.Blocked) as cm:
            h.plan_fleet(self.fleet(a), 3)
        self.assertIn("declares no ceilings", str(cm.exception))

    def test_blocked_when_a_ceiling_cannot_be_split(self):
        a = dict(host("a", identities=3), ceilings={"cpu_millis": 2})
        with self.assertRaises(h.Blocked):
            h.plan_fleet(self.fleet(a), 3)

    def test_shape_names_hosts_and_shares_and_skips_unused_hosts(self):
        a = dict(host("a", identities=2), ceilings={"cpu_millis": 2000}, arch="x86_64", priority=1)
        b = dict(host("b"), ceilings=None, arch="aarch64", priority=0)
        f = self.fleet(a, b)
        shape = h.fleet_shape(f, h.plan_fleet(f, 2))
        self.assertEqual(sorted(shape), ["a", "b"])  # one identity each: least loaded first
        shape3 = h.fleet_shape(f, h.plan_fleet(f, 3))
        self.assertEqual(shape3["a"]["identities"], 2)
        self.assertEqual(shape3["a"]["per_identity_ceilings"], {"cpu_millis": 1000})
        only_a = h.fleet_shape(self.fleet(a), h.plan_fleet(self.fleet(a), 1))
        self.assertEqual(list(only_a), ["a"])


class Scenarios(unittest.TestCase):
    def test_fleet_scenarios_are_the_perf_matrix_and_nothing_else(self):
        self.assertEqual(sorted(h.FLEET_SCENARIOS), sorted(f"fleet-w{n}-{m}" for n in (1, 3, 10) for m in ("steady", "burst")))
        for name, s in h.FLEET_SCENARIOS.items():
            self.assertEqual(s["kind"], "perf")
            self.assertTrue(s["fleet"])
            self.assertNotIn("disk", s)
            self.assertNotIn("link", s)
        for name, s in h.SCENARIOS.items():
            if name not in h.FLEET_SCENARIOS:
                self.assertFalse(s.get("fleet"))


class RemoteCleanup(unittest.TestCase):
    """The remote host is this machine, reached through `env`."""

    def start(self, parent, cfg):
        os.makedirs(parent, exist_ok=True)
        p = subprocess.Popen(["setsid", "sh", "-c", "sleep 300; :", "_", cfg],
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        return p

    def record(self, tmp, parent, cfg, pid):
        path = os.path.join(tmp, "rec.json")
        with open(path, "w") as f:
            json.dump({"host": "a", "exec": ["env"], "parent": parent, "config": cfg, "pid": pid, "worker_id": None}, f)
        return path

    def test_release_stops_the_recorded_process_and_removes_only_the_b09_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = os.path.join(tmp, "b09-fleet-w1-steady")
            cfg = os.path.join(parent, "w1.toml")
            p = self.start(parent, cfg)
            rec = self.record(tmp, parent, cfg, p.pid)
            h.fleet_release(rec)
            p.wait(timeout=10)
            self.assertIsNotNone(p.returncode)
            self.assertFalse(os.path.exists(parent))
            self.assertFalse(os.path.exists(rec))
            h.fleet_release(rec)  # idempotent

    def test_a_reused_pid_that_is_not_our_worker_is_not_signalled(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = os.path.join(tmp, "b09-x")
            other = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
            try:
                rec = self.record(tmp, parent, os.path.join(parent, "w1.toml"), other.pid)
                h.fleet_release(rec)
                self.assertIsNone(other.poll())
            finally:
                other.kill()
                other.wait()

    def test_refuses_a_directory_that_is_not_b09(self):
        with self.assertRaises(RuntimeError):
            h.release_script({"parent": "/var/lib/sentinel-worker", "config": "/x", "pid": 5, "worker_id": None})

    def test_cleanup_walks_every_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "fleet"))
            procs = []
            for i in (1, 2):
                parent = os.path.join(tmp, f"b09-s{i}")
                cfg = os.path.join(parent, "w.toml")
                p = self.start(parent, cfg)
                procs.append((p, parent))
                with open(os.path.join(tmp, "fleet", f"s-{i}.json"), "w") as f:
                    json.dump({"host": "a", "exec": ["env"], "parent": parent, "config": cfg, "pid": p.pid, "worker_id": None}, f)
            h.fleet_cleanup(tmp)
            for p, parent in procs:
                p.wait(timeout=10)
                self.assertFalse(os.path.exists(parent))
            self.assertEqual(os.listdir(os.path.join(tmp, "fleet")), [])


if __name__ == "__main__":
    unittest.main()
