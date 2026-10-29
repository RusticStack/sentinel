"""The B05 matrix scripts run end to end at smoke size against stub toolchains (bench/fake/b05).

    cargo build --release --locked -p sentinel-cache --example b05-cache
    python3 -m unittest bench/test_b05_matrix.py        (Linux verification host)

The cache driver runs for real at tiny sizes (plain Linux code, copy backend); only the toolchains and the failing
cell are stand-ins. What this proves: the scripts' plumbing, the record shape, the shuffle and its recorded seed, the
lock, the failure accounting. It proves nothing about cache cost: every record is marked "smoke":true and the scripts
refuse to write one into bench/.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CACHE = os.path.join(HERE, "b05-cache.sh")
WORKLOADS = os.path.join(HERE, "b05-workloads.sh")
FAKE = os.path.join(HERE, "fake", "b05")
LINUX = sys.platform.startswith("linux") and shutil.which("flock") and shutil.which("bash") and shutil.which("shuf")

CELLS = {"mid-20k-8k", "tree-500k", "mix-10g", "big-10g"}
RECORD_KEYS = {"record", "label", "shape", "backend", "hw", "build", "host", "shuffle_seed", "position", "pass", "smoke",
               "load_start", "load_end", "dist"}
LANGS = ["go", "rust", "js", "python", "java", "custom"]


def driver():
    for base in (os.environ.get("CARGO_TARGET_DIR"), os.path.join(REPO, "target")):
        if base:
            p = os.path.join(base, "release", "examples", "b05-cache")
            if os.path.isfile(p):
                return p
    return None


def read(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


@unittest.skipUnless(LINUX, "needs Linux, flock, bash and shuf")
class Matrix(unittest.TestCase):
    def setUp(self):
        self.bin = driver()
        if self.bin is None:
            self.skipTest("skipped: build the driver first: cargo build --release --locked -p sentinel-cache --example b05-cache")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.out = os.path.join(self.d, "b05.jsonl")
        self.lock = os.path.join(self.d, "lock")
        self.fake_log = os.path.join(self.d, "calls.log")
        # A checkout does not promise executable bits: the stubs are used from a copy that has them.
        self.fake = os.path.join(self.d, "fake-b05")
        shutil.copytree(FAKE, self.fake)
        for dirpath, _dirs, files in os.walk(self.fake):
            for name in files:
                if name != "lib.sh":
                    os.chmod(os.path.join(dirpath, name), 0o755)

    def env(self, **extra):
        base = {k: v for k, v in os.environ.items()
                if not k.startswith(("SENTINEL_", "SHUF_", "FAKE_", "B05_")) and k not in ("OUT", "BIN", "ROOT", "REPS", "PASSES")}
        base.update(ROOT=REPO, BIN=self.bin, OUT=self.out, SENTINEL_SRC=REPO, SENTINEL_BENCH_HOST_LABEL="smoke-host",
                    SENTINEL_VERIFY_LOCK=self.lock, B05_DATA=os.path.join(self.d, "data"), B05_TOOLS=self.fake,
                    FAKE_LOG=self.fake_log, SHUF_SEED="seed-one", REPS="2",
                    SENTINEL_PRESSURE_FILE=self.pressure_file())
        base.update(extra)
        return base

    def pressure_file(self):
        p = os.path.join(self.d, "pressure")
        if not os.path.exists(p):
            with open(p, "w") as f:
                f.write("some avg10=0.50 avg60=0.50 avg300=0.50 total=0\n")
        return p

    def cache(self, *args, **env):
        return subprocess.run(["bash", CACHE, "--profile", "smoke", *args], capture_output=True, text=True, env=self.env(**env))

    def workloads(self, *args, **env):
        return subprocess.run(["bash", WORKLOADS, "--profile", "smoke", *args], capture_output=True, text=True, env=self.env(**env))

    def order(self, records):
        """{pass: [shape in the order they ran]} from the recorded positions."""
        by = {}
        for r in records:
            by.setdefault(r["pass"], {})[r["shape"]] = r["position"]
        return {p: [s for s, _ in sorted(m.items(), key=lambda kv: kv[1])] for p, m in by.items()}

    # -- the synthetic matrix --------------------------------------------------------------------------------

    def test_every_cell_runs_once_per_pass_and_every_record_has_the_common_shape(self):
        r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke", PASSES="2")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        recs = read(self.out)
        self.assertTrue(recs)
        for rec in recs:
            self.assertTrue(RECORD_KEYS <= set(rec), f"{rec['record']}/{rec['shape']} lacks {RECORD_KEYS - set(rec)}")
            self.assertTrue(rec["build"]["commit"])
            self.assertIs(type(rec["build"]["dirty"]), bool)
            self.assertEqual(rec["host"]["hostname"], "smoke-host")
            self.assertIs(rec["smoke"], True)
            self.assertEqual(rec["shuffle_seed"], "seed-one")
            self.assertEqual(rec["label"], "smoke")
            self.assertNotIn("hostname", rec["hw"], "the driver's hardware block does not shadow the host stamp")
        self.assertEqual({r["shape"] for r in recs}, CELLS)
        self.assertEqual({r["pass"] for r in recs}, {1, 2})
        order = self.order(recs)
        for p in (1, 2):
            self.assertEqual(sorted(order[p]), sorted(CELLS), "each cell ran once in the pass")
        positions = {(r["pass"], r["shape"]): r["position"] for r in recs}
        self.assertEqual(len(positions), 8, "one position per cell and pass, never two")
        self.assertTrue(any(r["record"] == "b05-restore" or r["record"].startswith("b05-") for r in recs))

    def test_the_same_seed_replays_the_order_and_another_seed_changes_it(self):
        def run(seed):
            if os.path.exists(self.out):
                os.remove(self.out)
            r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke", SHUF_SEED=seed)
            self.assertEqual(r.returncode, 0, r.stderr[-2000:])
            return self.order(read(self.out))[1]
        first = run("replay-a")
        self.assertEqual(run("replay-a"), first)
        others = [run(f"other-{i}") for i in range(5)]
        self.assertTrue(any(o != first for o in others), "five other seeds all gave the first order")

    def test_a_cell_that_fails_fails_the_matrix_and_leaves_no_record_for_it(self):
        r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke",
                       BIN=os.path.join(self.fake, "b05-cache-fail.sh"), FAKE_REAL_BIN=self.bin, FAKE_FAIL_SHAPE="big-10g")
        self.assertEqual(r.returncode, 1, r.stderr[-2000:])
        self.assertIn("big-10g", r.stderr.splitlines()[-1], "the failure names the shape")
        shapes = {x["shape"] for x in read(self.out)}
        self.assertEqual(shapes, CELLS - {"big-10g"})

    def test_a_matrix_where_every_cell_fails_exits_non_zero(self):
        r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke", BIN="/bin/false")
        self.assertEqual(r.returncode, 1, r.stderr[-2000:])
        self.assertEqual(read(self.out), [])

    def test_the_lock_serializes_concurrent_matrices_and_is_free_afterwards(self):
        trace = os.path.join(self.d, "trace")
        procs = []
        pids = os.path.join(self.d, "pids")
        for i in range(2):
            env = self.env(B05_TAKE_LOCK="1", BIN=os.path.join(self.fake, "b05-cache-fail.sh"), FAKE_REAL_BIN=self.bin,
                           FAKE_TRACE=trace, FAKE_ORPHAN="1", FAKE_PIDS=pids, OUT=os.path.join(self.d, f"out{i}.jsonl"))
            procs.append(subprocess.Popen(["bash", CACHE, "--profile", "smoke", "synthetic", os.path.join(self.d, f"work{i}"), "smoke"],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=env))
        for p in procs:
            _out, err = p.communicate(timeout=300)
            self.assertEqual(p.returncode, 0, err[-2000:])
        events = []
        with open(trace) as f:
            for line in f:
                shape, kind, ns = line.split()
                events.append((int(ns), kind))
        events.sort()
        self.assertEqual(len(events), 16, "two matrices of four cells")
        depth = 0
        for _ns, kind in events:
            depth += 1 if kind == "start" else -1
            self.assertLessEqual(depth, 1, "two cells ran at the same time under the lock")
        try:
            free = subprocess.run(["flock", "-n", self.lock, "true"])
            self.assertEqual(free.returncode, 0, "a sleep a cell left behind kept the benchmark lock")
        finally:
            with open(pids) as f:
                for pid in f.read().split():
                    subprocess.run(["kill", pid], capture_output=True)

    def test_the_cache_script_refuses_to_write_a_smoke_record_into_bench(self):
        target = os.path.join(HERE, "b05-smoke-must-not-exist.jsonl")
        try:
            r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke", OUT=target)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse(os.path.exists(target))
        finally:
            if os.path.exists(target):
                os.remove(target)

    def test_a_busy_host_makes_the_smoke_run_pending(self):
        with open(self.pressure_file(), "w") as f:
            f.write("some avg10=40.00 avg60=1.00 avg300=1.00 total=0\n")
        r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke")
        self.assertEqual(r.returncode, 75, r.stderr)
        self.assertEqual(read(self.out), [])

    def test_no_label_no_run(self):
        r = self.cache("synthetic", os.path.join(self.d, "work"), "smoke", SENTINEL_BENCH_HOST_LABEL="")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(read(self.out), [])

    def test_the_real_cells_run_on_the_trees_the_workloads_leave(self):
        w = self.run_workloads(["go", "rust", "custom"], CUSTOM_COUNT="16", CUSTOM_BYTES="1024")
        self.assertEqual(w.returncode, 0, w.stderr[-2000:])
        os.replace(self.out, os.path.join(self.d, "rebuild.jsonl"))
        r = self.cache("real", os.path.join(self.d, "work"), "smoke")
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
        shapes = {x["shape"] for x in read(self.out)}
        self.assertTrue(any(s.startswith("real-go-") for s in shapes), shapes)
        self.assertTrue(any(s.startswith("real-custom-") for s in shapes), shapes)
        for rec in read(self.out):
            self.assertTrue(RECORD_KEYS <= set(rec))

    # -- the toolchain workloads -----------------------------------------------------------------------------

    def run_workloads(self, langs, **env):
        w = self.workloads("locks", **env)
        self.assertEqual(w.returncode, 0, w.stderr[-2000:])
        return self.workloads("run", *langs, **env)

    def test_every_language_runs_cold_then_deps_then_warm_each_repetition_in_a_recorded_order(self):
        w = self.run_workloads(LANGS, CUSTOM_COUNT="16", CUSTOM_BYTES="1024")
        self.assertEqual(w.returncode, 0, w.stderr[-2000:])
        recs = read(self.out)
        rebuild = [r for r in recs if r["record"] == "b05-rebuild"]
        self.assertEqual(len(rebuild), (5 * 3 + 2) * 2, "go rust js python java x 3 states, custom x 2, two repetitions")
        for r in rebuild:
            self.assertEqual(r["rc"], 0, f"{r['workload']} {r['variant']} rep{r['rep']} failed")
            self.assertEqual(r["shuffle_seed"], "seed-one")
            self.assertIs(r["smoke"], True)
            self.assertTrue(r["build"]["commit"])
            self.assertIs(type(r["build"]["dirty"]), bool)
            self.assertEqual(r["host"]["hostname"], "smoke-host")
            self.assertGreater(r["duration_ns"], 0)
        for lang in LANGS:
            for rep in (1, 2):
                states = [r["variant"] for r in rebuild if r["workload"] == lang and r["rep"] == rep]
                self.assertEqual(states, ["cold", "warm"] if lang == "custom" else ["cold", "deps", "warm"], (lang, rep))
        for rep in (1, 2):
            pos = {r["workload"]: r["position"] for r in rebuild if r["rep"] == rep}
            self.assertEqual(sorted(pos.values()), list(range(1, 7)), "a permutation of the six languages")
        trees = [r for r in recs if r["record"] == "b05-tree"]
        self.assertTrue({"go", "rust", "js", "python", "java", "custom"} <= {t["workload"] for t in trees})
        for t in trees:
            self.assertTrue({"entry", "files", "symlinks", "bytes", "build", "host", "smoke"} <= set(t), t)
            self.assertGreater(t["files"], 0)
        with open(self.fake_log) as f:
            tools = {l.split()[0] for l in f}
        self.assertTrue({"go", "cargo", "npm", "npx", "mvn", "pip"} <= tools, tools)

    def test_the_language_order_replays_from_the_seed(self):
        def order(seed):
            if os.path.exists(self.out):
                os.remove(self.out)
            w = self.run_workloads(["go", "rust", "js", "python", "java"], SHUF_SEED=seed, REPS="1")
            self.assertEqual(w.returncode, 0, w.stderr[-2000:])
            rec = [r for r in read(self.out) if r["record"] == "b05-rebuild" and r["variant"] == "cold"]
            return [r["workload"] for r in sorted(rec, key=lambda r: r["position"])]
        first = order("lang-a")
        self.assertEqual(order("lang-a"), first)
        self.assertTrue(any(order(f"lang-{i}") != first for i in range(5)))

    def test_a_failing_toolchain_fails_the_run_and_the_record_says_so(self):
        w = self.run_workloads(["go"], FAKE_FAIL="go", REPS="1")
        self.assertEqual(w.returncode, 1, w.stderr[-2000:])
        rec = [r for r in read(self.out) if r["record"] == "b05-rebuild"]
        self.assertTrue(rec)
        self.assertTrue(all(r["rc"] != 0 for r in rec))

    def test_the_stub_go_fails_offline_with_an_empty_cache_so_the_state_order_matters(self):
        cache = os.path.join(self.d, "mod")
        env = dict(os.environ, GOPROXY="off", GOMODCACHE=cache, GOCACHE=os.path.join(self.d, "gc"))
        go = os.path.join(self.fake, "bin", "go")
        self.assertEqual(subprocess.run([go, "build", "./..."], env=env, capture_output=True).returncode, 1)
        online = dict(env, GOPROXY="https://proxy.example.invalid")
        self.assertEqual(subprocess.run([go, "build", "./..."], env=online, capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([go, "build", "./..."], env=env, capture_output=True).returncode, 0, "warm cache serves offline")

    def test_tools_are_not_installed_and_clean_keeps_the_tracked_stubs(self):
        w = self.workloads("tools")
        self.assertEqual(w.returncode, 2, w.stderr)
        self.assertIn("stub", w.stderr)
        self.assertEqual(self.workloads("clean").returncode, 0)
        self.assertTrue(os.path.isfile(os.path.join(self.fake, "bin", "go")), "clean must not delete bench/fake/b05")
        self.assertTrue(os.path.isfile(os.path.join(self.fake, "pip.pyz")))

    def test_the_workloads_script_refuses_bench_and_a_missing_label(self):
        target = os.path.join(HERE, "b05-smoke-must-not-exist.jsonl")
        try:
            r = self.workloads("run", "go", OUT=target)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertFalse(os.path.exists(target))
        finally:
            if os.path.exists(target):
                os.remove(target)
        r = self.workloads("run", "go", SENTINEL_BENCH_HOST_LABEL="")
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertEqual(read(self.out), [])

    def test_no_script_touches_the_production_tree(self):
        for path in (CACHE, WORKLOADS, os.path.join(HERE, "b05-timed.sh")):
            with open(path) as f:
                self.assertNotIn("/srv/sentinel/", f.read(), path)


if __name__ == "__main__":
    unittest.main()
