import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import m08_overhead as m  # noqa: E402


DAY_MS = 1_730_000_000_000  # one UTC day for every record unless a test moves it


def rec(lane, cond, iso, secs, warmup=False, state="passed", contract=("pilots-ci-isolation", 1), commit="c" * 40,
        binary="b" * 64, hostname="kvm-host", cpu="Test CPU", pressure=0.5, day_ms=DAY_MS):
    return {
            "build": {"commit": commit, "dirty": False, "binary_sha256": binary},
            "host": {"hostname": hostname, "cpu_model": cpu}, "cpu_pressure_avg60": pressure,
            "contract": {"id": contract[0], "revision": contract[1], "lane": lane, "condition": cond, "isolation": iso},
            "warmup": warmup, "job_state": state, "intake_to_finished_ns": int(secs * 1e9),
            "jobs": [{"timestamps": {"queued_ms": day_ms, "running_ms": day_ms + 2000, "terminal_ms": day_ms + 2000 + int(secs * 1000)}}]}


def write(records):
    f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
    f.write("\n".join(json.dumps(r) for r in records))
    f.close()
    return f.name


def series(iso, values, **kw):
    return [rec("cli", "warm", iso, v, **kw) for v in values]


class Overhead(unittest.TestCase):
    def test_p95_is_nearest_rank(self):
        self.assertEqual(m.p95(list(range(1, 21))), 19)
        self.assertEqual(m.p95([5]), 5)

    def run_main(self, records, *extra):
        path = write(records)
        try:
            return m.main([path, "--min-samples", "10", *extra])
        finally:
            os.remove(path)

    def test_within_the_gate_exits_zero(self):
        self.assertEqual(self.run_main(series("container", [10] * 10) + series("microvm", [10.5] * 10)), 0)

    def test_over_the_gate_exits_one(self):
        self.assertEqual(self.run_main(series("container", [10] * 10) + series("microvm", [11.5] * 10)), 1)

    def test_the_gate_is_on_the_tail_not_the_median(self):
        micro = [10] * 9 + [14]  # equal median, p95 (the maximum of ten) 40 % over
        self.assertEqual(self.run_main(series("container", [10] * 10) + series("microvm", micro)), 1)

    def test_too_few_samples_or_a_missing_side_is_insufficient(self):
        self.assertEqual(self.run_main(series("container", [10] * 3) + series("microvm", [10] * 3)), 2)
        self.assertEqual(self.run_main(series("container", [10] * 10)), 2)

    def test_warmups_and_failed_samples_are_left_out(self):
        recs = (series("container", [10] * 10) + series("microvm", [10] * 10)
                + series("microvm", [99] * 5, warmup=True) + series("microvm", [99] * 5, state="failed"))
        self.assertEqual(self.run_main(recs), 0)

    def test_other_contracts_are_refused(self):
        self.assertEqual(self.run_main([rec("cli", "warm", "container", 10, contract=("pilots-ci", 4))]), 3)

    def mixed(self, field, container_value, microvm_value):
        recs = (series("container", [10] * 10, **{field: container_value})
                + series("microvm", [10] * 10, **{field: microvm_value}))
        return self.run_main(recs)

    def test_series_from_different_builds_or_hosts_are_not_paired(self):
        self.assertEqual(self.mixed("commit", "a" * 40, "b" * 40), 3)
        self.assertEqual(self.mixed("binary", "a" * 64, "b" * 64), 3)
        self.assertEqual(self.mixed("hostname", "kvm-host", "reference-host"), 3)
        self.assertEqual(self.mixed("cpu", "Test CPU", "Other CPU"), 3)
        self.assertEqual(self.mixed("day_ms", DAY_MS, DAY_MS + 2 * 86_400_000), 3)
        self.assertEqual(self.mixed("commit", "a" * 40, "a" * 40), 0, "the same build on both sides pairs")

    def test_the_message_names_the_field_and_not_the_values(self):
        path = write(series("container", [10] * 10, commit="1" * 40) + series("microvm", [10] * 10, commit="2" * 40))
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(m.main([path]), 3)
        finally:
            os.remove(path)
        self.assertIn("build.commit", err.getvalue())
        self.assertNotIn("1" * 40, err.getvalue())

    def test_records_that_cannot_be_paired_or_started_quietly_are_bad_input(self):
        bare = series("container", [10] * 10) + series("microvm", [10] * 10)
        del bare[0]["build"]
        self.assertEqual(self.run_main(bare), 3, "no build stamp")
        busy = series("container", [10] * 10) + series("microvm", [10] * 10, pressure=2.0)
        self.assertEqual(self.run_main(busy), 3, "start pressure at the contract's 2 % limit")
        unknown = series("container", [10] * 10) + series("microvm", [10] * 10)
        del unknown[3]["cpu_pressure_avg60"]
        self.assertEqual(self.run_main(unknown), 3, "pressure not recorded")

    def test_a_warmup_or_failed_record_does_not_need_a_stamp(self):
        recs = series("container", [10] * 10) + series("microvm", [10] * 10)
        warm = series("microvm", [99] * 2, warmup=True)
        del warm[0]["build"]
        self.assertEqual(self.run_main(recs + warm), 0)

    def test_a_short_series_is_marked_as_a_maximum(self):
        s = m.summarize({"total": list(range(1, 11)), "start": [], "run": []})
        self.assertTrue(s["p95_is_max"])
        self.assertFalse(m.summarize({"total": list(range(1, 21)), "start": [], "run": []})["p95_is_max"])

    def test_phases(self):
        self.assertEqual(m.phases([{"timestamps": {"queued_ms": 0, "running_ms": 2000, "terminal_ms": 12000}}]), (2.0, 10.0))
        self.assertIsNone(m.phases([{"timestamps": {"queued_ms": 0}}]))


if __name__ == "__main__":
    unittest.main()
