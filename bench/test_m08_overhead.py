import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import m08_overhead as m  # noqa: E402


def rec(lane, cond, iso, secs, warmup=False, state="passed", contract=("pilots-ci-isolation", 1)):
    return {"contract": {"id": contract[0], "revision": contract[1], "lane": lane, "condition": cond, "isolation": iso},
            "warmup": warmup, "job_state": state, "intake_to_finished_ns": int(secs * 1e9),
            "jobs": [{"timestamps": {"queued_ms": 1000, "running_ms": 3000, "terminal_ms": 3000 + int(secs * 1000)}}]}


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

    def test_phases(self):
        self.assertEqual(m.phases([{"timestamps": {"queued_ms": 0, "running_ms": 2000, "terminal_ms": 12000}}]), (2.0, 10.0))
        self.assertIsNone(m.phases([{"timestamps": {"queued_ms": 0}}]))


if __name__ == "__main__":
    unittest.main()
