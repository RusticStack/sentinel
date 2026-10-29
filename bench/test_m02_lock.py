"""bench/microvm/m02_boot.py takes the shared verification lock for the whole process and records that it did."""
import argparse
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LINUX = sys.platform.startswith("linux")


def load():
    sys.path.insert(0, HERE)
    spec = importlib.util.spec_from_file_location("m02_boot", os.path.join(HERE, "microvm", "m02_boot.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@unittest.skipUnless(LINUX, "needs Linux and flock")
class Lock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="m02-lock-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = os.path.join(self.tmp, "verify.lock")
        old = os.environ.get("SENTINEL_VERIFY_LOCK")
        os.environ["SENTINEL_VERIFY_LOCK"] = self.path
        self.addCleanup(lambda: os.environ.__setitem__("SENTINEL_VERIFY_LOCK", old) if old else os.environ.pop("SENTINEL_VERIFY_LOCK", None))
        self.m02 = load()

    def test_the_lock_is_held_non_inheritable_and_recorded(self):
        import fcntl
        a = argparse.Namespace(no_lock=False)
        rec = self.m02.take_lock(a)
        self.addCleanup(os.close, a.lock_fd)
        self.assertEqual((rec["path"], rec["held"]), (self.path, True))
        self.assertGreaterEqual(rec["waited_ns"], 0)
        self.assertFalse(os.get_inheritable(a.lock_fd), "a VMM the script starts must not keep the lock")
        other = os.open(self.path, os.O_RDWR)
        self.addCleanup(os.close, other)
        with self.assertRaises(OSError):
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_a_dry_run_says_it_did_not_hold_the_lock(self):
        a = argparse.Namespace(no_lock=True)
        self.assertEqual(self.m02.take_lock(a), {"path": self.path, "held": False})
        self.assertFalse(hasattr(a, "lock_fd"))

    def test_a_lock_that_cannot_be_opened_exits_naming_it_not_a_traceback(self):
        bad = os.path.join(self.tmp, "no-such-dir", "verify.lock")
        os.environ["SENTINEL_VERIFY_LOCK"] = bad
        with self.assertRaises(SystemExit) as caught:
            self.m02.take_lock(argparse.Namespace(no_lock=False))
        self.assertIn(bad, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
