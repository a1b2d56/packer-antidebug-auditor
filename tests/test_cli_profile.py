"""End-to-end tests for the additive --profile CLI flag."""

import json
import os
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cli.py")


def _is_pe(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"MZ"
    except OSError:
        return False


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, CLI, *args], capture_output=True, text=True, cwd=ROOT, timeout=120
    )


@unittest.skipUnless(_is_pe(sys.executable), "needs a Windows PE interpreter binary as sample")
class TestCLIProfile(unittest.TestCase):
    def test_default_output_reports_balanced_profile(self):
        proc = _run(sys.executable, "--json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        verdict = json.loads(proc.stdout)["verdict"]
        self.assertEqual(verdict["profile"], "balanced")
        self.assertIn("confidence", verdict)

    def test_profile_changes_thresholds_not_signals(self):
        reports = {}
        for prof in ("aggressive", "balanced", "conservative"):
            proc = _run(sys.executable, "--json", "--profile", prof)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            reports[prof] = json.loads(proc.stdout)["verdict"]
        self.assertEqual(reports["aggressive"]["thresholds"], {"medium": 2, "high": 5})
        self.assertEqual(reports["conservative"]["thresholds"], {"medium": 4, "high": 9})
        self.assertEqual(
            set(reports["aggressive"]["signal_keys"]), set(reports["balanced"]["signal_keys"])
        )

    def test_invalid_profile_rejected_by_argparse(self):
        proc = _run(sys.executable, "--profile", "paranoid")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("invalid choice", proc.stderr)


if __name__ == "__main__":
    unittest.main()
