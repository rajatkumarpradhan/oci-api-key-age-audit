import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from apikey_audit.cli import main

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_messy_sample_exits_2_and_covers_rules(self):
        code, out, _ = self.run_cli([os.path.join(SAMPLES, "users_messy.json"), "--as-of", "2026-11-14"])
        self.assertEqual(code, 2)
        for rule in ("KEY001", "KEY002", "KEY003", "KEY004"):
            self.assertIn(rule, out)

    def test_clean_sample_exits_0(self):
        code, out, _ = self.run_cli([os.path.join(SAMPLES, "users_clean.json"), "--as-of", "2026-11-14"])
        self.assertEqual(code, 0)
        self.assertIn("RESULT: clean", out)

    def test_bad_as_of_exits_2(self):
        code, _, err = self.run_cli([os.path.join(SAMPLES, "users_clean.json"), "--as-of", "14/11/2026"])
        self.assertEqual(code, 2)
        self.assertIn("--as-of", err)

    def test_malformed_json_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            code, _, err = self.run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("not valid JSON", err)
        finally:
            os.unlink(path)

    def test_missing_users_key_exits_2(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write('{"accounts": []}')
            path = fh.name
        try:
            code, _, err = self.run_cli([path])
            self.assertEqual(code, 2)
            self.assertIn("'users' list", err)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
