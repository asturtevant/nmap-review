"""CLI tests: the contract a pipeline depends on."""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from nmap_review.cli import main

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample.xml")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCLI(unittest.TestCase):
    def test_report_markdown_exits_zero_by_default(self):
        code, out, _ = run(["report", SAMPLE])
        self.assertEqual(0, code)
        self.assertIn("# nmap review", out)

    def test_fail_on_high_gates_the_pipeline(self):
        code, _, _ = run(["report", SAMPLE, "--fail-on", "high"])
        self.assertEqual(1, code)

    def test_fail_on_respects_filters(self):
        """--only coverage with no high coverage items must not fail the gate."""
        code, out, _ = run(["report", SAMPLE, "--only", "surface",
                            "--min-priority", "info", "-f", "json"])
        self.assertEqual(0, code)
        self.assertTrue(all(f["kind"] == "surface" for f in json.loads(out)["findings"]))

    def test_min_priority_drops_lower_items(self):
        _, out, _ = run(["report", SAMPLE, "-f", "json", "--min-priority", "high"])
        self.assertTrue(all(f["priority"] == "high" for f in json.loads(out)["findings"]))

    def test_missing_file_exits_two(self):
        code, _, err = run(["report", "/nonexistent/scan.xml"])
        self.assertEqual(2, code)
        self.assertIn("nmap-review", err)

    def test_bad_xml_exits_two_not_one(self):
        """A tool failure must be distinguishable from findings."""
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write("this is not nmap xml")
            path = f.name
        try:
            code, _, _ = run(["report", path])
            self.assertEqual(2, code)
        finally:
            os.unlink(path)

    def test_scan_without_args_explains_itself(self):
        code, _, err = run(["scan"])
        self.assertEqual(2, code)
        self.assertIn("after `--`", err)


if __name__ == "__main__":
    unittest.main()
