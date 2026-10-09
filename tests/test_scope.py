"""Scope-filter tests.

The behavioural rule being protected is the one in the module docstring: a
filtered host is *recorded*, never silently deleted. A host absent without
explanation reads exactly like a host that was never scanned, and only one of
those is a statement about the target.
"""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from nmap_review.cli import main
from nmap_review.parse import parse_file
from nmap_review.report import markdown, text, to_json
from nmap_review.html import html_report
from nmap_review.rules import review
from nmap_review.scope import apply_scope, matches, unmatched_patterns

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SAMPLE = os.path.join(FIXTURES, "sample.xml")


def sample():
    return parse_file(SAMPLE)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestMatching(unittest.TestCase):
    def setUp(self):
        self.host = sample().hosts[0]        # 192.168.56.10, build01/jenkins

    def test_exact_address(self):
        self.assertTrue(matches(self.host, "192.168.56.10"))
        self.assertFalse(matches(self.host, "192.168.56.11"))

    def test_cidr(self):
        self.assertTrue(matches(self.host, "192.168.56.0/24"))
        self.assertTrue(matches(self.host, "192.168.56.10/32"))
        self.assertFalse(matches(self.host, "10.0.0.0/8"))

    def test_address_glob(self):
        self.assertTrue(matches(self.host, "192.168.56.*"))
        self.assertFalse(matches(self.host, "192.168.57.*"))

    def test_hostname_glob(self):
        self.assertTrue(matches(self.host, "*.lab.internal"))
        self.assertTrue(matches(self.host, "jenkins.*"))      # second hostname
        self.assertFalse(matches(self.host, "*.corp.example"))

    def test_mac_address_does_not_break_cidr_matching(self):
        """The host carries a MAC in `addresses`; no CIDR can contain it."""
        self.assertFalse(matches(self.host, "0.0.0.0/0") is None)
        self.assertTrue(matches(self.host, "0.0.0.0/0"))


class TestApplyScope(unittest.TestCase):
    def test_exclude_moves_rather_than_deletes(self):
        scan = apply_scope(sample(), exclude=["192.168.56.11"])
        self.assertEqual(["192.168.56.10", "192.168.56.12"],
                         [h.address for h in scan.hosts])
        self.assertEqual(1, len(scan.excluded))
        host, reason = scan.excluded[0]
        self.assertEqual("192.168.56.11", host.address)
        self.assertIn("--exclude-host 192.168.56.11", reason)

    def test_only_host_is_an_allow_list(self):
        scan = apply_scope(sample(), only=["192.168.56.10"])
        self.assertEqual(["192.168.56.10"], [h.address for h in scan.hosts])
        self.assertEqual(2, len(scan.excluded))
        self.assertTrue(all("not matched by --only-host" in r for _, r in scan.excluded))

    def test_only_then_exclude_compose(self):
        """'this subnet, except that box'."""
        scan = apply_scope(sample(), only=["192.168.56.0/24"],
                           exclude=["192.168.56.12"])
        self.assertEqual(["192.168.56.10", "192.168.56.11"],
                         [h.address for h in scan.hosts])

    def test_no_patterns_is_a_no_op(self):
        scan = apply_scope(sample())
        self.assertEqual(3, len(scan.hosts))
        self.assertEqual([], scan.excluded)

    def test_findings_for_excluded_hosts_are_gone(self):
        scan = apply_scope(sample(), exclude=["192.168.56.11"])
        targets = " ".join(f.target for f in review(scan))
        self.assertNotIn("192.168.56.11", targets)

    def test_unmatched_patterns_are_reported(self):
        scan = apply_scope(sample(), exclude=["10.9.9.9"])
        self.assertEqual(["10.9.9.9"], unmatched_patterns(scan, ["10.9.9.9"]))
        self.assertEqual([], unmatched_patterns(scan, ["192.168.56.10"]))

    def test_an_excluded_host_still_counts_as_matched(self):
        """Having been excluded is not 'pattern matched nothing'."""
        scan = apply_scope(sample(), exclude=["192.168.56.11"])
        self.assertEqual([], unmatched_patterns(scan, ["192.168.56.11"]))


class TestRenderedTrace(unittest.TestCase):
    """Every format has to show that a filter was applied."""

    def setUp(self):
        self.scan = apply_scope(sample(), exclude=["192.168.56.11"])
        self.findings = review(self.scan)

    def test_markdown_names_the_excluded_host(self):
        md = markdown(self.scan, self.findings)
        self.assertIn("Excluded by filter", md)
        self.assertIn("192.168.56.11", md)

    def test_text_names_the_excluded_host(self):
        self.assertIn("excluded", text(self.scan, self.findings))

    def test_json_records_host_and_reason(self):
        payload = json.loads(to_json(self.scan, self.findings))
        self.assertEqual(1, len(payload["scan"]["excluded"]))
        self.assertIn("--exclude-host", payload["scan"]["excluded"][0]["reason"])

    def test_html_names_the_excluded_host(self):
        page = html_report(self.scan, self.findings)
        self.assertIn("Excluded", page)
        self.assertIn("192.168.56.11", page)
        # ...and it gets no card and no detail pane
        self.assertNotIn('data-host="192.168.56.11"', page)


class TestScopeCLI(unittest.TestCase):
    def test_exclude_flag(self):
        code, out, _ = run(["report", SAMPLE, "--exclude-host", "192.168.56.11",
                            "-f", "json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertEqual(["192.168.56.10", "192.168.56.12"],
                         [h["address"] for h in payload["hosts"]])

    def test_repeatable(self):
        code, out, _ = run(["report", SAMPLE, "--exclude-host", "192.168.56.11",
                            "--exclude-host", "192.168.56.12", "-f", "json"])
        payload = json.loads(out)
        self.assertEqual(["192.168.56.10"], [h["address"] for h in payload["hosts"]])

    def test_typo_warns_on_stderr_without_failing(self):
        code, _, err = run(["report", SAMPLE, "--exclude-host", "10.9.9.9", "-f", "json"])
        self.assertEqual(0, code)
        self.assertIn("no host matched", err)

    def test_scope_applies_to_both_sides_of_a_diff(self):
        code, out, _ = run(["diff", os.path.join(FIXTURES, "baseline.xml"), SAMPLE,
                            "--exclude-host", "192.168.56.13", "-f", "json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        kinds = {c["kind"] for c in payload["changes"]}
        self.assertNotIn("host-gone", kinds)      # the excluded host is not "missing"

    def test_only_host_narrows_a_diff(self):
        code, out, _ = run(["diff", os.path.join(FIXTURES, "baseline.xml"), SAMPLE,
                            "--only-host", "192.168.56.10", "-f", "json"])
        payload = json.loads(out)
        self.assertTrue(all(c["host"].startswith("192.168.56.10")
                            for c in payload["changes"] if c["host"] != "(scan-wide)"))


if __name__ == "__main__":
    unittest.main()


class TestCommaSeparated(unittest.TestCase):
    """nmap's own --exclude takes a comma list; diverging from it is a trap."""

    def test_split_patterns(self):
        from nmap_review.scope import split_patterns
        self.assertEqual(["a", "b", "c"], split_patterns(["a,b", "c"]))
        self.assertEqual(["a", "b"], split_patterns(["a, b"]))        # spaces
        self.assertEqual(["a"], split_patterns(["a,"]))               # trailing comma
        self.assertEqual([], split_patterns([]))

    def test_comma_list_excludes_both(self):
        scan = apply_scope(sample(), exclude=["192.168.56.11,192.168.56.12"])
        self.assertEqual(["192.168.56.10"], [h.address for h in scan.hosts])
        self.assertEqual(2, len(scan.excluded))

    def test_comma_and_repeated_flags_combine(self):
        code, out, _ = run(["report", SAMPLE,
                            "--exclude-host", "192.168.56.11,192.168.56.12",
                            "-f", "json"])
        self.assertEqual(0, code)
        self.assertEqual(["192.168.56.10"],
                         [h["address"] for h in json.loads(out)["hosts"]])

    def test_trailing_comma_does_not_produce_a_bogus_warning(self):
        code, _, err = run(["report", SAMPLE, "--exclude-host", "192.168.56.11,",
                            "-f", "json"])
        self.assertEqual(0, code)
        self.assertNotIn("no host matched", err)

    def test_one_bad_entry_in_a_list_still_warns(self):
        _, _, err = run(["report", SAMPLE, "--exclude-host", "192.168.56.11,10.9.9.9",
                         "-f", "json"])
        self.assertIn("10.9.9.9", err)
