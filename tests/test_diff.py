"""Diff tests.

Beyond "does it spot the change", two properties are pinned deliberately:

* a standing finding whose wording shifts (counts change between runs) must not
  be reported as new -- that is how a diff turns into noise nobody reads;
* the CI gate must consider only NEW changes, because a gate that fires on the
  estate's existing exposure fires on every run forever.
"""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout

from nmap_review.cli import main
from nmap_review.diff import diff_scans
from nmap_review.parse import parse_file, parse_string
from nmap_review.rules import review

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
BASELINE = os.path.join(FIXTURES, "baseline.xml")
SAMPLE = os.path.join(FIXTURES, "sample.xml")

HEAD = ('<?xml version="1.0"?><nmaprun args="nmap -sV -p- 10.0.0.1" version="7.94">'
        '<scaninfo type="syn" protocol="tcp" numservices="10" services="1-10"/>')


def scan(ports, state="up", addr="10.0.0.1", source="s"):
    return parse_string(
        HEAD + f'<host><status state="{state}"/><address addr="{addr}" addrtype="ipv4"/>'
        + f'<ports>{ports}</ports></host></nmaprun>', source=source)


def port(num, state="open", name="", product="", version=""):
    svc = (f'<service name="{name}" method="probed" conf="10"'
           + (f' product="{product}"' if product else "")
           + (f' version="{version}"' if version else "") + "/>") if name else ""
    return (f'<port protocol="tcp" portid="{num}">'
            f'<state state="{state}" reason="syn-ack"/>{svc}</port>')


def compare(old, new):
    return diff_scans(old, new, review(old), review(new))


def kinds(d):
    return {c.kind for c in d.changes}


class TestDiff(unittest.TestCase):
    def test_identical_scans_produce_no_changes(self):
        a = scan(port(22, name="ssh", product="OpenSSH", version="9.6"))
        b = scan(port(22, name="ssh", product="OpenSSH", version="9.6"))
        d = compare(a, b)
        self.assertTrue(d.unchanged)
        self.assertEqual([], d.new_findings)

    def test_newly_opened_port_is_high(self):
        d = compare(scan(port(22, name="ssh")),
                    scan(port(22, name="ssh") + port(6379, name="redis")))
        opened = d.by_kind("port-opened")
        self.assertEqual(1, len(opened))
        self.assertEqual("high", opened[0].priority)
        self.assertIn("6379/tcp", opened[0].port)

    def test_filtered_to_open_counts_as_opened(self):
        d = compare(scan(port(3306, state="filtered", name="mysql")),
                    scan(port(3306, name="mysql")))
        self.assertEqual(1, len(d.by_kind("port-opened")))

    def test_closed_port_is_reported_but_not_as_a_fix(self):
        d = compare(scan(port(23, name="telnet")), scan(port(23, state="filtered", name="telnet")))
        closed = d.by_kind("port-closed")
        self.assertEqual(1, len(closed))
        self.assertIn("dropped probe", closed[0].detail)

    def test_service_change_outranks_a_version_change(self):
        d = compare(scan(port(8080, name="http", product="nginx", version="1.24.0")),
                    scan(port(8080, name="ssh", product="OpenSSH", version="9.6")))
        self.assertEqual("high", d.by_kind("service-changed")[0].priority)
        self.assertEqual([], d.by_kind("version-changed"))

    def test_version_change_is_low_and_shows_both_sides(self):
        d = compare(scan(port(22, name="ssh", product="OpenSSH", version="8.9")),
                    scan(port(22, name="ssh", product="OpenSSH", version="9.6")))
        ch = d.by_kind("version-changed")[0]
        self.assertEqual("low", ch.priority)
        self.assertIn("8.9", ch.before)
        self.assertIn("9.6", ch.after)

    def test_new_host_and_vanished_host(self):
        old = scan(port(22, name="ssh"), addr="10.0.0.1")
        new = scan(port(22, name="ssh"), addr="10.0.0.2")
        d = compare(old, new)
        self.assertEqual(1, len(d.by_kind("host-appeared")))
        self.assertEqual(1, len(d.by_kind("host-gone")))
        self.assertEqual("high", d.by_kind("host-appeared")[0].priority)

    def test_host_down_then_up_is_an_appearance(self):
        d = compare(scan("", state="down"), scan(port(22, name="ssh")))
        self.assertEqual(1, len(d.by_kind("host-appeared")))
        self.assertIn("not responding in the previous scan",
                      d.by_kind("host-appeared")[0].detail)

    def test_standing_finding_with_shifted_wording_is_not_new(self):
        """Identity is (rule, target) -- not the prose, which carries counts."""
        old = parse_file(BASELINE)
        new = parse_file(BASELINE)
        new.hosts[1].extraports = [("filtered", 991, ["no-responses"])]   # was 988
        d = compare(old, new)
        self.assertEqual([], [f for f in d.new_findings if f.rule == "COV-FILTERED"])

    def test_cleared_findings_carry_the_caveat(self):
        d = compare(parse_file(SAMPLE), parse_file(BASELINE))
        cleared = d.by_kind("finding-cleared")
        self.assertTrue(cleared)
        self.assertIn("narrower scan", cleared[0].detail)

    def test_fixture_pair_finds_the_expected_shape_of_change(self):
        d = compare(parse_file(BASELINE), parse_file(SAMPLE))
        self.assertTrue({"port-opened", "service-changed", "version-changed",
                         "host-gone", "finding-new"} <= kinds(d))
        self.assertEqual("192.168.56.13 (old-jump.lab.internal)",
                         d.by_kind("host-gone")[0].host)

    def test_changes_are_ordered_by_priority(self):
        d = compare(parse_file(BASELINE), parse_file(SAMPLE))
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        order = [rank[c.priority] for c in d.changes]
        self.assertEqual(sorted(order), order)

    def test_finding_target_is_not_printed_twice(self):
        d = compare(parse_file(BASELINE), parse_file(SAMPLE))
        for c in d.by_kind("finding-new"):
            if c.port:
                self.assertNotIn(c.port, c.host)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestDiffCLI(unittest.TestCase):
    def test_two_files_diff(self):
        code, out, _ = run(["diff", BASELINE, SAMPLE, "-f", "json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertTrue(payload["changed"])
        self.assertGreater(payload["counts"]["high"], 0)

    def test_gate_fires_on_new_exposure(self):
        code, _, _ = run(["diff", BASELINE, SAMPLE, "--fail-on", "high", "-f", "json"])
        self.assertEqual(1, code)

    def test_gate_is_quiet_when_nothing_changed(self):
        code, _, _ = run(["diff", SAMPLE, SAMPLE, "--fail-on", "high", "-f", "json"])
        self.assertEqual(0, code)

    def test_sides_can_be_merged_with_a_separator(self):
        code, out, _ = run(["diff", BASELINE, "--", SAMPLE,
                            os.path.join(FIXTURES, "sample-udp.xml"), "-f", "json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        self.assertIn("sample-udp.xml", payload["current"]["source"])

    def test_ambiguous_file_count_is_a_usage_error(self):
        code, _, err = run(["diff", BASELINE, SAMPLE, SAMPLE])
        self.assertEqual(2, code)
        self.assertIn("baseline", err)

    def test_report_merges_several_files(self):
        code, out, _ = run(["report", SAMPLE, os.path.join(FIXTURES, "sample-udp.xml"),
                            "-f", "json"])
        self.assertEqual(0, code)
        payload = json.loads(out)
        protocols = {p["protocol"] for h in payload["hosts"] for p in h["ports"]}
        self.assertEqual({"tcp", "udp"}, protocols)

    def test_html_diff_renders(self):
        code, out, _ = run(["diff", BASELINE, SAMPLE, "-f", "html"])
        self.assertEqual(0, code)
        self.assertIn("nmap review — changes", out)
        self.assertIn("Summary of changes", out)
        self.assertIn('data-detail="192.168.56.10"', out)   # drill-down survives


if __name__ == "__main__":
    unittest.main()
