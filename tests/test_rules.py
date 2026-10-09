"""Rule tests.

Two things are being protected here. The first is that the review rules fire on
the cases they exist for. The second, and the one more likely to rot, is that
they keep their *altitude*: the report must not assert a vulnerability from a
banner, and it must not drop the "this was a guess" qualifier when nmap did not
probe. Both are asserted directly.
"""

import os
import unittest

from nmap_review.parse import parse_file, parse_string
from nmap_review.report import markdown, text, to_json
from nmap_review.rules import review

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SAMPLE = os.path.join(FIXTURES, "sample.xml")

HEADER = ('<?xml version="1.0"?><nmaprun scanner="nmap" args="{args}" version="7.94">'
          '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>')


def synth(args="nmap -sV -p 1-1000 10.0.0.1", ports="", hostscript="", state="up"):
    xml = HEADER.format(args=args) + (
        f'<host><status state="{state}"/><address addr="10.0.0.1" addrtype="ipv4"/>'
        f'<ports>{ports}</ports>{hostscript}</host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>')
    return parse_string(xml, source="synth")


def port(num, state="open", name="", method="probed", product="", version="", script=None):
    svc = (f'<service name="{name}" method="{method}" conf="10"'
           + (f' product="{product}"' if product else "")
           + (f' version="{version}"' if version else "") + '/>') if name or product else ""
    scr = f'<script id="{script[0]}" output="{script[1]}"/>' if script else ""
    return (f'<port protocol="tcp" portid="{num}"><state state="{state}" reason="syn-ack"/>'
            f'{svc}{scr}</port>')


def rules_fired(scan):
    return {f.rule for f in review(scan)}


def titles(scan):
    return [f.title for f in review(scan)]


class TestCoverageRules(unittest.TestCase):
    def test_default_port_range_is_flagged(self):
        scan = synth(args="nmap -sV 10.0.0.1", ports=port(22, name="ssh"))
        self.assertIn("COV-PORTS-DEFAULT", rules_fired(scan))

    def test_explicit_port_range_is_not_flagged(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1", ports=port(22, name="ssh"))
        self.assertNotIn("COV-PORTS-DEFAULT", rules_fired(scan))

    def test_fast_scan_is_flagged(self):
        scan = synth(args="nmap -F -sV -p 1-100 10.0.0.1", ports=port(22, name="ssh"))
        self.assertIn("COV-PORTS-FAST", rules_fired(scan))

    def test_missing_version_detection_is_high_priority(self):
        scan = synth(args="nmap -p- 10.0.0.1", ports=port(22, name="ssh", method="table"))
        fired = [f for f in review(scan) if f.rule == "COV-NO-SV"]
        self.assertEqual(1, len(fired))
        self.assertEqual("high", fired[0].priority)

    def test_version_detection_present_is_not_flagged(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1", ports=port(22, name="ssh"))
        self.assertNotIn("COV-NO-SV", rules_fired(scan))

    def test_aggressive_timing_is_flagged(self):
        scan = synth(args="nmap -sV -p- -T4 10.0.0.1", ports=port(22, name="ssh"))
        self.assertIn("COV-TIMING", rules_fired(scan))

    def test_udp_absence_flagged_and_udp_presence_not(self):
        self.assertIn("COV-NO-UDP", rules_fired(synth(ports=port(22, name="ssh"))))
        xml = ('<?xml version="1.0"?><nmaprun args="nmap -sU -sV -p- 10.0.0.1" version="7.94">'
               '<scaninfo type="udp" protocol="udp" numservices="1000" services="1-1000"/>'
               '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
               '<ports></ports></host></nmaprun>')
        self.assertNotIn("COV-NO-UDP", rules_fired(parse_string(xml, source="u")))

    def test_all_hosts_down_is_flagged(self):
        self.assertIn("COV-ALL-DOWN", rules_fired(synth(state="down")))

    def test_no_hosts_at_all_is_flagged(self):
        xml = HEADER.format(args="nmap -sV -p- 10.0.0.0/30") + "</nmaprun>"
        self.assertIn("COV-NO-HOSTS", rules_fired(parse_string(xml, source="e")))

    def test_truncated_scan_is_flagged_high(self):
        scan = parse_file(SAMPLE)
        scan.exit_status = "truncated"
        fired = [f for f in review(scan) if f.rule == "COV-TRUNCATED"]
        self.assertEqual("high", fired[0].priority)

    def test_guessed_services_are_reported_as_guesses(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1",
                     ports=port(3306, name="mysql", method="table"))
        fired = rules_fired(scan)
        self.assertIn("COV-GUESSED-SERVICES", fired)
        detail = next(f.detail for f in review(scan) if f.rule == "COV-GUESSED-SERVICES")
        self.assertIn("not from a probe", detail)


class TestSurfaceRules(unittest.TestCase):
    def test_unidentified_open_port_is_high(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1", ports=port(44444))
        fired = [f for f in review(scan) if f.rule == "SRF-UNIDENTIFIED"]
        self.assertEqual("high", fired[0].priority)

    def test_tcpwrapped_explains_itself(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1", ports=port(9999, name="tcpwrapped"))
        detail = next(f.detail for f in review(scan) if f.rule == "SRF-UNIDENTIFIED")
        self.assertIn("tcpwrapped", detail)

    def test_sensitive_service_on_nonstandard_port_is_caught_by_name(self):
        # Redis on 7777: a port-number-only table would miss this entirely.
        scan = synth(args="nmap -sV -p- 10.0.0.1",
                     ports=port(7777, name="redis", product="Redis key-value store"))
        self.assertIn("SRF-SENSITIVE-SERVICE", rules_fired(scan))

    def test_unprobed_sensitive_service_is_downgraded(self):
        """A guess must not carry the same weight as a probe."""
        probed = synth(args="nmap -sV -p- 10.0.0.1", ports=port(6379, name="redis"))
        guessed = synth(args="nmap -sV -p- 10.0.0.1",
                        ports=port(6379, name="redis", method="table"))
        p = next(f for f in review(probed) if f.rule == "SRF-SENSITIVE-SERVICE")
        g = next(f for f in review(guessed) if f.rule == "SRF-SENSITIVE-SERVICE")
        self.assertEqual("high", p.priority)
        self.assertEqual("medium", g.priority)
        self.assertIn("inferred from the port number", g.detail)

    def test_script_vulnerable_keyword_is_high(self):
        scan = synth(args="nmap -sV -sC -p- 10.0.0.1",
                     ports=port(445, name="microsoft-ds",
                                script=("smb-vuln-ms17-010", "State: VULNERABLE")))
        fired = [f for f in review(scan) if f.rule == "SRF-SCRIPT-SIGNAL"]
        self.assertEqual(1, len(fired))
        self.assertEqual("high", fired[0].priority)

    def test_host_level_scripts_are_reviewed(self):
        scan = synth(args="nmap -sV -sC -p- 10.0.0.1", ports=port(445, name="microsoft-ds"),
                     hostscript='<hostscript><script id="smb2-security-mode" '
                                'output="Message signing enabled but not required"/></hostscript>')
        self.assertIn("SRF-SCRIPT-SIGNAL", rules_fired(scan))

    def test_version_finding_does_not_assert_vulnerability(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1",
                     ports=port(22, name="ssh", product="OpenSSH", version="7.4"))
        f = next(f for f in review(scan) if f.rule == "SRF-VERSION-AGE")
        self.assertEqual("medium", f.priority)
        self.assertIn("not a patch level", f.detail)
        for word in ("vulnerable", "exploitable"):
            self.assertNotIn(word, f.detail.lower())

    def test_current_versions_are_not_flagged(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1",
                     ports=port(22, name="ssh", product="OpenSSH", version="9.6"))
        self.assertNotIn("SRF-VERSION-AGE", rules_fired(scan))

    def test_broad_surface_flagged_once(self):
        ports = "".join(port(1000 + i, name="http", product="nginx", version="1.24.0")
                        for i in range(16))
        fired = [f for f in review(synth(args="nmap -sV -p- 10.0.0.1", ports=ports))
                 if f.rule == "SRF-BROAD-SURFACE"]
        self.assertEqual(1, len(fired))

    def test_closed_ports_produce_nothing(self):
        scan = synth(args="nmap -sV -p- 10.0.0.1",
                     ports=port(6379, state="closed", name="redis"))
        self.assertNotIn("SRF-SENSITIVE-SERVICE", rules_fired(scan))

    def test_findings_are_ordered_by_priority(self):
        order = [f.priority for f in review(parse_file(SAMPLE))]
        rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.assertEqual(sorted(order, key=lambda p: rank[p]), order)


class TestRenderers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scan = parse_file(SAMPLE)
        cls.findings = review(cls.scan)

    def test_markdown_puts_coverage_before_the_queue(self):
        md = markdown(self.scan, self.findings)
        self.assertLess(md.index("How far to trust this scan"), md.index("Review queue"))
        self.assertLess(md.index("Review queue"), md.index("## 3. Inventory"))

    def test_markdown_marks_unprobed_ports_in_the_inventory(self):
        md = markdown(self.scan, self.findings)
        self.assertIn("port table", md)

    def test_text_renders_without_error(self):
        self.assertIn("REVIEW QUEUE", text(self.scan, self.findings))

    def test_json_is_machine_readable(self):
        import json
        payload = json.loads(to_json(self.scan, self.findings))
        self.assertEqual(3, payload["scan"]["hosts_up"])
        self.assertGreater(payload["counts"]["high"], 0)
        self.assertTrue(all({"rule", "priority", "next_step"} <= set(f)
                            for f in payload["findings"]))

    def test_followups_name_the_unknown_ports(self):
        payload = to_json(self.scan, self.findings)
        self.assertIn("--version-all", payload)


if __name__ == "__main__":
    unittest.main()
