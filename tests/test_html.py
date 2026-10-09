"""HTML report tests.

The structural ones matter less than the two safety ones: target-controlled
text must never reach the page as markup, and no host may silently lose its
detail pane. Everything else is layout, which the committed sample report
covers as a golden file.
"""

import os
import re
import unittest
from html.parser import HTMLParser

from nmap_review.html import html_report
from nmap_review.parse import parse_file, parse_string
from nmap_review.rules import review

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample.xml")


class WellFormed(HTMLParser):
    VOID = {"meta", "br", "img", "input", "link", "hr", "source"}

    def __init__(self):
        super().__init__()
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.errors.append(f"</{tag}> closes nothing (open: {self.stack[-3:]})")


class TestHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scan = parse_file(SAMPLE)
        cls.page = html_report(cls.scan, review(cls.scan))

    def test_well_formed(self):
        p = WellFormed()
        p.feed(self.page)
        self.assertEqual([], p.errors)
        self.assertEqual([], p.stack)

    def test_is_self_contained(self):
        """No CDN, no external fonts: these reports get read offline."""
        for pattern in (r'src="http', r'href="http[^"]*\.css', r"@import"):
            self.assertIsNone(re.search(pattern, self.page), pattern)

    def test_summary_counts_hosts_and_ports(self):
        self.assertIn("Hosts scanned", self.page)
        self.assertIn("Open ports", self.page)
        self.assertIn("Hosts needing attention", self.page)

    def test_every_up_host_has_a_card_and_a_detail_pane(self):
        for host in self.scan.up_hosts():
            self.assertIn(f'data-host="{host.address}"', self.page)
            self.assertIn(f'data-detail="{host.address}"', self.page)

    def test_down_hosts_are_listed_but_get_no_card(self):
        self.assertIn("192.168.56.12", self.page)
        self.assertNotIn('data-host="192.168.56.12"', self.page)

    def test_identification_method_is_visible_per_port(self):
        self.assertIn(">probe<", self.page)
        self.assertIn(">port table<", self.page)

    def test_script_output_is_present_verbatim(self):
        self.assertIn("Anonymous FTP login allowed", self.page)

    def test_target_controlled_text_is_escaped(self):
        """A hostile target can put markup in its own banner. It must not run."""
        xml = ('<?xml version="1.0"?><nmaprun args="nmap -sV -p- 10.0.0.1" version="7.94">'
               '<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>'
               '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
               '<hostnames><hostname name="&lt;img src=x onerror=alert(1)&gt;" type="PTR"/></hostnames>'
               '<ports><port protocol="tcp" portid="80">'
               '<state state="open" reason="syn-ack"/>'
               '<service name="http" product="&lt;script&gt;alert(1)&lt;/script&gt;" '
               'method="probed" conf="10"/>'
               '<script id="http-title" output="&lt;/pre&gt;&lt;script&gt;alert(2)&lt;/script&gt;"/>'
               '</port></ports></host></nmaprun>')
        scan = parse_string(xml, source="hostile")
        page = html_report(scan, review(scan))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)
        self.assertNotIn("</pre><script>alert(2)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        # ...and the only <script> element is the page's own navigation code.
        self.assertEqual(1, page.count("<script>"))

    def test_backticks_become_code_spans_not_literal(self):
        self.assertIn("<code>-p-</code>", self.page)

    def test_empty_scan_still_renders(self):
        scan = parse_string('<?xml version="1.0"?><nmaprun args="nmap 10.0.0.0/30" '
                            'version="7.94"></nmaprun>', source="empty")
        page = html_report(scan, review(scan))
        self.assertIn("No responsive hosts", page)

    def test_sample_report_is_committed_and_current(self):
        committed = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "docs", "sample-report.html")
        self.assertTrue(os.path.exists(committed), "run `make sample`")
        # `make sample` runs from the repo root, so the scan's recorded source
        # is the relative path. Re-render with that to compare like for like.
        scan = parse_file(SAMPLE)
        scan.source = "tests/fixtures/sample.xml"
        with open(committed, encoding="utf-8") as f:
            self.assertEqual(f.read(), html_report(scan, review(scan)),
                             "docs/sample-report.html is stale -- run `make sample`")


if __name__ == "__main__":
    unittest.main()
