"""Parser tests: the distinctions the review pass depends on.

These are not schema tests. Each one pins a fact the rules rely on -- probed vs
guessed, ambiguous states, extraports counts, truncated output -- because if the
parser flattens any of those, the report loses the ability to say "nmap assumed
this" and starts asserting it instead.
"""

import os
import unittest

from nmap_review.parse import ParseError, parse_file, parse_string

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SAMPLE = os.path.join(FIXTURES, "sample.xml")


class TestParse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scan = parse_file(SAMPLE)

    def test_scan_metadata(self):
        self.assertIn("-sV", self.scan.args)
        self.assertEqual("7.94", self.scan.version)
        self.assertEqual("success", self.scan.exit_status)
        self.assertEqual([("syn", "tcp", "1-1024,1025-1030")], self.scan.scan_types)

    def test_host_states(self):
        self.assertEqual(3, len(self.scan.hosts))
        self.assertEqual(2, len(self.scan.up_hosts()))
        self.assertEqual(["192.168.56.10", "192.168.56.11"],
                         [h.address for h in self.scan.up_hosts()])

    def test_ipv4_preferred_over_mac_as_address(self):
        host = self.scan.hosts[0]
        self.assertEqual("192.168.56.10", host.address)
        self.assertEqual(2, len(host.addresses))     # the MAC is kept, not dropped

    def test_hostnames_and_label(self):
        host = self.scan.hosts[0]
        self.assertEqual(2, len(host.hostnames))
        self.assertIn("build01.lab.internal", host.label)

    def test_probed_vs_guessed(self):
        ports = {p.number: p for p in self.scan.hosts[0].ports}
        self.assertTrue(ports[22].probed)             # method="probed"
        self.assertFalse(ports[3306].probed)          # method="table" -- a guess
        self.assertEqual("mysql", ports[3306].service)
        self.assertEqual("", ports[3306].banner)

    def test_banner_assembly(self):
        ports = {p.number: p for p in self.scan.hosts[0].ports}
        self.assertEqual("OpenSSH 7.4 protocol 2.0", ports[22].banner)

    def test_ambiguous_state_preserved(self):
        host = self.scan.hosts[1]
        self.assertEqual(["3389/tcp"], [p.id for p in host.ambiguous_ports()])

    def test_extraports_counted(self):
        self.assertEqual(986, self.scan.hosts[0].count_extra("closed"))
        self.assertEqual(988, self.scan.hosts[1].count_extra("filtered"))

    def test_open_ports_exclude_filtered_and_ambiguous(self):
        self.assertEqual([445], [p.number for p in self.scan.hosts[1].open_ports()])

    def test_scripts_attached_at_both_levels(self):
        host = self.scan.hosts[0]
        self.assertEqual(["smb2-security-mode"], [s.id for s in host.scripts])
        ftp = next(p for p in host.ports if p.number == 21)
        self.assertIn("Anonymous FTP login allowed", ftp.scripts[0].output)

    def test_os_matches_with_accuracy(self):
        self.assertEqual(("Linux 3.2 - 4.9", 92), self.scan.hosts[0].os_matches[0])

    def test_truncated_xml_is_recovered_and_flagged(self):
        with open(SAMPLE, encoding="utf-8") as f:
            text = f.read()
        cut = text[:text.index("<runstats>")] + "<port protocol=\"tcp\" portid=\"99"
        scan = parse_string(cut, source="cut.xml")
        self.assertEqual("truncated", scan.exit_status)
        self.assertEqual(3, len(scan.hosts))          # the hosts before the cut survive

    def test_garbage_raises(self):
        with self.assertRaises(ParseError):
            parse_string("not xml at all", source="x")

    def test_wrong_root_raises(self):
        with self.assertRaises(ParseError):
            parse_string("<other/>", source="x")


if __name__ == "__main__":
    unittest.main()
