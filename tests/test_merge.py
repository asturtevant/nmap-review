"""Merge tests.

The property that matters: merging must never *lose* evidence, and must never
*invent* it. A fast sweep that saw `open, no service` and a `-sV` run that
identified the service are not in conflict -- the merged record has to keep the
identification. Equally, two scans of the same 1,000 ports must not add up to
2,000 filtered ports.
"""

import os
import unittest

from nmap_review.merge import merge_scans
from nmap_review.parse import parse_file, parse_string
from nmap_review.rules import review

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

HEAD = ('<?xml version="1.0"?><nmaprun args="{args}" version="7.94">'
        '<scaninfo type="{t}" protocol="{proto}" numservices="10" services="1-10"/>')


def scan(args, ports, proto="tcp", t="syn", state="up", addr="10.0.0.1", extra=""):
    return parse_string(
        HEAD.format(args=args, proto=proto, t=t)
        + f'<host><status state="{state}"/><address addr="{addr}" addrtype="ipv4"/>'
        + f'<ports>{extra}{ports}</ports></host>'
        + '<runstats><finished exit="success"/></runstats></nmaprun>',
        source=args)


def port(num, state="open", name="", method="probed", product="", version="", proto="tcp"):
    svc = (f'<service name="{name}" method="{method}" conf="10"'
           + (f' product="{product}"' if product else "")
           + (f' version="{version}"' if version else "") + "/>") if name else ""
    return (f'<port protocol="{proto}" portid="{num}">'
            f'<state state="{state}" reason="syn-ack"/>{svc}</port>')


class TestMerge(unittest.TestCase):
    def test_single_scan_is_returned_unchanged(self):
        one = scan("nmap -sV -p- 10.0.0.1", port(22, name="ssh"))
        self.assertIs(one, merge_scans([one]))

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError):
            merge_scans([])

    def test_ports_from_both_scans_are_present(self):
        merged = merge_scans([
            scan("nmap -p 22 10.0.0.1", port(22, name="ssh")),
            scan("nmap -sU -p 161 10.0.0.1", port(161, name="snmp", proto="udp"),
                 proto="udp", t="udp"),
        ])
        self.assertEqual({("tcp", 22), ("udp", 161)},
                         {(p.protocol, p.number) for p in merged.hosts[0].ports})

    def test_identified_service_beats_an_unidentified_one(self):
        """The scan that asked wins over the scan that didn't."""
        merged = merge_scans([
            scan("nmap -p- 10.0.0.1", port(6379, name="redis", method="table")),
            scan("nmap -sV -p 6379 10.0.0.1",
                 port(6379, name="redis", product="Redis key-value store", version="5.0.7")),
        ])
        p = merged.hosts[0].ports[0]
        self.assertTrue(p.probed)
        self.assertEqual("Redis key-value store 5.0.7", p.banner)

    def test_identification_survives_regardless_of_input_order(self):
        a = scan("nmap -sV -p 6379 10.0.0.1",
                 port(6379, name="redis", product="Redis", version="5.0.7"))
        b = scan("nmap -p- 10.0.0.1", port(6379, name="redis", method="table"))
        self.assertTrue(merge_scans([a, b]).hosts[0].ports[0].probed)
        self.assertTrue(merge_scans([b, a]).hosts[0].ports[0].probed)

    def test_open_beats_filtered(self):
        merged = merge_scans([
            scan("nmap -p 3306 10.0.0.1", port(3306, state="filtered", name="mysql")),
            scan("nmap -p 3306 10.0.0.1", port(3306, state="open", name="mysql")),
        ])
        self.assertEqual("open", merged.hosts[0].ports[0].state)

    def test_extraports_are_not_summed_across_overlapping_scans(self):
        ex = '<extraports state="filtered" count="988"><extrareasons reason="no-responses" count="988"/></extraports>'
        merged = merge_scans([
            scan("nmap -p- 10.0.0.1", port(22, name="ssh"), extra=ex),
            scan("nmap -p- 10.0.0.1", port(22, name="ssh"), extra=ex),
        ])
        self.assertEqual(988, merged.hosts[0].count_extra("filtered"))

    def test_up_in_one_scan_beats_down_in_another(self):
        merged = merge_scans([
            scan("nmap -p- 10.0.0.1", "", state="down"),
            scan("nmap -Pn -p- 10.0.0.1", port(22, name="ssh")),
        ])
        self.assertEqual("up", merged.hosts[0].state)
        self.assertEqual(1, len(merged.up_hosts()))

    def test_distinct_hosts_are_kept_separate(self):
        merged = merge_scans([
            scan("nmap 10.0.0.1", port(22, name="ssh"), addr="10.0.0.1"),
            scan("nmap 10.0.0.2", port(80, name="http"), addr="10.0.0.2"),
        ])
        self.assertEqual(["10.0.0.1", "10.0.0.2"], [h.address for h in merged.hosts])

    def test_truncation_is_contagious(self):
        a = scan("nmap -p- 10.0.0.1", port(22, name="ssh"))
        b = scan("nmap -p- 10.0.0.1", port(80, name="http"))
        b.exit_status = "truncated"
        self.assertEqual("truncated", merge_scans([a, b]).exit_status)

    def test_scripts_from_both_scans_are_kept(self):
        a = parse_string(HEAD.format(args="a", proto="tcp", t="syn")
                         + '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                           '<ports><port protocol="tcp" portid="21">'
                           '<state state="open" reason="syn-ack"/>'
                           '<service name="ftp" method="probed" conf="10"/>'
                           '<script id="ftp-anon" output="Anonymous FTP login allowed"/>'
                           '</port></ports></host></nmaprun>', source="a")
        b = parse_string(HEAD.format(args="b", proto="tcp", t="syn")
                         + '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                           '<ports><port protocol="tcp" portid="21">'
                           '<state state="open" reason="syn-ack"/>'
                           '<service name="ftp" method="probed" conf="10"/>'
                           '<script id="ftp-syst" output="STAT: FTP server status"/>'
                           '</port></ports></host></nmaprun>', source="b")
        merged = merge_scans([a, b])
        self.assertEqual({"ftp-anon", "ftp-syst"},
                         {s.id for s in merged.hosts[0].ports[0].scripts})

    def test_merging_a_udp_pass_clears_the_no_udp_caveat(self):
        """The point of the whole module: the caveat must describe the scan SET."""
        tcp = parse_file(os.path.join(FIXTURES, "sample.xml"))
        udp = parse_file(os.path.join(FIXTURES, "sample-udp.xml"))
        self.assertIn("COV-NO-UDP", {f.rule for f in review(tcp)})
        merged = merge_scans([tcp, udp])
        self.assertNotIn("COV-NO-UDP", {f.rule for f in review(merged)})

    def test_merged_source_names_every_input(self):
        merged = merge_scans([scan("a", port(22, name="ssh")), scan("b", port(80, name="http"))])
        self.assertIn("a", merged.source)
        self.assertIn("b", merged.source)


if __name__ == "__main__":
    unittest.main()
