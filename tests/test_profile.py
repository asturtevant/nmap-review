"""Role-inference tests.

The feature is guesswork with a confident voice, so most of these pin the
restraints rather than the detections: a hostname alone must never produce a
confident claim, common roles must not generate findings, and every reported
role must carry the signals that produced it.
"""

import os
import unittest

from nmap_review.parse import parse_file, parse_string
from nmap_review.profile import detect_roles, role_label
from nmap_review.rules import review

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
SAMPLE = os.path.join(FIXTURES, "sample.xml")

HEAD = ('<?xml version="1.0"?><nmaprun args="nmap -sV -p- 10.0.0.1" version="7.94">'
        '<scaninfo type="syn" protocol="tcp" numservices="10" services="1-10"/>')


def host(ports, name="host.example", os_name="", script="", addr="10.0.0.1"):
    xml = (HEAD + f'<host><status state="up"/><address addr="{addr}" addrtype="ipv4"/>'
           f'<hostnames><hostname name="{name}" type="PTR"/></hostnames>'
           f'<ports>{ports}</ports>'
           + (f'<os><osmatch name="{os_name}" accuracy="96"/></os>' if os_name else "")
           + (f'<hostscript><script id="smb-os-discovery" output="{script}"/></hostscript>'
              if script else "")
           + '</host></nmaprun>')
    return parse_string(xml, source="t").hosts[0]


def port(num, name="", product="", proto="tcp"):
    svc = (f'<service name="{name}" method="probed" conf="10"'
           + (f' product="{product}"' if product else "") + "/>") if name else ""
    return (f'<port protocol="{proto}" portid="{num}">'
            f'<state state="open" reason="syn-ack"/>{svc}</port>')


def names(h):
    return [r.name for r in detect_roles(h)]


class TestDomainController(unittest.TestCase):
    def test_kerberos_plus_ldap_is_enough(self):
        h = host(port(88, "kerberos-sec") + port(389, "ldap"))
        roles = detect_roles(h)
        self.assertEqual("Active Directory domain controller", roles[0].name)
        self.assertIn(roles[0].confidence, ("likely", "strong"))

    def test_full_dc_port_set_is_strong(self):
        h = host("".join(port(n) for n in (53, 88, 135, 139, 389, 445, 464, 636, 3268)))
        role = detect_roles(h)[0]
        self.assertEqual("Active Directory domain controller", role.name)
        self.assertEqual("strong", role.confidence)

    def test_hostname_alone_is_not_a_domain_controller(self):
        """`dc01` speaking neither Kerberos nor LDAP is a label, not a role."""
        h = host(port(80, "http"), name="dc01.corp.example")
        self.assertNotIn("Active Directory domain controller", names(h))

    def test_hostname_plus_one_weak_signal_stays_possible(self):
        h = host(port(445, "microsoft-ds") + port(135, "msrpc"), name="dc01.corp.example")
        role = next(r for r in detect_roles(h)
                    if r.name == "Active Directory domain controller")
        self.assertEqual("possible", role.confidence)

    def test_detection_works_without_version_detection(self):
        """Port numbers alone carry it: a -sV-less scan still sees 88+389+3268."""
        h = host(port(88) + port(389) + port(3268) + port(464))
        self.assertEqual("Active Directory domain controller", names(h)[0])

    def test_ldap_banner_alone_is_conclusive_enough(self):
        h = host(port(389, "ldap", "Microsoft Windows Active Directory LDAP"))
        self.assertIn("Active Directory domain controller", names(h))

    def test_fixture_dc_is_detected_and_the_decoy_is_not(self):
        scan = parse_file(SAMPLE)
        by_addr = {h.address: h for h in scan.hosts}
        self.assertEqual("Active Directory domain controller",
                         names(by_addr["192.168.56.14"])[0])
        # ...while win-dc01, whose DC ports were all filtered, is not claimed.
        self.assertNotIn("Active Directory domain controller",
                         names(by_addr["192.168.56.11"]))


class TestOtherRoles(unittest.TestCase):
    def test_hypervisor(self):
        self.assertIn("Virtualization host",
                      names(host(port(902, "vmware-auth") + port(443, "https", "VMware ESXi"))))

    def test_kubernetes_control_plane(self):
        self.assertIn("Kubernetes control plane",
                      names(host(port(6443) + port(2379) + port(10250))))

    def test_container_host(self):
        self.assertIn("Container host", names(host(port(2375))))

    def test_printer(self):
        self.assertIn("Network printer", names(host(port(9100) + port(631, "ipp"))))

    def test_network_device_from_os_fingerprint(self):
        h = host(port(22, "ssh") + port(161, "snmp", proto="udp"),
                 os_name="Cisco IOS 15.2")
        self.assertIn("Network device", names(h))

    def test_mail_server(self):
        self.assertIn("Mail server",
                      names(host(port(25, "smtp", "Postfix smtpd") + port(993, "imaps"))))

    def test_plain_web_host_claims_only_web_server(self):
        h = host(port(80, "http", "nginx") + port(443, "https"))
        self.assertEqual(["Web server"], names(h))

    def test_no_signals_means_no_roles(self):
        self.assertEqual([], names(host(port(12345))))

    def test_roles_are_ordered_by_evidence(self):
        h = host("".join(port(n) for n in (88, 389, 3268, 464, 445)) + port(80, "http"))
        scores = [r.score for r in detect_roles(h)]
        self.assertEqual(sorted(scores, reverse=True), scores)

    def test_role_label_is_renderable(self):
        self.assertIn("(strong)", role_label(host(port(6443) + port(2379) + port(10250))))


class TestRoleFindings(unittest.TestCase):
    def test_consequential_role_produces_a_finding(self):
        scan = parse_file(SAMPLE)
        dc = [f for f in review(scan)
              if f.rule == "SRF-HOST-ROLE" and "domain controller" in f.title]
        self.assertEqual(1, len(dc))
        self.assertEqual("high", dc[0].priority)
        self.assertIn("192.168.56.14", dc[0].target)

    def test_finding_shows_its_signals_and_hedges(self):
        scan = parse_file(SAMPLE)
        f = next(f for f in review(scan)
                 if f.rule == "SRF-HOST-ROLE" and "domain controller" in f.title)
        self.assertIn("Matched on:", f.detail)
        self.assertIn("inferred from the scan, not confirmed", f.detail)

    def test_common_roles_do_not_generate_findings(self):
        """Half an estate is a web server; flagging that is noise, not signal."""
        scan = parse_string(
            HEAD + '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                   f'<ports>{port(80, "http", "nginx")}{port(443, "https")}</ports>'
                   '</host></nmaprun>', source="t")
        self.assertEqual([], [f for f in review(scan) if f.rule == "SRF-HOST-ROLE"])

    def test_weak_evidence_is_reported_quietly_not_silently(self):
        scan = parse_string(
            HEAD + '<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>'
                   '<hostnames><hostname name="dc01.corp.example" type="PTR"/></hostnames>'
                   f'<ports>{port(445, "microsoft-ds")}{port(135, "msrpc")}</ports>'
                   '</host></nmaprun>', source="t")
        dc = [f for f in review(scan)
              if f.rule == "SRF-HOST-ROLE" and "domain controller" in f.title]
        self.assertEqual(1, len(dc))
        self.assertEqual("medium", dc[0].priority)      # downgraded from high
        self.assertIn("possible", dc[0].title)

    def test_grammar_of_the_title(self):
        scan = parse_file(SAMPLE)
        titles = [f.title for f in review(scan) if f.rule == "SRF-HOST-ROLE"]
        self.assertTrue(any(t.startswith("Looks like an Active Directory") for t in titles))
        self.assertFalse(any(" a Active" in t or " an Container" in t for t in titles))


if __name__ == "__main__":
    unittest.main()
