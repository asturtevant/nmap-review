"""What a host appears to BE, not just what ports it has.

The gap this fills
------------------
A port list is not a host. "445/tcp, 3389/tcp, 5985/tcp on Windows Server" is
technically complete and practically useless: the reader still has to know that
this is a domain controller before any of it means anything. Everything about
the review changes once that is said out loud -- SMB signing stops being a
hygiene item and becomes a path to the directory, and "remote administration
reachable" stops being routine.

So this module names the role, and every role carries the sentence explaining
why it changes the reading of the rest of the host.

Evidence, weights, and never bluffing
-------------------------------------
Role inference is guesswork with a confident voice, which is a bad combination
in a security report. Three defences:

* Every role is scored from *named* signals, and the report prints the signals
  it matched. The reader can see "Kerberos + LDAP + global catalog" and judge
  it themselves rather than trusting a label.
* Confidence is reported (`strong` / `likely` / `possible`) and derived from
  the score, so a host identified by one weak hint is never presented the way
  one with four independent protocol signals is.
* A hostname is a *corroborating* signal worth almost nothing on its own. A box
  called `dc01` that speaks no Kerberos and no LDAP is not a domain controller;
  it is a name. Naming alone can never exceed `possible`.

The port-only signals deliberately tolerate missing `-sV`: a scan that never
probed still knows which ports answered, and 88 + 389 + 3268 together is a
domain controller whether or not anything asked the services their names.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Role:
    name: str
    confidence: str          # strong | likely | possible
    score: int
    signals: list = field(default_factory=list)
    priority: str = ""       # review priority when this role warrants a finding
    review: str = ""         # why the role changes how the host is read
    next_step: str = ""


def _ports(host):
    """{(protocol, number)} of everything open, for the port-only signals."""
    return {(p.protocol, p.number) for p in host.open_ports()}


def _has(host, number, protocol="tcp"):
    return (protocol, number) in _ports(host)


def _any_port(host, numbers, protocol="tcp"):
    open_ = _ports(host)
    return any((protocol, n) in open_ for n in numbers)


def _count(host, numbers, protocol="tcp"):
    open_ = _ports(host)
    return sum(1 for n in numbers if (protocol, n) in open_)


def _banner_has(host, pattern):
    rx = re.compile(pattern, re.I)
    return any(rx.search(p.banner) or rx.search(p.service or "")
               for p in host.open_ports())


def _script_has(host, pattern):
    rx = re.compile(pattern, re.I)
    scripts = list(host.scripts) + [s for p in host.ports for s in p.scripts]
    return any(rx.search(s.output) for s in scripts)


def _os_has(host, pattern):
    rx = re.compile(pattern, re.I)
    return any(rx.search(name) for name, _ in host.os_matches)


def _name_has(host, pattern):
    rx = re.compile(pattern, re.I)
    names = [host.address] + [n for n, _ in host.hostnames]
    return any(rx.search(n) for n in names)


# --------------------------------------------------------------------------
# Role definitions
#
# (weight, description, predicate). Weight 1 is corroboration, 2 is a real
# indicator, 3 is close to conclusive on its own.
# --------------------------------------------------------------------------

ROLES = [
    {
        "name": "Active Directory domain controller",
        "priority": "high",
        "review": (
            "A domain controller holds the credentials for everything that "
            "trusts it, so every other item on this host is read differently: "
            "SMB signing is a relay path to the directory rather than a "
            "hygiene note, an exposed administration service is a route to "
            "Domain Admin, and an unpatched SMB stack is the whole estate."
        ),
        "next_step": (
            "Confirm the domain and the DC role (`--script smb-os-discovery,"
            "ldap-rootdse`), then review this host against DC hardening "
            "specifically: SMB signing required, LDAP channel binding and "
            "signing, no anonymous bind, print spooler, and the patch level of "
            "the SMB and Netlogon stacks."
        ),
        "signals": [
            (3, "LDAP banner names Active Directory",
             lambda h: _banner_has(h, r"active directory")),
            (3, "Kerberos (88) and LDAP (389) both open",
             lambda h: _has(h, 88) and _has(h, 389)),
            (2, "Global catalog (3268/3269) open",
             lambda h: _any_port(h, (3268, 3269))),
            (2, "Kerberos password change (464) open", lambda h: _has(h, 464)),
            (2, "a script reports a Windows domain",
             lambda h: _script_has(h, r"Domain name:|defaultNamingContext|"
                                      r"dnsHostName|NetBIOS domain name")),
            (1, "LDAPS (636) open", lambda h: _has(h, 636)),
            (1, "DNS (53) served by a Windows host",
             lambda h: _has(h, 53) and (_os_has(h, "windows") or _has(h, 445))),
            (1, "SMB (445) and RPC endpoint mapper (135) open",
             lambda h: _has(h, 445) and _has(h, 135)),
            (1, "hostname suggests a domain controller (weak on its own)",
             lambda h: _name_has(h, r"(^|[^a-z])dc\d*([^a-z]|$)|domaincontroller")),
        ],
    },
    {
        "name": "Virtualization host",
        "priority": "high",
        "review": (
            "A hypervisor's management plane is equivalent to physical access "
            "to every guest on it: console, disk, and snapshot. Its exposure "
            "decision is about the guests, not about this address."
        ),
        "next_step": "Confirm the product and version, and verify the management "
                     "interface is reachable only from an administration network.",
        "signals": [
            (3, "ESXi/vSphere service banner",
             lambda h: _banner_has(h, r"vmware|esxi|vsphere")),
            (2, "VMware authentication daemon (902/903)",
             lambda h: _any_port(h, (902, 903))),
            (3, "Proxmox web interface (8006)", lambda h: _has(h, 8006)),
            (2, "libvirt (16509/16514)", lambda h: _any_port(h, (16509, 16514))),
            (1, "Xen/oVirt-style management port (8443) with a hypervisor name",
             lambda h: _has(h, 8443) and _name_has(h, r"esx|vmw|hv|hyperv|prox")),
        ],
    },
    {
        "name": "Kubernetes control plane",
        "priority": "high",
        "review": (
            "The API server and etcd together are the cluster: read access to "
            "etcd is every secret in it, and the kubelet API has historically "
            "allowed unauthenticated exec into running containers."
        ),
        "next_step": "Check `--anonymous-auth`, RBAC bindings, and whether etcd "
                     "and the kubelet are reachable from outside the control plane.",
        "signals": [
            (3, "Kubernetes API server (6443)", lambda h: _has(h, 6443)),
            (2, "kubelet API (10250/10255)", lambda h: _any_port(h, (10250, 10255))),
            (2, "etcd (2379/2380)", lambda h: _any_port(h, (2379, 2380))),
            (1, "Kubernetes in a service banner", lambda h: _banner_has(h, r"kubernetes|k8s")),
        ],
    },
    {
        "name": "Container host",
        "priority": "high",
        "review": "An exposed Docker API is root on the host, with no "
                  "authentication step in the default configuration.",
        "next_step": "Confirm whether the daemon requires client certificates; "
                     "an unauthenticated answer on 2375 is immediate compromise.",
        "signals": [
            (3, "Docker API over plain HTTP (2375)", lambda h: _has(h, 2375)),
            (2, "Docker API over TLS (2376)", lambda h: _has(h, 2376)),
            (1, "Docker in a service banner", lambda h: _banner_has(h, r"docker")),
        ],
    },
    {
        "name": "Mail server",
        "priority": "medium",
        "review": "Mail infrastructure is both an inbound attack surface and a "
                  "resource worth abusing: relay, spoofing, and credential "
                  "harvesting are all decided here.",
        "next_step": "Review relay policy, STARTTLS enforcement and "
                     "authentication (`--script smtp-open-relay,smtp-commands`).",
        "signals": [
            (2, "SMTP (25) open", lambda h: _has(h, 25)),
            (2, "submission or SMTPS (587/465)", lambda h: _any_port(h, (587, 465))),
            (2, "mailbox access (110/143/993/995)",
             lambda h: _any_port(h, (110, 143, 993, 995))),
            (1, "mail software in a banner",
             lambda h: _banner_has(h, r"postfix|exim|sendmail|dovecot|exchange")),
        ],
    },
    {
        "name": "Database server",
        "priority": "medium",
        "review": "The host's value is its data rather than its services, so "
                  "the exposure question is who can reach the listener at all.",
        "next_step": "Confirm authentication and network restriction on each "
                     "database port; a listener reachable from a user network "
                     "is the finding regardless of its version.",
        "signals": [
            (2, "database listener open",
             lambda h: _any_port(h, (3306, 5432, 1433, 1521, 27017, 6379, 9200,
                                     5984, 9042, 11211))),
            (2, "a second database listener open",
             lambda h: _count(h, (3306, 5432, 1433, 1521, 27017, 6379, 9200,
                                  5984, 9042, 11211)) > 1),
            (1, "database software in a banner",
             lambda h: _banner_has(h, r"mysql|mariadb|postgres|sql server|oracle|"
                                      r"mongodb|redis|elasticsearch")),
        ],
    },
    {
        "name": "Network device",
        "priority": "medium",
        "review": "Switches, routers and firewalls see and shape other hosts' "
                  "traffic, and are routinely left on vendor defaults and "
                  "firmware years behind.",
        "next_step": "Identify the vendor and firmware, check for default "
                     "credentials and SNMP community strings, and confirm "
                     "management is not reachable from a user network.",
        "signals": [
            (3, "network-vendor OS fingerprint",
             lambda h: _os_has(h, r"cisco|juniper|mikrotik|arista|fortinet|"
                                  r"palo alto|ubiquiti|hp switch|aruba")),
            (2, "SNMP (161/udp) with a management service",
             lambda h: _has(h, 161, "udp") and _any_port(h, (22, 23, 80, 443))),
            (2, "telnet open alongside SNMP",
             lambda h: _has(h, 23) and _has(h, 161, "udp")),
            (1, "vendor name in a banner",
             lambda h: _banner_has(h, r"cisco|juniper|mikrotik|routeros|fortigate")),
        ],
    },
    {
        "name": "Network printer",
        "priority": "medium",
        "review": "Printers hold queued documents and often cached directory "
                  "credentials, answer on unauthenticated raw ports, and are "
                  "excluded from patching programmes almost everywhere.",
        "next_step": "Check the embedded web server for an unauthenticated "
                     "admin interface and for stored scan-to-folder or LDAP "
                     "credentials.",
        "signals": [
            (3, "raw print port (9100)", lambda h: _has(h, 9100)),
            (2, "IPP (631) or LPD (515)", lambda h: _any_port(h, (631, 515))),
            (1, "printer vendor in a banner",
             lambda h: _banner_has(h, r"jetdirect|printer|kyocera|ricoh|xerox|lexmark")),
        ],
    },
    {
        "name": "Web server",
        "priority": "",            # context, not a finding: too common to flag
        "review": "",
        "next_step": "",
        "signals": [
            (2, "HTTP/HTTPS open", lambda h: _any_port(h, (80, 443))),
            (1, "alternate HTTP port open", lambda h: _any_port(h, (8080, 8443, 8000))),
            (1, "web server software in a banner",
             lambda h: _banner_has(h, r"apache|nginx|iis|lighttpd|caddy|tomcat")),
        ],
    },
    {
        "name": "File server",
        "priority": "",
        "review": "",
        "next_step": "",
        "signals": [
            (2, "SMB (445) open", lambda h: _has(h, 445)),
            (2, "NFS (2049) open", lambda h: _has(h, 2049)),
            (1, "FTP (21) open", lambda h: _has(h, 21)),
        ],
    },
    {
        "name": "DNS server",
        "priority": "",
        "review": "",
        "next_step": "",
        "signals": [
            (3, "DNS (53) answering", lambda h: _has(h, 53) or _has(h, 53, "udp")),
            (1, "DNS software in a banner", lambda h: _banner_has(h, r"bind|dnsmasq|unbound")),
        ],
    },
]

# A score needs this much to be claimed at all, and this much to be confident.
_POSSIBLE, _LIKELY, _STRONG = 2, 3, 5


def detect_roles(host):
    """Roles this host appears to fill, best-supported first."""
    found = []
    for spec in ROLES:
        score, signals = 0, []
        for weight, description, predicate in spec["signals"]:
            try:
                hit = predicate(host)
            except Exception:                      # pragma: no cover - defensive
                hit = False
            if hit:
                score += weight
                signals.append(description)
        if score < _POSSIBLE:
            continue
        # A name alone never graduates past "possible": `dc01` that speaks no
        # Kerberos is a label somebody typed, not a domain controller.
        protocol_score = score - sum(
            w for w, d, p in spec["signals"]
            if d in signals and ("hostname" in d or "name in a banner" in d))
        confidence = ("strong" if score >= _STRONG and protocol_score >= _LIKELY
                      else "likely" if score >= _LIKELY and protocol_score >= 2
                      else "possible")
        found.append(Role(name=spec["name"], confidence=confidence, score=score,
                          signals=signals, priority=spec["priority"],
                          review=spec["review"], next_step=spec["next_step"]))
    found.sort(key=lambda r: (-r.score, r.name))
    return found


def role_label(host):
    """One-line summary for a card or a table: 'DC (strong), file server'."""
    roles = detect_roles(host)
    return ", ".join(f"{r.name} ({r.confidence})" for r in roles)
