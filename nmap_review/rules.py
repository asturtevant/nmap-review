"""The review pass: what in this scan a human still has to look at.

Scope discipline
----------------
Nothing here claims a vulnerability. nmap reports what answered a probe; it does
not establish exploitability, and a banner is not a patch level. So every rule
produces an item for a *review queue* -- a thing to check, with the check named
-- and the wording stays at that altitude deliberately. A report that says
"VULNERABLE: OpenSSH 7.4" from a banner alone trains its reader to ignore it.

The two kinds of finding are not the same question
--------------------------------------------------
* `coverage` findings are about the *scan*: what it did not look at, and where
  its answers are guesses. These come first in the report, because they bound
  how much the rest of it is worth. A clean-looking host that was scanned on
  1,000 of 65,535 ports is not a clean-looking host.
* `surface` findings are about the *target*: exposed services whose presence is
  worth a human decision, ambiguous results, and evidence NSE already surfaced.

Priority is review urgency, not severity. `high` means "look at this first",
not "this is a critical vulnerability".
"""

import re
from dataclasses import dataclass, field

PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    rule: str
    priority: str            # high | medium | low | info
    kind: str                # coverage | surface
    title: str
    detail: str
    next_step: str
    target: str = ""         # host, or host:port
    evidence: list = field(default_factory=list)

    def sort_key(self):
        return (PRIORITY_ORDER.get(self.priority, 9), self.rule, self.target)


# --------------------------------------------------------------------------
# Service catalogue
#
# Keyed on nmap's service NAME where possible and the port number only as a
# fallback, because a service on a non-standard port is exactly the case a
# port-number-only table misses (Redis on 7000, mongo on 37017).
# --------------------------------------------------------------------------

# name -> (priority, what to review)
SENSITIVE_SERVICES = {
    # Datastores: historically unauthenticated by default, and the blast radius
    # of a wrong answer here is the whole dataset.
    "mysql":        ("high", "database exposed to the scanning position"),
    "postgresql":   ("high", "database exposed to the scanning position"),
    "ms-sql-s":     ("high", "database exposed to the scanning position"),
    "oracle-tns":   ("high", "database exposed to the scanning position"),
    "mongodb":      ("high", "database exposed; older defaults bind without auth"),
    "redis":        ("high", "key-value store exposed; default config has no auth"),
    "memcached":    ("high", "cache exposed; no auth in the protocol, UDP amplification source"),
    "elasticsearch": ("high", "search cluster exposed; no auth in the OSS default"),
    "couchdb":      ("high", "database exposed to the scanning position"),
    "cassandra":    ("high", "database exposed to the scanning position"),
    # Orchestration / infrastructure control planes: access here is usually
    # equivalent to code execution on the host or cluster.
    "docker":       ("high", "Docker API exposed; unauthenticated access is root on the host"),
    "kubernetes":   ("high", "Kubernetes API exposed; review anonymous-auth and RBAC"),
    "etcd":         ("high", "etcd exposed; holds cluster state and secrets"),
    "rmiregistry":  ("high", "Java RMI exposed; historically a deserialisation path"),
    "zookeeper":    ("medium", "coordination service exposed"),
    "consul":       ("medium", "service mesh / KV control plane exposed"),
    "rabbitmq":     ("medium", "message broker exposed"),
    # Cleartext protocols: credentials and content are recoverable on-path.
    "telnet":       ("high", "cleartext remote shell; credentials recoverable on-path"),
    "ftp":          ("high", "cleartext file transfer; check for anonymous login"),
    "rsh":          ("high", "cleartext remote shell with host-based trust"),
    "rlogin":       ("high", "cleartext remote login with host-based trust"),
    "rexec":        ("high", "cleartext remote execution"),
    "tftp":         ("medium", "UDP file transfer, no authentication"),
    "snmp":         ("high", "SNMP exposed; check for default community strings"),
    "ldap":         ("medium", "directory exposed without TLS; check for anonymous bind"),
    "pop3":         ("medium", "cleartext mail retrieval"),
    "imap":         ("medium", "cleartext mail retrieval"),
    "smtp":         ("medium", "mail transfer; check relay and STARTTLS policy"),
    "vnc":          ("high", "remote desktop exposed; VNC auth is weak by design"),
    "x11":          ("high", "X11 exposed; check access control (xhost)"),
    # Remote administration: legitimate, but each one is an authentication
    # surface that belongs in the exposure decision.
    "ssh":          ("medium", "remote administration reachable from this position"),
    "ms-wbt-server": ("medium", "RDP reachable; review NLA and lockout policy"),
    "winrm":        ("medium", "Windows remote management reachable"),
    # File sharing / RPC: broad protocol surface, frequent lateral-movement path.
    "microsoft-ds": ("medium", "SMB reachable; review signing, SMBv1, and share ACLs"),
    "netbios-ssn":  ("medium", "legacy NetBIOS session service reachable"),
    "nfs":          ("high", "NFS export reachable; review the export list and squash options"),
    "rpcbind":      ("medium", "RPC portmapper reachable; enumerates further services"),
    "msrpc":        ("medium", "RPC endpoint mapper reachable"),
    "ipp":          ("low", "print service exposed"),
    "upnp":         ("medium", "UPnP exposed; frequently unauthenticated"),
}

# Ports that matter even when nmap could not name the service.
SENSITIVE_PORTS = {
    2375: ("high", "Docker API (plain HTTP) exposed; unauthenticated access is root on the host"),
    2376: ("medium", "Docker API over TLS; review client-certificate enforcement"),
    6443: ("high", "Kubernetes API server exposed; review anonymous-auth and RBAC"),
    10250: ("high", "kubelet API exposed; historically allowed unauthenticated exec"),
    8500: ("medium", "Consul HTTP API exposed"),
    9200: ("high", "Elasticsearch HTTP exposed"),
    6379: ("high", "Redis exposed"),
    11211: ("high", "memcached exposed"),
    27017: ("high", "MongoDB exposed"),
    5601: ("medium", "Kibana exposed; often fronts an unauthenticated cluster"),
    15672: ("medium", "RabbitMQ management UI exposed"),
    9090: ("medium", "Prometheus/Cockpit-class admin UI exposed"),
    3000: ("low", "common development server port; confirm this is intentional"),
    8080: ("low", "common alternate HTTP port; confirm what is behind it"),
    4444: ("medium", "port commonly used by implants and handlers; confirm the owner"),
}

HTTP_NAMES = {"http", "http-alt", "http-proxy", "https", "https-alt", "ssl/http", "nagios-nsca"}

# Script output worth a human's eyes. Matched case-insensitively against NSE
# output; each entry is (pattern, priority, why).
SCRIPT_SIGNALS = [
    (r"\bVULNERABLE\b",              "high",   "an NSE script asserted a vulnerable state"),
    (r"CVE-\d{4}-\d{4,}",            "high",   "an NSE script referenced a specific CVE"),
    (r"anonymous (?:FTP )?login allowed", "high", "anonymous authentication accepted"),
    (r"\bLogin Success\b|\bvalid credentials\b", "high", "a script authenticated successfully"),
    (r"SSLv2|SSLv3",                 "high",   "obsolete SSL version offered"),
    (r"TLSv1\.0|TLSv1\.1",           "medium", "deprecated TLS version offered"),
    (r"self[- ]signed",              "medium", "certificate is self-signed"),
    (r"Not valid after:\s*\d{4}",    "medium", "certificate validity window needs checking"),
    (r"\bexpired\b",                 "medium", "certificate or credential reported expired"),
    (r"weak|insecure|deprecated",    "medium", "a script flagged a weak or deprecated setting"),
    (r"message_signing: disabled|signing (?:is )?disabled|signing enabled but not required",
     "high", "SMB signing is not enforced; relay attacks are in scope"),
    (r"SMBv1|smbv1",                 "high",   "SMBv1 in use"),
    (r"open relay|relay: *yes",      "high",   "mail relay may be open"),
    (r"default (?:password|credential|community)", "high", "default credentials or community string"),
    (r"directory listing|Index of /", "low",   "directory listing exposed"),
    (r"TRACE|PUT is allowed|WebDAV", "medium", "risky HTTP method or WebDAV enabled"),
]

# Software whose presence in a banner is worth a version check. The report never
# asserts the version is vulnerable -- it asserts a human should compare it to
# the vendor's advisories, which is a different and defensible claim.
VERSION_CHECKS = [
    (r"OpenSSH[ /](\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (8, 0),
     "OpenSSH older than 8.x"),
    (r"Apache httpd (\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (2, 4),
     "Apache httpd older than 2.4"),
    (r"nginx (\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (1, 20),
     "nginx older than 1.20"),
    (r"PHP[ /](\d+)\.", lambda m: int(m.group(1)) < 8, "PHP 7.x or older (end of life)"),
    (r"Microsoft IIS httpd (\d+)", lambda m: int(m.group(1)) < 8, "IIS 7.x or older"),
    (r"OpenSSL[ /](\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (3, 0),
     "OpenSSL 1.x branch"),
    (r"MySQL (\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (8, 0),
     "MySQL older than 8.0"),
    (r"ProFTPD (\d+)\.(\d+)", lambda m: True, "ProFTPD -- check advisories for this build"),
    (r"vsftpd (2\.3\.4)", lambda m: True, "vsftpd 2.3.4 -- the backdoored release"),
    (r"Samba smbd (\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (4, 15),
     "Samba older than 4.15"),
    (r"Exim smtpd (\d+)\.(\d+)", lambda m: (int(m.group(1)), int(m.group(2))) < (4, 95),
     "Exim older than 4.95"),
]


# --------------------------------------------------------------------------
# Coverage rules: how much of the target did this scan actually look at
# --------------------------------------------------------------------------

def _coverage(scan):
    out = []
    args = scan.args or ""
    tcp_services = ""
    protocols = set()
    for stype, proto, services in scan.scan_types:
        protocols.add(proto)
        if proto == "tcp":
            tcp_services = services

    if scan.exit_status == "truncated":
        out.append(Finding(
            "COV-TRUNCATED", "high", "coverage",
            "Scan output is incomplete",
            "The XML has no closing element, so nmap was interrupted or is still "
            "running. Hosts and ports after the cut-off point are simply absent "
            "from this report -- their absence is not a result.",
            "Re-run the scan to completion before treating any host here as clean.",
            target=scan.source,
        ))

    # Port breadth. nmap's default is its top 1,000 ports; everything else is
    # unexamined, and "no open ports found" means nothing without this context.
    if not re.search(r"(^|\s)(-p|--ports|-p-)", args):
        out.append(Finding(
            "COV-PORTS-DEFAULT", "high", "coverage",
            "Only nmap's default 1,000 ports were scanned",
            f"No explicit port selection was given (`{args.strip() or 'args unavailable'}`), "
            "so 64,535 of the 65,535 TCP ports were never probed. Services "
            "deliberately placed on high ports are the ones most likely to be "
            "interesting and the ones this scan cannot see.",
            "Re-run with `-p-` against the hosts that matter, even if only overnight.",
        ))
    elif "-F" in args.split():
        out.append(Finding(
            "COV-PORTS-FAST", "high", "coverage",
            "Fast scan: 100 ports only",
            "`-F` probes nmap's top 100 ports. This is a triage sweep, not an "
            "inventory.",
            "Re-run without `-F` (and ideally with `-p-`) before reporting coverage.",
        ))

    if "udp" not in protocols:
        out.append(Finding(
            "COV-NO-UDP", "medium", "coverage",
            "No UDP scan",
            "DNS, SNMP, NTP, TFTP, IKE, NetBIOS and most amplification-capable "
            "services are UDP. None of them can appear in a TCP-only result.",
            "Run a targeted `-sU --top-ports 50` pass; a full UDP sweep is rarely worth the time.",
        ))

    # Service identification. Without -sV every service name in the report is a
    # lookup of the port number in nmap-services -- a convention, not evidence.
    if not re.search(r"(^|\s)(-sV|-A|--version-all)", args):
        out.append(Finding(
            "COV-NO-SV", "high", "coverage",
            "No version detection: service names are port-number guesses",
            "Without `-sV`, nmap labels port 8080 'http-proxy' and port 3306 "
            "'mysql' because that is what those ports conventionally carry. "
            "Nothing in this scan confirms what is actually listening, so no "
            "version-based judgement below it is sound.",
            "Re-run with `-sV` (add `--version-all` where a service resists identification).",
        ))

    if not re.search(r"(^|\s)(-sC|-A|--script)", args):
        out.append(Finding(
            "COV-NO-SCRIPTS", "low", "coverage",
            "No NSE scripts were run",
            "The default script set is where anonymous-login, certificate, SMB "
            "signing and HTTP-method findings normally come from. None of that "
            "evidence exists in this scan.",
            "Re-run with `-sC`, or targeted `--script` categories for the services found.",
        ))

    if re.search(r"(^|\s)-T[45]", args):
        out.append(Finding(
            "COV-TIMING", "medium", "coverage",
            "Aggressive timing template",
            "`-T4`/`-T5` shortens probe timeouts. Against a rate-limiting host "
            "or a congested path this produces false 'closed'/'filtered' results "
            "that are indistinguishable from a genuinely closed port.",
            "Re-test anything you intend to report as closed at `-T3` or lower.",
        ))

    if re.search(r"(^|\s)(-Pn)", args) and not scan.up_hosts():
        out.append(Finding(
            "COV-PN-NO-HOSTS", "medium", "coverage",
            "`-Pn` was used and nothing responded",
            "With host discovery disabled, every address is treated as up and "
            "scanned regardless. A result with no responsive hosts may mean the "
            "range is empty, or that the scan never reached it at all.",
            "Confirm reachability from the scanning position (traceroute/ICMP) before concluding the range is empty.",
        ))

    if re.search(r"(^|\s)-sT(\s|$)", args):
        out.append(Finding(
            "COV-CONNECT-SCAN", "low", "coverage",
            "TCP connect scan (unprivileged)",
            "`-sT` completes the handshake, so the scan is slower, far noisier "
            "in the target's application logs, and cannot do OS detection or "
            "any raw-packet scan type.",
            "Re-run with root privileges for `-sS` if the scan needs to be quieter or broader.",
        ))

    if not scan.hosts:
        out.append(Finding(
            "COV-NO-HOSTS", "high", "coverage",
            "No hosts in the scan at all",
            "The run produced no host records. Either the target specification "
            "matched nothing, or the scan failed before probing.",
            "Check the target specification and the scanner's own network path.",
        ))

    down = [h for h in scan.hosts if h.state != "up"]
    if down and len(down) == len(scan.hosts):
        out.append(Finding(
            "COV-ALL-DOWN", "high", "coverage",
            "Every host was reported down",
            f"All {len(down)} host(s) were non-responsive. Host discovery is "
            "blocked by any firewall that drops ICMP and probes to closed ports, "
            "which is the common case for a hardened host -- 'down' is frequently "
            "a statement about the path, not the host.",
            "Re-run with `-Pn` to scan regardless of discovery.",
        ))

    if tcp_services and tcp_services.count(",") < 5 and "-" not in tcp_services:
        out.append(Finding(
            "COV-NARROW", "info", "coverage",
            "Very narrow port selection",
            f"The scan covered only: {tcp_services}. Useful for a single "
            "question; not an inventory of the host.",
            "State the port list alongside any 'no other services found' claim.",
        ))

    return out


def _host_coverage(scan):
    """Per-host caveats: results that exist but cannot be relied on as answers."""
    out = []
    for host in scan.up_hosts():
        filtered = host.count_extra("filtered") + sum(
            1 for p in host.ports if p.state == "filtered")
        total_ports = filtered + len(host.ports) + host.count_extra("closed")

        if total_ports and filtered / total_ports > 0.9 and filtered > 100:
            out.append(Finding(
                "COV-FILTERED", "medium", "coverage",
                "Almost everything came back filtered",
                f"{filtered} ports returned no response on {host.label}. Something "
                "on the path is dropping probes, so this host's port list is a "
                "statement about the firewall, not about the host.",
                "Re-scan from a position inside the filtering boundary, or confirm with the network owner which device is dropping.",
                target=host.label,
            ))

        ambiguous = host.ambiguous_ports()
        if ambiguous:
            out.append(Finding(
                "COV-AMBIGUOUS", "medium", "coverage",
                f"{len(ambiguous)} port(s) in an unresolved state",
                "nmap could not distinguish open from filtered on "
                + ", ".join(p.id for p in ambiguous[:12])
                + (" (and more)" if len(ambiguous) > 12 else "")
                + ". This is the normal outcome of a UDP scan and of a filtered "
                "TCP path: no response arrived, and silence has two causes.",
                "Probe these individually with `-sV --version-all`, or a protocol-specific client, before deciding.",
                target=host.label,
                evidence=[p.id for p in ambiguous[:30]],
            ))

        # "unknown"/"tcpwrapped" are not guesses about what the service is, so
        # they belong to SRF-UNIDENTIFIED rather than here; listing them as
        # "guessed to be unknown" is noise.
        guessed = [p for p in host.open_ports()
                   if p.service and not p.probed
                   and p.service not in {"unknown", "tcpwrapped"}]
        if guessed:
            out.append(Finding(
                "COV-GUESSED-SERVICES", "medium", "coverage",
                f"{len(guessed)} service name(s) are port-table guesses",
                "These ports are labelled from nmap-services, not from a probe: "
                + ", ".join(f"{p.id} -> {p.service}" for p in guessed[:12])
                + (" (and more)" if len(guessed) > 12 else "")
                + ". Treat the name as a hypothesis.",
                "Confirm with `-sV` on exactly these ports.",
                target=host.label,
                evidence=[f"{p.id} {p.service}" for p in guessed[:30]],
            ))

        low_conf = [p for p in host.open_ports()
                    if p.probed and p.confidence is not None and p.confidence <= 5]
        if low_conf:
            out.append(Finding(
                "COV-LOW-CONFIDENCE", "low", "coverage",
                "Low-confidence service identification",
                "nmap probed but was unsure about "
                + ", ".join(f"{p.id} (conf {p.confidence})" for p in low_conf[:10]) + ".",
                "Confirm by hand -- a banner grab or a protocol client is usually quicker than another nmap pass.",
                target=host.label,
            ))

        if host.os_matches:
            best = max(a for _, a in host.os_matches)
            if best < 90:
                out.append(Finding(
                    "COV-OS-UNCERTAIN", "low", "coverage",
                    f"OS fingerprint is uncertain ({best}%)",
                    "Best guesses: "
                    + "; ".join(f"{n} ({a}%)" for n, a in host.os_matches[:3])
                    + ". Below ~90% accuracy the OS line should not be quoted as fact.",
                    "Corroborate from a service banner, TTL, or an authenticated source before relying on the platform.",
                    target=host.label,
                ))
    return out


# --------------------------------------------------------------------------
# Surface rules: what is exposed, and what the evidence already says
# --------------------------------------------------------------------------

def _surface(scan):
    out = []
    for host in scan.up_hosts():
        open_ports = host.open_ports()

        for port in open_ports:
            where = f"{host.label} {port.id}"
            name = (port.service or "").lower()
            base = name.split("/")[-1]   # "ssl/http" -> "http"

            hit = SENSITIVE_SERVICES.get(base) or SENSITIVE_SERVICES.get(name)
            if hit:
                priority, why = hit
                detail = f"`{port.service}`" + (f" -- {port.banner}" if port.banner else "")
                if not port.probed:
                    priority = "medium" if priority == "high" else priority
                    detail += " (service name inferred from the port number, not probed)"
                out.append(Finding(
                    "SRF-SENSITIVE-SERVICE", priority, "surface",
                    f"{_sentence(why.split(';')[0].strip())} on {port.id}",
                    f"{detail}. {_sentence(why)}.",
                    _next_step_for(base, port),
                    target=where,
                ))
            elif port.number in SENSITIVE_PORTS:
                priority, why = SENSITIVE_PORTS[port.number]
                out.append(Finding(
                    "SRF-SENSITIVE-PORT", priority, "surface",
                    f"Port {port.id} is reachable",
                    f"{_sentence(why)}." + ("" if port.probed else " Nothing probed this port, so the service is unconfirmed."),
                    "Identify what is actually listening (`-sV -p " f"{port.number}`), then decide whether this exposure is intended.",
                    target=where,
                ))

            # Unidentified open ports are the single most review-worthy result
            # in any scan: something is listening and nobody knows what.
            if port.state == "open" and (not port.service or port.service in {"unknown", "tcpwrapped"}):
                out.append(Finding(
                    "SRF-UNIDENTIFIED", "high", "surface",
                    f"Unidentified service on {port.id}",
                    ("nmap saw a `tcpwrapped` response: the TCP handshake completed "
                     "and the service then closed the connection without speaking, "
                     "so what is behind it is unknown."
                     if port.service == "tcpwrapped" else
                     "A port is open and nmap could not name the service."),
                    "Grab the banner by hand (`ncat -v <host> " f"{port.number}`), then `-sV --version-all -p {port.number}`.",
                    target=where,
                ))

            if base in HTTP_NAMES and port.number not in (80, 443, 8080, 8443):
                out.append(Finding(
                    "SRF-HTTP-ODD-PORT", "low", "surface",
                    f"HTTP on a non-standard port ({port.id})",
                    "Web services on unexpected ports are usually admin "
                    "interfaces, dev builds or appliances -- the things least "
                    "likely to be in an asset inventory.",
                    "Open it and identify the application; run `--script http-title,http-headers` at minimum.",
                    target=where,
                ))

            if base == "http" and port.tunnel != "ssl" and port.number not in (8080,):
                out.append(Finding(
                    "SRF-CLEARTEXT-HTTP", "medium", "surface",
                    f"Cleartext HTTP on {port.id}",
                    "No TLS was detected on this listener. Anything authenticated "
                    "over it is recoverable on-path.",
                    "Check whether it redirects to HTTPS, and whether the redirect is enforced (HSTS) rather than advisory.",
                    target=where,
                ))

            out.extend(_version_findings(port, where))
            out.extend(_script_findings(port.scripts, where, port.id))

        out.extend(_script_findings(host.scripts, host.label, "host"))

        if len(open_ports) >= 15:
            out.append(Finding(
                "SRF-BROAD-SURFACE", "medium", "surface",
                f"{len(open_ports)} open ports on one host",
                "A host this broad is either a jump box, a misconfigured "
                "multi-role server, or something that has accumulated services "
                "nobody owns any more.",
                "Reconcile the port list against what this host is supposed to run; everything unaccounted for is the finding.",
                target=host.label,
                evidence=[f"{p.id} {p.service}" for p in open_ports],
            ))

        if len(host.hostnames) > 1:
            names = ", ".join(n for n, _ in host.hostnames)
            out.append(Finding(
                "SRF-MULTI-NAME", "info", "surface",
                "Host answers to several names",
                f"{names}. Virtual hosting means the services reached by name "
                "may differ from what the IP serves -- scanning the IP can miss "
                "a vhost entirely.",
                "Re-scan web services by hostname, and check for others (certificate SANs, `--script http-vhosts`).",
                target=host.label,
            ))

    return out


def _sentence(s):
    """Upper-case the first letter and leave the rest alone.

    `str.capitalize()` lower-cases the remainder, which turns "SNMP exposed"
    into "Snmp exposed" and "an NSE script" into "an nse script". Acronyms are
    most of the vocabulary here, so it cannot be used.
    """
    return s[:1].upper() + s[1:] if s else s


def _next_step_for(service, port):
    steps = {
        "ftp": f"`--script ftp-anon,ftp-syst -p {port.number}`; check for anonymous and writable paths.",
        "snmp": f"`--script snmp-info,snmp-brute -p {port.number}` (UDP); test `public`/`private`.",
        "smtp": f"`--script smtp-open-relay,smtp-commands -p {port.number}`.",
        "ldap": f"`--script ldap-rootdse -p {port.number}`; test for anonymous bind.",
        "redis": f"`redis-cli -h <host> -p {port.number} info` -- unauthenticated access shows immediately.",
        "mongodb": f"`--script mongodb-info -p {port.number}`.",
        "mysql": f"`--script mysql-info,mysql-empty-password -p {port.number}`.",
        "ms-sql-s": f"`--script ms-sql-info,ms-sql-empty-password -p {port.number}`.",
        "microsoft-ds": f"`--script smb2-security-mode,smb-os-discovery,smb-enum-shares -p {port.number}`.",
        "nfs": "`showmount -e <host>`; review exports for `no_root_squash` and world-readable paths.",
        "vnc": f"`--script vnc-info,realvnc-auth-bypass -p {port.number}`.",
        "telnet": "Confirm whether it can simply be turned off; if not, record the compensating control.",
        "ssh": f"`--script ssh2-enum-algos,ssh-auth-methods -p {port.number}`; confirm password auth is disabled.",
        "ms-wbt-server": f"`--script rdp-ntlm-info,rdp-enum-encryption -p {port.number}`; confirm NLA is required.",
        "docker": "`curl http://<host>:2375/version` -- an answer here is unauthenticated host root.",
        "kubernetes": "`curl -k https://<host>:6443/version`; review `--anonymous-auth` and RBAC bindings.",
        "elasticsearch": "`curl http://<host>:9200/_cat/indices` -- a listing means no auth.",
        "memcached": f"`--script memcached-info -p {port.number}`; check UDP is disabled (amplification).",
        "rpcbind": "`rpcinfo -p <host>` to enumerate what the mapper exposes.",
    }
    return steps.get(service,
                     f"Confirm the service and its authentication on {port.id}, then decide whether this exposure is intended.")


def _version_findings(port, where):
    out = []
    banner = port.banner
    if not banner:
        return out
    for pattern, predicate, label in VERSION_CHECKS:
        m = re.search(pattern, banner, re.I)
        if not m:
            continue
        try:
            if not predicate(m):
                continue
        except (ValueError, IndexError):       # pragma: no cover - defensive
            continue
        out.append(Finding(
            "SRF-VERSION-AGE", "medium", "surface",
            f"{label} on {port.id}",
            f"Banner: `{banner}`. A banner is not a patch level -- distributions "
            "backport fixes without changing it, and some services lie "
            "deliberately -- so this is a version to *check*, not a vulnerability.",
            "Compare the exact build against the vendor's advisories, or confirm the patch level from the host itself.",
            target=where,
            evidence=[banner],
        ))
    return out


def _script_findings(scripts, where, port_label):
    out = []
    for script in scripts:
        for pattern, priority, why in SCRIPT_SIGNALS:
            m = re.search(pattern, script.output, re.I)
            if not m:
                continue
            out.append(Finding(
                "SRF-SCRIPT-SIGNAL", priority, "surface",
                f"`{script.id}` output needs review ({port_label})",
                f"{_sentence(why)}. Matched: `{_excerpt(script.output, m)}`",
                "Read the full script output below and verify the claim directly; NSE reports both false positives and stale CVE mappings.",
                target=where,
                evidence=[f"{script.id}: {script.output}"],
            ))
            break   # one finding per script; the first match is the strongest
    return out


def _excerpt(text, match, width=90):
    start = max(0, match.start() - 20)
    end = min(len(text), match.end() + width)
    snippet = " ".join(text[start:end].split())
    return ("..." if start else "") + snippet + ("..." if end < len(text) else "")


def review(scan):
    """All findings for a scan, highest review priority first."""
    findings = _coverage(scan) + _host_coverage(scan) + _surface(scan)
    findings.sort(key=lambda f: f.sort_key())
    return findings
