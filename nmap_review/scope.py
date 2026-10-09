"""Dropping hosts from a report, visibly.

Why a filter at all
-------------------
Scans pick up things the report should not carry: the scanning box itself, a
neighbour's address inside the same /24, a jump host the client has put out of
scope, a load balancer that answers for everything and drowns the grid.

Why it is never silent
----------------------
A security report where a host simply is not there cannot be distinguished from
a scan that never saw it -- and that is the exact confusion the rest of this
tool exists to prevent. So filtering does not delete: it moves hosts into
`Scan.excluded`, every renderer prints what was excluded and by which pattern,
and the counts in the summary describe what is shown. A reader can always see
that a decision was made, and can ask whether it was the right one.

Matching
--------
A pattern may be an exact address, a CIDR block, or a shell-style glob that is
tried against the address and every hostname:

    --exclude-host 10.0.0.5
    --exclude-host 10.0.0.0/24
    --exclude-host '*.corp.internal'
    --only-host '192.168.56.*'

`--only-host` is applied first (an allow-list), then `--exclude-host` removes
from what is left -- so the two compose the way a reader expects: "this subnet,
except that box".
"""

import fnmatch
import ipaddress


def _as_network(pattern):
    try:
        return ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return None


def matches(host, pattern):
    """True when `pattern` selects this host by address, CIDR, or hostname glob."""
    net = _as_network(pattern)
    if net is not None:
        for addr, kind in (host.addresses or [(host.address, "ipv4")]):
            try:
                if ipaddress.ip_address(addr) in net:
                    return True
            except ValueError:
                continue        # a MAC address, which no CIDR can contain
        return False

    candidates = [host.address] + [a for a, _ in host.addresses] + \
                 [n for n, _ in host.hostnames]
    return any(fnmatch.fnmatch(c, pattern) or c == pattern for c in candidates)


def apply_scope(scan, only=(), exclude=()):
    """Return `scan` with out-of-scope hosts moved to `scan.excluded`.

    Mutates and returns the scan it is given -- the caller has just parsed it
    and nobody else holds a reference. Each excluded host is recorded with the
    pattern that removed it, so the report can say *why* as well as *what*.
    """
    only = [p for p in (only or []) if p]
    exclude = [p for p in (exclude or []) if p]
    if not only and not exclude:
        return scan

    kept, dropped = [], []
    for host in scan.hosts:
        reason = None
        if only:
            hit = next((p for p in only if matches(host, p)), None)
            if hit is None:
                reason = "not matched by --only-host"
        if reason is None:
            hit = next((p for p in exclude if matches(host, p)), None)
            if hit is not None:
                reason = f"--exclude-host {hit}"
        if reason is None:
            kept.append(host)
        else:
            dropped.append((host, reason))

    scan.hosts = kept
    scan.excluded = list(getattr(scan, "excluded", [])) + dropped
    return scan


def unmatched_patterns(scan, patterns):
    """Patterns that selected nothing -- usually a typo, and worth saying so."""
    everything = list(scan.hosts) + [h for h, _ in getattr(scan, "excluded", [])]
    return [p for p in patterns
            if p and not any(matches(h, p) for h in everything)]
