"""What changed between two scans.

The question a second scan is actually asking
---------------------------------------------
Nobody scans the same estate twice to read the same report twice. They scan it
again to find out what moved: a host that appeared, a port that opened, a
service that was upgraded (or downgraded), an exposure that was closed after
the last round of tickets. A full report of the new scan buries all of that
under the ninety percent that did not change.

It is also the only form of this report that can sit in CI without becoming
noise. `--fail-on high` against a single scan fires forever, because the
estate's standing exposures do not go away between Tuesday and Wednesday.
`diff --fail-on high` fires when something *new* appears, which is a check a
team can leave switched on for a year.

What counts as a change
-----------------------
Hosts appearing and disappearing, port states opening and closing, service
identity changing, and findings arriving or clearing. Service *version* changes
are reported separately from service *name* changes because they mean different
things: a version bump is usually patching, a name change usually means
something else is listening on that port.

Two cautions are built into the wording rather than left to the reader:

* A host that "disappeared" may simply not have answered this time -- the same
  silence that host discovery always has two readings for.
* A port that changed from `open` to `filtered` may be a firewall rule, a
  service stopping, or a dropped probe. The diff reports the transition; it
  does not claim the remediation happened.
"""

from dataclasses import dataclass, field

from .rules import PRIORITY_ORDER

KIND_ORDER = ["host-appeared", "port-opened", "service-changed", "finding-new",
              "version-changed", "port-closed", "host-gone", "finding-cleared"]


@dataclass
class Change:
    kind: str
    priority: str          # high | medium | low | info -- attention, not severity
    host: str
    title: str
    detail: str
    port: str = ""
    before: str = ""
    after: str = ""

    def sort_key(self):
        return (PRIORITY_ORDER.get(self.priority, 9),
                KIND_ORDER.index(self.kind) if self.kind in KIND_ORDER else 99,
                self.host, self.port)


@dataclass
class Diff:
    old: object
    new: object
    changes: list = field(default_factory=list)
    new_findings: list = field(default_factory=list)
    cleared_findings: list = field(default_factory=list)

    def by_kind(self, kind):
        return [c for c in self.changes if c.kind == kind]

    def counts(self):
        out = {k: 0 for k in PRIORITY_ORDER}
        for c in self.changes:
            out[c.priority] = out.get(c.priority, 0) + 1
        return out

    @property
    def unchanged(self):
        return not self.changes


def diff_scans(old, new, old_findings, new_findings):
    """Compare two scans (each may itself be a merge of several)."""
    d = Diff(old=old, new=new)
    old_hosts = {h.address: h for h in old.hosts}
    new_hosts = {h.address: h for h in new.hosts}

    for addr, host in new_hosts.items():
        if host.state != "up":
            continue
        prior = old_hosts.get(addr)
        if prior is None or prior.state != "up":
            why = ("was not in the previous scan at all" if prior is None
                   else "was not responding in the previous scan")
            d.changes.append(Change(
                "host-appeared", "high", host.label,
                f"New host: {host.label}",
                f"{host.label} {why}, and now answers with "
                f"{len(host.open_ports())} open port(s). Either it is new, or it "
                "was there and the previous scan could not see it -- both are "
                "worth knowing which.",
            ))

    for addr, prior in old_hosts.items():
        if prior.state != "up":
            continue
        host = new_hosts.get(addr)
        if host is None or host.state != "up":
            d.changes.append(Change(
                "host-gone", "medium", prior.label,
                f"Host no longer responding: {prior.label}",
                "It answered in the previous scan and did not this time. "
                "Decommissioned, powered off, moved, or simply not reached -- "
                "silence does not distinguish between them.",
            ))

    # Per-host port comparison, only where both scans saw the host.
    for addr, host in new_hosts.items():
        prior = old_hosts.get(addr)
        if prior is None or host.state != "up" or prior.state != "up":
            continue
        _diff_ports(d, prior, host)

    old_keys = {_finding_key(f) for f in old_findings}
    new_keys = {_finding_key(f) for f in new_findings}
    d.new_findings = [f for f in new_findings if _finding_key(f) not in old_keys]
    d.cleared_findings = [f for f in old_findings if _finding_key(f) not in new_keys]

    for f in d.new_findings:
        d.changes.append(Change(
            "finding-new", f.priority, _host_of(f.target),
            f"New review item: {f.title}", f.detail,
            port=_port_of(f.target),
        ))
    for f in d.cleared_findings:
        d.changes.append(Change(
            "finding-cleared", "info", _host_of(f.target),
            f"No longer reported: {f.title}",
            "This item does not appear in the new scan. Confirm it was fixed "
            "rather than merely not looked at -- a narrower scan clears "
            "findings just as effectively as a remediation does.",
            port=_port_of(f.target),
        ))

    d.changes.sort(key=lambda c: c.sort_key())
    return d


def _diff_ports(d, prior, host):
    was = {(p.protocol, p.number): p for p in prior.ports}
    now = {(p.protocol, p.number): p for p in host.ports}

    for key, port in now.items():
        before = was.get(key)
        if port.state == "open" and (before is None or before.state != "open"):
            prev = ("was not seen in the previous scan" if before is None
                    else f"was {before.state}")
            d.changes.append(Change(
                "port-opened", "high", host.label,
                f"Port opened: {port.id}"
                + (f" ({port.service})" if port.service else ""),
                f"{port.id} is open" + (f" running {port.banner}" if port.banner else "")
                + f"; it {prev}.",
                port=port.id, before=(before.state if before else "—"), after=port.state,
            ))
        elif before is not None and before.state != port.state:
            d.changes.append(Change(
                "port-closed" if before.state == "open" else "service-changed",
                "medium" if before.state == "open" else "low",
                host.label,
                f"Port state changed: {port.id}",
                f"{before.state} → {port.state}. A firewall rule, a stopped "
                "service, or a dropped probe all look like this.",
                port=port.id, before=before.state, after=port.state,
            ))

        if before is None or port.state != "open" or before.state != "open":
            continue
        if port.service and before.service and port.service != before.service:
            d.changes.append(Change(
                "service-changed", "high", host.label,
                f"Service changed on {port.id}: {before.service} → {port.service}",
                "A different service is answering on this port than last time. "
                "That is rarely a patch; something else is listening.",
                port=port.id, before=before.service, after=port.service,
            ))
        elif port.banner and before.banner and port.banner != before.banner:
            d.changes.append(Change(
                "version-changed", "low", host.label,
                f"Version changed on {port.id}",
                f"{before.banner} → {port.banner}. Usually patching; worth "
                "confirming it moved in the direction you expect.",
                port=port.id, before=before.banner, after=port.banner,
            ))

    for key, before in was.items():
        if before.state == "open" and key not in now:
            d.changes.append(Change(
                "port-closed", "medium", host.label,
                f"Port no longer reported open: {before.id}",
                "It was open in the previous scan and is absent from this one. "
                "Check the new scan actually covered this port before recording "
                "it as closed.",
                port=before.id, before="open", after="—",
            ))


def _finding_key(f):
    """Identity of a finding across scans: the rule and what it points at.

    Deliberately not the detail text -- "989 ports filtered" becoming "991
    ports filtered" is the same standing finding, and reporting it as new every
    week is how a diff becomes noise.
    """
    return (f.rule, f.target)


def _port_of(target):
    tail = (target or "").rsplit(" ", 1)[-1]
    return tail if "/" in tail else ""


def _host_of(target):
    """A finding's target minus its port, so the two are not printed twice."""
    if not target:
        return "(scan-wide)"
    head, _, tail = target.rpartition(" ")
    return head if head and "/" in tail else target
