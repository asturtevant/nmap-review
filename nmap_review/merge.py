"""Combine several scans of the same estate into one.

Why this is needed
------------------
A real engagement does not produce one XML. It produces a quick TCP sweep, a
UDP pass, an overnight `-p-`, and often one file per subnet. Reviewed
separately, each report repeats the others' hosts and -- worse -- each one
carries coverage caveats the *set* has already answered: the TCP report says
"no UDP scan" when the UDP scan is sitting in the next file.

So merging is not a convenience. It is what makes the coverage rules tell the
truth about what was actually looked at.

How conflicts are resolved
--------------------------
Two scans frequently disagree about a port, and the disagreement is almost
always one scan knowing more than the other rather than the target changing.
A `-sV` run that identified `6379/tcp redis 5.0.7` and a fast sweep that called
it `open, no service` are not a contradiction; the second simply didn't ask. So
the record carrying more evidence wins, scored in this order:

    state (open > open|filtered > filtered > closed) > probed > has a banner

...and NSE output is unioned rather than replaced, because two scans with
different `--script` sets each hold evidence the other lacks.

The honest caveat
-----------------
Merged `args` is the concatenation of every input's. The coverage rules read
it, so a set containing one `-p-` scan will not report "only the default ports
were scanned" -- even if that `-p-` only covered one host of twelve. The merged
report therefore lists every input source in its header, and this is the reason
why: coverage of the *set* is being asserted, not of each host individually.
Where that distinction matters, review the scans separately.
"""

from .model import Host, Port, Scan

_STATE_RANK = {"open": 4, "open|filtered": 3, "filtered": 2,
               "unfiltered": 1, "closed": 0, "unknown": 0}


def merge_scans(scans):
    """Fold several `Scan`s into one. Order matters only for tie-breaks."""
    scans = [s for s in scans if s is not None]
    if not scans:
        raise ValueError("nothing to merge")
    if len(scans) == 1:
        return scans[0]

    merged = Scan(
        args=" | ".join(s.args for s in scans if s.args),
        version=next((s.version for s in scans if s.version), ""),
        start=next((s.start for s in scans if s.start), ""),
        finished=next((s.finished for s in reversed(scans) if s.finished), ""),
        source=" + ".join(s.source for s in scans),
    )
    merged.exit_status = ("truncated" if any(s.exit_status == "truncated" for s in scans)
                          else "success")

    seen_types = []
    for s in scans:
        for t in s.scan_types:
            if t not in seen_types:
                seen_types.append(t)
    merged.scan_types = seen_types

    by_addr = {}
    order = []
    for s in scans:
        for host in s.hosts:
            if host.address not in by_addr:
                by_addr[host.address] = _copy_host(host)
                order.append(host.address)
            else:
                _fold_host(by_addr[host.address], host)
    merged.hosts = [by_addr[a] for a in order]
    return merged


def _copy_host(host):
    clone = Host(address=host.address, state=host.state,
                 addresses=list(host.addresses), hostnames=list(host.hostnames),
                 os_matches=list(host.os_matches), ports=[_copy_port(p) for p in host.ports],
                 extraports=list(host.extraports), scripts=list(host.scripts),
                 distance=host.distance)
    return clone


def _copy_port(port):
    clone = Port(number=port.number, protocol=port.protocol, state=port.state,
                 reason=port.reason, service=port.service, product=port.product,
                 version=port.version, extrainfo=port.extrainfo, tunnel=port.tunnel,
                 method=port.method, confidence=port.confidence,
                 scripts=list(port.scripts))
    return clone


def _fold_host(into, other):
    # "up" from any scan wins: one scan reaching a host disproves the other's
    # "down", which only ever meant "I got no answer".
    if other.state == "up":
        into.state = "up"

    for item in other.addresses:
        if item not in into.addresses:
            into.addresses.append(item)
    for item in other.hostnames:
        if item not in into.hostnames:
            into.hostnames.append(item)

    # Keep the single most confident OS match per name.
    best = {n: a for n, a in into.os_matches}
    for name, acc in other.os_matches:
        if acc > best.get(name, -1):
            best[name] = acc
    into.os_matches = sorted(best.items(), key=lambda kv: -kv[1])

    if into.distance is None:
        into.distance = other.distance

    into.scripts = _merge_scripts(into.scripts, other.scripts)

    # extraports is a per-scan summary of the same address space; summing it
    # across overlapping scans would invent ports. The largest single-scan
    # count is the defensible number.
    totals = {}
    for state, count, reasons in list(into.extraports) + list(other.extraports):
        prev = totals.get(state)
        if prev is None or count > prev[0]:
            totals[state] = (count, reasons)
    into.extraports = [(st, cnt, reasons) for st, (cnt, reasons) in totals.items()]

    index = {(p.protocol, p.number): p for p in into.ports}
    for port in other.ports:
        key = (port.protocol, port.number)
        if key not in index:
            clone = _copy_port(port)
            into.ports.append(clone)
            index[key] = clone
        else:
            index[key] = _fold_port(index[key], port, into)


def _fold_port(existing, other, host):
    scripts = _merge_scripts(existing.scripts, other.scripts)
    winner = existing if _evidence(existing) >= _evidence(other) else other
    if winner is not existing:
        clone = _copy_port(other)
        host.ports[host.ports.index(existing)] = clone
        winner = clone
    winner.scripts = scripts
    return winner


def _evidence(port):
    return (_STATE_RANK.get(port.state, 0), 1 if port.probed else 0,
            1 if port.banner else 0, 1 if port.service else 0)


def _merge_scripts(a, b):
    out = list(a)
    have = {s.id: s for s in out}
    for script in b:
        prior = have.get(script.id)
        if prior is None:
            out.append(script)
            have[script.id] = script
        elif len(script.output) > len(prior.output):
            out[out.index(prior)] = script
            have[script.id] = script
    return out
