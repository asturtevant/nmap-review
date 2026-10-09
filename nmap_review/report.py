"""Renderers: markdown, terminal text, and JSON.

Ordering is the argument
------------------------
Every renderer puts the review queue and the coverage caveats *above* the port
inventory. The inventory is the part people skim and feel informed by; the
caveats are the part that says how much the inventory is worth. Putting the
tables first would be prettier and would reliably mislead.

The JSON form exists so this can sit in a pipeline (diff two scans, feed a
ticket tracker) without anyone parsing the prose.
"""

import json
from dataclasses import asdict

from .rules import PRIORITY_ORDER

MARK = {"high": "!!", "medium": "!", "low": "~", "info": "i"}
BADGE = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def counts(findings):
    out = {k: 0 for k in PRIORITY_ORDER}
    for f in findings:
        out[f.priority] = out.get(f.priority, 0) + 1
    return out


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

def markdown(scan, findings):
    L = []
    w = L.append
    c = counts(findings)
    cov = [f for f in findings if f.kind == "coverage"]
    srf = [f for f in findings if f.kind == "surface"]

    w("# nmap review")
    w("")
    w(f"- **Source:** `{scan.source}`")
    if scan.args:
        w(f"- **Command:** `{scan.args}`")
    if scan.version:
        w(f"- **nmap:** {scan.version}")
    if scan.start:
        w(f"- **Started:** {scan.start}")
    if scan.finished:
        w(f"- **Finished:** {scan.finished}"
          + ("  **(incomplete output)**" if scan.exit_status == "truncated" else ""))
    up = scan.up_hosts()
    open_total = sum(len(h.open_ports()) for h in up)
    w(f"- **Hosts:** {len(up)} up of {len(scan.hosts)} scanned — "
      f"**{open_total} open port(s)** total")
    w(f"- **Review items:** {c['high']} high · {c['medium']} medium · "
      f"{c['low']} low · {c['info']} info")
    w("")
    w("> This report says what answered a probe and what a human still has to "
      "check. It does not establish that anything is vulnerable: a banner is "
      "not a patch level, and an open port is not a finding until someone "
      "decides it should not be open.")
    w("")

    # --- Coverage first -----------------------------------------------------
    w("## 1. How far to trust this scan")
    w("")
    if not cov:
        w("No coverage caveats: the scan's breadth and identification method "
          "support the conclusions below.")
        w("")
    else:
        w("Each item below limits what the rest of this report can be used to "
          "claim. Read them before the inventory.")
        w("")
        for f in cov:
            _md_finding(w, f)

    # --- Review queue -------------------------------------------------------
    w("## 2. Review queue")
    w("")
    if not srf:
        w("Nothing in the results flagged for review. Given the coverage notes "
          "above, that is a statement about this scan, not about the target.")
        w("")
    else:
        w("| # | Priority | Target | Item |")
        w("|---|---|---|---|")
        for i, f in enumerate(srf, 1):
            w(f"| {i} | {BADGE[f.priority]} | `{f.target or '-'}` | {f.title} |")
        w("")
        for i, f in enumerate(srf, 1):
            _md_finding(w, f, index=i)

    # --- Inventory ----------------------------------------------------------
    w("## 3. Inventory")
    w("")
    if not up:
        w("No responsive hosts.")
        w("")
    for host in up:
        w(f"### {host.label}")
        w("")
        meta = []
        if host.os_matches:
            n, a = host.os_matches[0]
            meta.append(f"OS guess: {n} ({a}%)")
        if host.distance is not None:
            meta.append(f"{host.distance} hop(s) away")
        extra = ", ".join(f"{cnt} {st}" for st, cnt, _ in host.extraports if cnt)
        if extra:
            meta.append(f"not shown: {extra}")
        if meta:
            w("*" + " · ".join(meta) + "*")
            w("")

        shown = [p for p in host.ports if p.state != "closed"]
        if not shown:
            w("No open or ambiguous ports in the scanned range.")
            w("")
            continue
        w("| Port | State | Service | Version | Identified by |")
        w("|---|---|---|---|---|")
        for p in sorted(shown, key=lambda p: (p.protocol, p.number)):
            how = "probe" if p.probed else ("port table" if p.service else "—")
            w(f"| {p.id} | {p.state} | {p.service or '—'} | "
              f"{p.banner or '—'} | {how} |")
        w("")

        scripted = [p for p in shown if p.scripts]
        if scripted or host.scripts:
            w("<details><summary>NSE script output</summary>")
            w("")
            for s in host.scripts:
                w(f"**host · {s.id}**")
                w("")
                w("```")
                w(s.output)
                w("```")
                w("")
            for p in scripted:
                for s in p.scripts:
                    w(f"**{p.id} · {s.id}**")
                    w("")
                    w("```")
                    w(s.output)
                    w("```")
                    w("")
            w("</details>")
            w("")

    # --- Follow-up ----------------------------------------------------------
    w("## 4. Suggested follow-up scans")
    w("")
    steps = _followups(scan, findings)
    if steps:
        w("```bash")
        for s in steps:
            w(s)
        w("```")
    else:
        w("None beyond the per-item next steps above.")
    w("")
    w("---")
    w("")
    w("*Generated by `nmap-review`. Scan only systems you are authorised to test.*")
    return "\n".join(L) + "\n"


def _md_finding(w, f, index=None):
    head = f"**{BADGE[f.priority]}** — {f.title}"
    if index is not None:
        head = f"**{index}. {BADGE[f.priority]}** — {f.title}"
    w(f"#### {head}")
    w("")
    if f.target:
        w(f"`{f.target}`  ·  rule `{f.rule}`")
        w("")
    else:
        w(f"rule `{f.rule}`")
        w("")
    w(f.detail)
    w("")
    w(f"**Next step:** {f.next_step}")
    w("")


# --------------------------------------------------------------------------
# Terminal text
# --------------------------------------------------------------------------

def text(scan, findings, width=78):
    L = []
    w = L.append
    c = counts(findings)
    w("=" * width)
    w("nmap review".center(width))
    w("=" * width)
    w(f"source   : {scan.source}")
    if scan.args:
        w(f"command  : {scan.args}")
    up = scan.up_hosts()
    w(f"hosts    : {len(up)} up / {len(scan.hosts)} scanned, "
      f"{sum(len(h.open_ports()) for h in up)} open port(s)")
    w(f"review   : {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    w("")

    for kind, heading in (("coverage", "SCAN COVERAGE -- what this scan cannot tell you"),
                          ("surface", "REVIEW QUEUE -- what needs a human")):
        items = [f for f in findings if f.kind == kind]
        w("-" * width)
        w(heading)
        w("-" * width)
        if not items:
            w("  (nothing)")
            w("")
            continue
        for f in items:
            target = f" [{f.target}]" if f.target else ""
            w(f"[{MARK[f.priority]}] {f.title}{target}")
            for line in _wrap(f.detail, width - 6):
                w(f"      {line}")
            for line in _wrap("-> " + f.next_step, width - 6):
                w(f"      {line}")
            w("")

    w("-" * width)
    w("INVENTORY")
    w("-" * width)
    for host in up:
        w(f"{host.label}  ({host.state})")
        shown = [p for p in host.ports if p.state != "closed"]
        if not shown:
            w("    no open or ambiguous ports")
        for p in sorted(shown, key=lambda p: (p.protocol, p.number)):
            flag = " " if p.probed else "?"
            w(f"  {flag} {p.id:<12} {p.state:<14} {p.service or '-':<16} {p.banner}")
        extra = ", ".join(f"{cnt} {st}" for st, cnt, _ in host.extraports if cnt)
        if extra:
            w(f"    not shown: {extra}")
        w("")
    w("  '?' = service name guessed from the port number, not probed")
    w("")
    steps = _followups(scan, findings)
    if steps:
        w("-" * width)
        w("SUGGESTED FOLLOW-UP")
        w("-" * width)
        for s in steps:
            w(f"  {s}")
        w("")
    return "\n".join(L) + "\n"


def _wrap(s, width):
    words, line, out = s.split(), "", []
    for word in words:
        if len(line) + len(word) + 1 > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------

def to_json(scan, findings, indent=2):
    payload = {
        "scan": {
            "source": scan.source,
            "args": scan.args,
            "nmap_version": scan.version,
            "started": scan.start,
            "finished": scan.finished,
            "exit_status": scan.exit_status,
            "hosts_scanned": len(scan.hosts),
            "hosts_up": len(scan.up_hosts()),
            "open_ports": sum(len(h.open_ports()) for h in scan.up_hosts()),
        },
        "counts": counts(findings),
        "findings": [asdict(f) for f in findings],
        "hosts": [
            {
                "address": h.address,
                "hostnames": [n for n, _ in h.hostnames],
                "state": h.state,
                "os": [{"name": n, "accuracy": a} for n, a in h.os_matches],
                "ports": [
                    {
                        "port": p.number, "protocol": p.protocol, "state": p.state,
                        "service": p.service, "version": p.banner,
                        "identified_by": "probe" if p.probed else ("port-table" if p.service else None),
                        "confidence": p.confidence,
                        "scripts": {s.id: s.output for s in p.scripts},
                    }
                    for p in h.ports if p.state != "closed"
                ],
                "not_shown": [{"state": st, "count": cnt} for st, cnt, _ in h.extraports],
            }
            for h in scan.hosts
        ],
        "followups": _followups(scan, findings),
    }
    return json.dumps(payload, indent=indent) + "\n"


# --------------------------------------------------------------------------
# Follow-up command suggestions
# --------------------------------------------------------------------------

def _followups(scan, findings):
    """Concrete next scans, derived from the gaps the rules actually found.

    Deliberately a small set of whole commands rather than one per finding: a
    reviewer will run three commands and ignore thirty.
    """
    rules = {f.rule for f in findings}
    targets = " ".join(h.address for h in scan.up_hosts()) or "<target>"
    out = []

    if "COV-PORTS-DEFAULT" in rules or "COV-PORTS-FAST" in rules:
        out.append(f"nmap -p- -sV -T3 -oX full-tcp.xml {targets}   # the 64,535 ports this scan skipped")
    if "COV-NO-SV" in rules:
        out.append(f"nmap -sV -sC -oX identified.xml {targets}     # confirm services instead of guessing")
    elif "COV-NO-SCRIPTS" in rules:
        out.append(f"nmap -sV -sC -oX scripted.xml {targets}       # default NSE evidence")
    if "COV-NO-UDP" in rules:
        out.append(f"sudo nmap -sU --top-ports 50 -sV -oX udp.xml {targets}")
    if "COV-ALL-DOWN" in rules:
        out.append(f"nmap -Pn -sV -oX nodiscovery.xml {targets}    # discovery is being filtered")

    # Ports nmap could not identify: the highest-value re-probe there is.
    unknown = []
    for h in scan.up_hosts():
        for p in h.open_ports():
            if not p.service or p.service in {"unknown", "tcpwrapped"} or not p.probed:
                unknown.append(str(p.number))
    if unknown:
        ports = ",".join(sorted(set(unknown), key=int)[:40])
        out.append(f"nmap -sV --version-all -p {ports} -oX unknown-services.xml {targets}")
    return out
