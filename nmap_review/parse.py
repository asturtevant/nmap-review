"""nmap XML -> `model` objects.

Why XML and not grepping normal output
--------------------------------------
`-oN` output is formatted for a human and loses things this report depends on:
the `method`/`conf` attributes that say whether a service was *probed* or merely
looked up by port number, the `extraports` summary that says how much of the
scan came back as "no response", and the per-port `reason`. The whole point of
the review pass is to distinguish "nmap found X" from "nmap assumed X", and only
the XML carries that distinction.

Robustness
----------
nmap writes XML incrementally and the trailing `</nmaprun>` is missing if the
scan was killed. That is a common real case (a long scan interrupted), and the
partial data is still worth reviewing -- so a truncated document is repaired and
parsed, and the truncation is reported as a coverage caveat rather than being
silently ignored or fatally raised.
"""

import re
import xml.etree.ElementTree as ET

from .model import Host, Port, Scan, Script


class ParseError(Exception):
    pass


def parse_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return parse_string(f.read(), source=path)


def parse_string(text, source="<string>"):
    truncated = False
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        repaired = _repair_truncated(text)
        if repaired is None:
            raise ParseError(f"{source}: not parseable as nmap XML")
        try:
            root = ET.fromstring(repaired)
        except ET.ParseError as exc:
            raise ParseError(f"{source}: not parseable as nmap XML ({exc})")
        truncated = True

    if root.tag != "nmaprun":
        raise ParseError(f"{source}: root element is <{root.tag}>, expected <nmaprun>")

    scan = Scan(
        args=root.get("args", ""),
        version=root.get("version", ""),
        start=root.get("startstr", "") or root.get("start", ""),
        source=source,
    )

    for st in root.findall("scaninfo"):
        scan.scan_types.append((st.get("type", ""), st.get("protocol", ""), st.get("services", "")))

    runstats = root.find("runstats")
    if runstats is not None:
        fin = runstats.find("finished")
        if fin is not None:
            scan.finished = fin.get("timestr", "") or fin.get("time", "")
            scan.exit_status = fin.get("exit", "")

    if truncated:
        # Carried as an exit status the renderers and rules can both see; nmap
        # itself only writes "success"/"error" here, so "truncated" cannot
        # collide with a real value.
        scan.exit_status = "truncated"

    for el in root.findall("host"):
        scan.hosts.append(_host(el))

    return scan


def _host(el):
    host = Host(address="")

    for a in el.findall("address"):
        addr = a.get("addr", "")
        host.addresses.append((addr, a.get("addrtype", "")))
        # Prefer an IP as the canonical label; MAC addresses also appear here.
        if not host.address and a.get("addrtype", "").startswith("ipv"):
            host.address = addr
    if not host.address and host.addresses:
        host.address = host.addresses[0][0]

    status = el.find("status")
    if status is not None:
        host.state = status.get("state", "unknown")

    names = el.find("hostnames")
    if names is not None:
        for n in names.findall("hostname"):
            host.hostnames.append((n.get("name", ""), n.get("type", "")))

    ports = el.find("ports")
    if ports is not None:
        for ex in ports.findall("extraports"):
            reasons = [r.get("reason", "") for r in ex.findall("extrareasons")]
            host.extraports.append((ex.get("state", ""), int(ex.get("count", "0") or 0), reasons))
        for p in ports.findall("port"):
            host.ports.append(_port(p))

    os_el = el.find("os")
    if os_el is not None:
        for m in os_el.findall("osmatch"):
            host.os_matches.append((m.get("name", ""), int(m.get("accuracy", "0") or 0)))

    hs = el.find("hostscript")
    if hs is not None:
        host.scripts = [_script(s) for s in hs.findall("script")]

    dist = el.find("distance")
    if dist is not None:
        host.distance = int(dist.get("value", "0") or 0)

    return host


def _port(el):
    state = el.find("state")
    svc = el.find("service")
    port = Port(
        number=int(el.get("portid", "0") or 0),
        protocol=el.get("protocol", ""),
        state=state.get("state", "unknown") if state is not None else "unknown",
        reason=state.get("reason", "") if state is not None else "",
    )
    if svc is not None:
        port.service = svc.get("name", "")
        port.product = svc.get("product", "")
        port.version = svc.get("version", "")
        port.extrainfo = svc.get("extrainfo", "")
        port.tunnel = svc.get("tunnel", "")
        port.method = svc.get("method", "")
        conf = svc.get("conf")
        port.confidence = int(conf) if conf and conf.isdigit() else None
    port.scripts = [_script(s) for s in el.findall("script")]
    return port


def _script(el):
    # Structured script output (<table>/<elem>) is flattened: the rules match on
    # text, and a table's text is what a human reads in the terminal anyway.
    out = el.get("output", "")
    if not out:
        out = " ".join(t.strip() for t in el.itertext() if t.strip())
    return Script(id=el.get("id", ""), output=out.strip())


def _repair_truncated(text):
    """Close an interrupted nmap document so the partial scan can still be read.

    Only ever *appends* closing tags, and only for the elements nmap leaves
    open mid-run. If the text does not even contain an `<nmaprun` opening tag
    there is nothing to repair and this returns None rather than inventing a
    document.
    """
    if "<nmaprun" not in text:
        return None
    # Drop a trailing partial element (the write that was cut mid-tag).
    cut = text.rfind("<")
    if cut > text.rfind(">"):
        text = text[:cut]
    opened = re.findall(r"<(host|ports|nmaprun)\b", text)
    closed = re.findall(r"</(host|ports|nmaprun)>", text)
    missing = []
    for tag in ("ports", "host", "nmaprun"):
        n = opened.count(tag) - closed.count(tag)
        missing.extend([tag] * max(0, n))
    return text + "".join(f"</{t}>" for t in missing)
