"""Self-contained HTML report: summary, host grid, per-host drill-down.

Shape of the page
-----------------
Three levels, because that is how a scan actually gets read:

1. **Summary band** -- how many hosts, how many up, how many open ports, how
   many hosts carry a high-priority item, how much of the target was examined.
   The numbers a reader wants before they want anything else.
2. **Host grid** -- one card per host, accented by its worst review priority,
   so the hosts needing attention are visible without reading anything. The
   grid is the landing view.
3. **Host detail** -- click a card: that host's findings, its full port table
   with how each service was identified, and its NSE output verbatim.

The scan-trust panel sits between (1) and (2) rather than at the end, for the
same reason the markdown report leads with it: a clean-looking host grid is
misleading until you know how little of the target was looked at.

Everything is in one file -- no CDN, no fonts, no network. Scan reports get
read on jump boxes and air-gapped laptops, and a report that needs the internet
to render is a report that doesn't render.

Escaping
--------
Service banners, hostnames and NSE script output are *target-controlled*
strings. A host can put `<script>` in its own HTTP server header, and anyone
writing an HTML reporter is one missing escape away from having their report
run the target's code. So every interpolation goes through `esc()`, and the
only HTML in this file is HTML written here.

JavaScript does navigation and filtering only: with JS off, every section is
still present and readable (the detail panes render open, the grid still shows
each host's state) because `hidden` is applied by script, not by CSS.
"""

import html as _html
import re
from collections import Counter

from .profile import detect_roles
from .report import _followups, counts

BADGE = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_CODE_RE = re.compile(r"`([^`]+)`")


def esc(value):
    return _html.escape(str(value if value is not None else ""), quote=True)


def rich(value):
    """Escape, then turn the rules' markdown-style `backticks` into <code>.

    The rule text is written once and rendered into markdown, plain text and
    this page. Backticks are the lowest common denominator: markdown renders
    them, the terminal leaves them alone, and here they become real code spans.
    Escaping happens FIRST, so the only tags in the output are the ones added
    on the line below.
    """
    out = esc(value)
    return _CODE_RE.sub(r"<code>\1</code>", out)


def html_report(scan, findings):
    c = counts(findings)
    up = scan.up_hosts()
    scan_wide, by_host = _assign(scan, findings)

    hosts = sorted(
        up,
        key=lambda h: (RANK.get(_worst(by_host.get(h.label, [])), 9),
                       -len(h.open_ports()), h.address),
    )

    parts = [_HEAD, _header(scan, c), _summary(scan, findings, by_host),
             _trust(scan_wide), _grid(hosts, by_host)]
    parts += [_detail(h, by_host.get(h.label, [])) for h in hosts]
    parts += [_down(scan), _followup_block(scan, findings), _footer(), _SCRIPT]
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Finding -> host attribution
# --------------------------------------------------------------------------

def _assign(scan, findings):
    """Split findings into scan-wide and per-host.

    `Finding.target` is either empty (a statement about the whole run), a host
    label, or "<host label> <port>". Matching on the label prefix keeps the
    attribution in one place instead of threading host identity through every
    rule.
    """
    labels = {h.label: h for h in scan.hosts}
    scan_wide, by_host = [], {label: [] for label in labels}
    for f in findings:
        for label in labels:
            if f.target == label or f.target.startswith(label + " "):
                by_host[label].append(f)
                break
        else:
            scan_wide.append(f)
    return scan_wide, by_host


def _worst(items):
    return min((f.priority for f in items), key=lambda p: RANK[p], default=None)


def _port_of(finding):
    """The port a finding points at, or None for a whole-host finding."""
    tail = finding.target.rsplit(" ", 1)[-1]
    return tail if "/" in tail else None


# --------------------------------------------------------------------------
# Blocks
# --------------------------------------------------------------------------

def _header(scan, c):
    meta = []
    if scan.args:
        meta.append(("Command", f"<code>{esc(scan.args)}</code>"))
    if scan.version:
        meta.append(("nmap", esc(scan.version)))
    if scan.start:
        meta.append(("Started", esc(scan.start)))
    if scan.finished:
        fin = esc(scan.finished)
        if scan.exit_status == "truncated":
            fin += ' <span class="warn">incomplete output</span>'
        meta.append(("Finished", fin))
    meta.append(("Source", f"<code>{esc(scan.source)}</code>"))
    if getattr(scan, "excluded", None):
        meta.append(("Excluded", "; ".join(
            f"{esc(h.label)} <span class=\"mute\">({esc(r)})</span>"
            for h, r in scan.excluded)))

    rows = "\n".join(
        f'<div class="metarow"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in meta)
    chips = "".join(
        f'<span class="chip p-{p}">{c[p]} {BADGE[p].lower()}</span>'
        for p in ("high", "medium", "low", "info") if c[p])
    return f"""
<header>
  <div class="hwrap">
    <div>
      <h1>nmap review</h1>
      <p class="sub">What answered a probe, and what still needs a human.</p>
    </div>
    <div class="chips">{chips or '<span class="chip p-info">no review items</span>'}</div>
  </div>
  <dl class="meta">{rows}</dl>
</header>"""


def _summary(scan, findings, by_host):
    up = scan.up_hosts()
    down = [h for h in scan.hosts if h.state != "up"]
    open_ports = [p for h in up for p in h.open_ports()]
    services = Counter(p.service for p in open_ports if p.service
                       and p.service not in {"unknown", "tcpwrapped"})
    unidentified = [p for p in open_ports
                    if not p.service or p.service in {"unknown", "tcpwrapped"}]
    guessed = [p for p in open_ports if p.service and not p.probed]
    flagged = sum(1 for h in up if _worst(by_host.get(h.label, [])) == "high")
    ambiguous = sum(len(h.ambiguous_ports()) for h in up)

    tiles = [
        ("Hosts scanned", len(scan.hosts), f"{len(up)} up · {len(down)} not responding"),
        ("Open ports", len(open_ports),
         f"across {len(up)} host{'s' if len(up) != 1 else ''}"),
        ("Distinct services", len(services),
         ", ".join(f"{n}×{esc(s)}" for s, n in services.most_common(3)) or "—"),
        ("Hosts needing attention", flagged,
         "carry a high-priority review item"),
        ("Ports to identify", len(unidentified) + len(guessed),
         f"{len(unidentified)} unidentified · {len(guessed)} guessed from port number"),
        ("Unresolved states", ambiguous, "open|filtered — silence, two causes"),
    ]
    cells = "".join(
        f'<div class="tile"><span class="tnum">{v}</span>'
        f'<span class="tlab">{k}</span><span class="tsub">{s}</span></div>'
        for k, v, s in tiles)
    return f"""
<section id="summary">
  <h2>Summary</h2>
  <div class="tiles">{cells}</div>
</section>"""


def _trust(scan_wide):
    if not scan_wide:
        body = ('<p class="ok">No scan-wide coverage caveats: the scan\'s breadth '
                'and identification method support the host results below.</p>')
    else:
        body = "".join(_finding_card(f, show_target=False) for f in scan_wide)
    return f"""
<section id="trust">
  <h2>How far to trust this scan</h2>
  <p class="lede">These limit what the rest of the report can be used to claim.
  A host with nothing interesting on it has not been cleared if the scan never
  looked.</p>
  {body}
</section>"""


def _grid(hosts, by_host, tags=None):
    if not hosts:
        return ('<section id="hosts"><h2>Hosts</h2>'
                '<p class="ok">No responsive hosts in this scan.</p></section>')
    tags = tags or {}
    cards = []
    for h in hosts:
        tag = tags.get(h.address, "")
        items = by_host.get(h.label, [])
        worst = _worst(items) or "none"
        c = Counter(f.priority for f in items)
        pills = "".join(f'<span class="pill p-{p}">{c[p]}</span>'
                        for p in ("high", "medium", "low", "info") if c[p]) \
            or '<span class="pill p-none">clear</span>'
        roles = detect_roles(h)
        role_html = "".join(
            f'<span class="role r-{r.confidence}">{esc(r.name)}</span>'
            for r in roles[:2])
        svc = ", ".join(sorted({p.service for p in h.open_ports() if p.service})) or "—"
        os_line = (f"{esc(h.os_matches[0][0])} ({h.os_matches[0][1]}%)"
                   if h.os_matches else "OS not determined")
        names = ", ".join(esc(n) for n, _ in h.hostnames)
        cards.append(f"""
    <button class="card w-{worst}" data-host="{esc(h.address)}"
            aria-controls="host-{esc(h.address)}">
      <div class="cardtop">
        <span class="addr">{esc(h.address)}{f' <span class="tag chg">{esc(tag)}</span>' if tag else ''}</span>
        <span class="pills">{pills}</span>
      </div>
      {f'<div class="roles">{role_html}</div>' if role_html else ''}
      {f'<div class="names">{names}</div>' if names else ''}
      <div class="cardstat">
        <span><b>{len(h.open_ports())}</b> open</span>
        <span><b>{h.count_extra('filtered') + sum(1 for p in h.ports if p.state == 'filtered')}</b> filtered</span>
        <span><b>{len(h.ambiguous_ports())}</b> unresolved</span>
      </div>
      <div class="os">{os_line}</div>
      <div class="svc" title="{esc(svc)}">{esc(svc)}</div>
      <span class="drill">View host →</span>
    </button>""")
    return f"""
<section id="hosts">
  <h2>Hosts</h2>
  <p class="lede">Accent colour is the host's highest review priority. Select a
  host to drill into its ports, findings and script output.</p>
  <div class="grid">{''.join(cards)}</div>
</section>"""


def _detail(host, items):
    port_findings = {}
    host_findings = []
    for f in items:
        p = _port_of(f)
        if p:
            port_findings.setdefault(p, []).append(f)
        else:
            host_findings.append(f)

    shown = sorted((p for p in host.ports if p.state != "closed"),
                   key=lambda p: (p.protocol, p.number))
    rows = []
    for p in shown:
        fs = port_findings.get(p.id, [])
        worst = _worst(fs)
        how = ('<span class="tag probed">probe</span>' if p.probed
               else ('<span class="tag guess">port table</span>' if p.service
                     else '<span class="tag none">not identified</span>'))
        # One pill per priority with a count, not one per finding: three
        # "Medium" pills in a row read as noise, and the number is the signal.
        grouped = Counter(f.priority for f in fs)
        tip = esc("; ".join(f.title for f in fs))
        flags = "".join(
            f'<span class="pill p-{p}" title="{tip}">{grouped[p]} {BADGE[p]}</span>'
            for p in ("high", "medium", "low", "info") if grouped[p]) or ""
        rows.append(f"""
      <tr class="{'has-f w-' + worst if worst else ''}">
        <td class="mono pcell">{esc(p.id)}</td>
        <td><span class="state s-{esc(p.state.replace('|', '-'))}">{esc(p.state)}</span></td>
        <td>{esc(p.service) or '—'}</td>
        <td class="mono ver">{esc(p.banner) or '—'}</td>
        <td>{how}</td>
        <td>{flags}</td>
      </tr>""")

    table = (f"""
    <table class="ports">
      <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th>
      <th>Identified by</th><th>Review</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>""" if rows else
        '<p class="ok">No open or ambiguous ports in the scanned range.</p>')

    extra = ", ".join(f"{cnt} {esc(st)}" for st, cnt, _ in host.extraports if cnt)
    meta = []
    roles = detect_roles(host)
    if host.hostnames:
        meta.append("Names: " + ", ".join(esc(n) for n, t in host.hostnames))
    if host.os_matches:
        meta.append("OS: " + "; ".join(f"{esc(n)} ({a}%)" for n, a in host.os_matches[:3]))
    if host.distance is not None:
        meta.append(f"{host.distance} hop(s) from the scanner")
    if extra:
        meta.append("Not shown: " + extra)
    for addr, kind in host.addresses:
        if kind == "mac":
            meta.append(f"MAC: {esc(addr)}")

    findings_html = ("".join(_finding_card(f) for f in items)
                     if items else '<p class="ok">Nothing flagged for review on this host.</p>')

    scripts = []
    for s in host.scripts:
        scripts.append(_script_block("host", s))
    for p in shown:
        for s in p.scripts:
            scripts.append(_script_block(p.id, s))
    scripts_html = ("".join(scripts) if scripts else
                    '<p class="ok">No NSE script output for this host.</p>')

    return f"""
<section class="detail" id="host-{esc(host.address)}" data-detail="{esc(host.address)}">
  <div class="dhead">
    <button class="back" data-back>← All hosts</button>
    <h2>{esc(host.address)}</h2>
  </div>
  {f'<p class="dmeta">{" · ".join(meta)}</p>' if meta else ''}
  {_roles_block(roles)}
  <h3>Ports</h3>
  {table}
  <h3>Review items ({len(items)})</h3>
  {findings_html}
  <h3>Script output</h3>
  {scripts_html}
</section>"""


def _roles_block(roles):
    """What the host appears to be, with the signals that say so.

    The signals are printed, not just the conclusion: role inference is
    guesswork in a confident voice, and the reader has to be able to overrule
    it without re-reading the port table.
    """
    if not roles:
        return ""
    cards = "".join(f"""
    <li><span class="role r-{r.confidence}">{esc(r.confidence)}</span>
      <b>{esc(r.name)}</b>
      <span class="sig">{esc(" · ".join(r.signals))}</span></li>"""
                    for r in roles)
    return f"""
  <h3>Appears to be</h3>
  <ul class="rolelist">{cards}</ul>"""


def _script_block(where, script):
    return f"""
  <details class="nse">
    <summary><span class="mono">{esc(where)}</span> · {esc(script.id)}</summary>
    <pre>{esc(script.output)}</pre>
  </details>"""


def _finding_card(f, show_target=True):
    target = (f'<span class="ftarget mono">{esc(f.target)}</span>'
              if show_target and f.target else "")
    return f"""
  <article class="finding p-{f.priority}" data-priority="{f.priority}">
    <div class="fhead">
      <span class="badge p-{f.priority}">{BADGE[f.priority]}</span>
      <h4>{esc(f.title)}</h4>
      {target}
      <span class="frule mono">{esc(f.rule)}</span>
    </div>
    <p>{rich(f.detail)}</p>
    <p class="next"><b>Next step:</b> {rich(f.next_step)}</p>
  </article>"""


def _down(scan):
    down = [h for h in scan.hosts if h.state != "up"]
    if not down:
        return ""
    items = ", ".join(esc(h.address) for h in down)
    return f"""
<section id="down">
  <h2>Not responding ({len(down)})</h2>
  <p class="lede">A host reported down is frequently a statement about the path,
  not the host: discovery is blocked by anything that drops ICMP and probes to
  closed ports. Re-run with <code>-Pn</code> to scan regardless.</p>
  <p class="mono">{items}</p>
</section>"""


def _followup_block(scan, findings):
    steps = _followups(scan, findings)
    if not steps:
        return ""
    lines = "\n".join(esc(s) for s in steps)
    return f"""
<section id="followup">
  <h2>Suggested follow-up scans</h2>
  <p class="lede">Derived from the gaps this scan actually left, not a generic
  checklist.</p>
  <pre class="cmds">{lines}</pre>
</section>"""


def _footer():
    return """
<footer>
  <p><b>What this report is.</b> nmap establishes that something answered a
  probe. It does not establish exploitability, and a service banner is not a
  patch level — distributions backport fixes without changing it, and some
  services misreport deliberately. Every item here is something to
  <i>check</i>; none of them is a confirmed vulnerability. Priority is review
  urgency, not severity.</p>
  <p>Generated by <code>nmap-review</code>. Scan only systems you are
  authorised to test.</p>
</footer>"""


# --------------------------------------------------------------------------
# Static head/script. Kept as literals so the output is one portable file.
# --------------------------------------------------------------------------

_HEAD = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nmap review</title>
<style>
:root{
  --bg:#f6f6f4; --panel:#fff; --ink:#1b1d1e; --mute:#5f6568; --line:#e2e2de;
  --high:#b32025; --medium:#9a5b06; --low:#2f6080; --info:#6b7173; --none:#2f7a52;
  --high-bg:#fdf0ef; --medium-bg:#fdf5e8; --low-bg:#eff5f9; --info-bg:#f2f3f3;
  --code:#f1f1ee;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#141617; --panel:#1c1f20; --ink:#e9e9e6; --mute:#9aa1a3; --line:#2c3031;
  --high:#ff7b74; --medium:#e9ab52; --low:#86b6d6; --info:#9aa1a3; --none:#74c295;
  --high-bg:#2a1b1b; --medium-bg:#262017; --low-bg:#1a2228; --info-bg:#212425;
  --code:#121415;
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header,section,footer{max-width:1100px;margin:0 auto;padding:0 24px}
header{padding-top:36px}
h1{font-size:26px;margin:0;letter-spacing:-.2px}
.sub{margin:4px 0 0;color:var(--mute)}
.hwrap{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.chips{display:flex;gap:6px;flex-wrap:wrap}
.chip{font-size:12px;padding:4px 10px;border-radius:999px;border:1px solid var(--line)}
.chip.p-high{color:var(--high);background:var(--high-bg);border-color:var(--high)}
.chip.p-medium{color:var(--medium);background:var(--medium-bg);border-color:var(--medium)}
.chip.p-low{color:var(--low);background:var(--low-bg)}
.chip.p-info{color:var(--info);background:var(--info-bg)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));
  gap:2px 24px;margin:20px 0 8px;padding:16px;background:var(--panel);
  border:1px solid var(--line);border-radius:10px}
.metarow{display:flex;gap:10px;font-size:13px;min-width:0}
.metarow dt{color:var(--mute);min-width:74px}
.metarow dd{margin:0;min-width:0;overflow-wrap:anywhere}
h2{font-size:19px;margin:34px 0 6px;letter-spacing:-.1px}
h3{font-size:15px;margin:26px 0 8px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--mute)}
.lede{margin:0 0 16px;color:var(--mute);max-width:70ch}
.ok{color:var(--mute);margin:0 0 12px}
.warn{color:var(--high);font-weight:600}
.mute{color:var(--mute)}
code{background:var(--code);padding:1px 5px;border-radius:4px;font-size:.92em}
/* summary tiles */
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:10px;margin:8px 0 4px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;display:flex;flex-direction:column;gap:2px}
.tnum{font-size:28px;font-weight:650;line-height:1.1;letter-spacing:-.5px}
.tlab{font-size:13px;font-weight:600}
.tsub{font-size:11.5px;color:var(--mute)}
/* host grid */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.card{all:unset;cursor:pointer;display:flex;flex-direction:column;gap:7px;
  background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--info);
  border-radius:10px;padding:14px 16px;transition:transform .08s,box-shadow .12s}
.card:hover,.card:focus-visible{transform:translateY(-1px);
  box-shadow:0 2px 10px rgba(0,0,0,.09);outline:none;border-color:var(--mute)}
.card.w-high{border-left-color:var(--high)}
.card.w-medium{border-left-color:var(--medium)}
.card.w-low{border-left-color:var(--low)}
.card.w-none{border-left-color:var(--none)}
.cardtop{display:flex;justify-content:space-between;align-items:center;gap:8px}
.addr{font-family:ui-monospace,Menlo,monospace;font-size:15px;font-weight:650}
.names,.os{font-size:12px;color:var(--mute);overflow-wrap:anywhere}
.cardstat{display:flex;gap:14px;font-size:12.5px;color:var(--mute)}
.cardstat b{color:var(--ink);font-size:14px}
.svc{font-size:12px;color:var(--mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.drill{font-size:12px;font-weight:600;color:var(--low)}
.pills{display:flex;gap:4px}
.roles{display:flex;gap:5px;flex-wrap:wrap}
.role{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:5px;
  background:var(--info-bg);color:var(--info);white-space:nowrap}
.role.r-strong{background:var(--high-bg);color:var(--high)}
.role.r-likely{background:var(--medium-bg);color:var(--medium)}
.role.r-possible{background:var(--low-bg);color:var(--low)}
.rolelist{list-style:none;padding:0;margin:0 0 4px}
.rolelist li{background:var(--panel);border:1px solid var(--line);border-radius:9px;
  padding:9px 13px;margin:0 0 7px;font-size:13.5px;display:flex;gap:9px;
  align-items:baseline;flex-wrap:wrap}
.rolelist .sig{color:var(--mute);font-size:12px;flex:1 1 100%}
.pill{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:999px;
  background:var(--info-bg);color:var(--info)}
.pill.p-high{background:var(--high-bg);color:var(--high)}
.pill.p-medium{background:var(--medium-bg);color:var(--medium)}
.pill.p-low{background:var(--low-bg);color:var(--low)}
.pill.p-none{background:transparent;color:var(--none);border:1px solid var(--none)}
/* detail */
.detail{padding-top:8px}
.dhead{display:flex;align-items:center;gap:14px;margin-top:30px}
.dhead h2{margin:0;font-family:ui-monospace,Menlo,monospace}
.back{all:unset;cursor:pointer;font-size:12.5px;font-weight:600;color:var(--low);
  border:1px solid var(--line);border-radius:7px;padding:5px 11px;background:var(--panel)}
.back:hover{border-color:var(--low)}
.dmeta{color:var(--mute);font-size:13px;margin:8px 0 0;overflow-wrap:anywhere}
table.ports{width:100%;border-collapse:collapse;font-size:13.5px;
  background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.ports th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;
  color:var(--mute);padding:9px 12px;border-bottom:1px solid var(--line);font-weight:600}
.ports td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
.ports td.ver{overflow-wrap:anywhere;min-width:11ch}
.ports tr:last-child td{border-bottom:none}
.ports tr.has-f{box-shadow:inset 3px 0 0 var(--info)}
.ports tr.w-high{box-shadow:inset 3px 0 0 var(--high)}
.ports tr.w-medium{box-shadow:inset 3px 0 0 var(--medium)}
.ports tr.w-low{box-shadow:inset 3px 0 0 var(--low)}
.pcell{white-space:nowrap}
.pill,.badge,.tag,.state{white-space:nowrap}
.ports td:last-child{display:flex;gap:4px;flex-wrap:wrap}
.state{font-size:12px;font-weight:600}
.s-open{color:var(--high)} .s-filtered{color:var(--mute)}
.s-open-filtered{color:var(--medium)}
.tag{font-size:10.5px;font-weight:700;padding:2px 7px;border-radius:5px;white-space:nowrap}
.tag.probed{background:var(--low-bg);color:var(--low)}
.tag.guess{background:var(--medium-bg);color:var(--medium)}
.tag.none{background:var(--high-bg);color:var(--high)}
.tag.chg{background:var(--medium-bg);color:var(--medium);margin-left:6px}
/* findings */
.finding{background:var(--panel);border:1px solid var(--line);
  border-left:4px solid var(--info);border-radius:10px;padding:13px 16px;margin:0 0 10px}
.finding.p-high{border-left-color:var(--high)}
.finding.p-medium{border-left-color:var(--medium)}
.finding.p-low{border-left-color:var(--low)}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fhead h4{margin:0;font-size:14.5px;font-weight:650}
.badge{font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;
  padding:3px 8px;border-radius:5px;background:var(--info-bg);color:var(--info)}
.badge.p-high{background:var(--high-bg);color:var(--high)}
.badge.p-medium{background:var(--medium-bg);color:var(--medium)}
.badge.p-low{background:var(--low-bg);color:var(--low)}
.ftarget,.frule{font-size:11.5px;color:var(--mute)}
.frule{margin-left:auto}
.finding p{margin:9px 0 0;font-size:13.5px;max-width:78ch}
.next{color:var(--mute)}
.next b{color:var(--ink)}
.delta{margin:8px 0 0;font-size:13px}
.delta .was{color:var(--mute);text-decoration:line-through}
.delta .now{color:var(--ink);font-weight:600}
.delta .arrow{color:var(--mute);padding:0 4px}
/* nse + commands */
.nse{background:var(--panel);border:1px solid var(--line);border-radius:9px;
  padding:9px 13px;margin:0 0 8px}
.nse summary{cursor:pointer;font-size:13px}
.nse pre,pre.cmds{background:var(--code);border-radius:7px;padding:11px 13px;
  overflow-x:auto;font-size:12.5px;margin:9px 0 2px;white-space:pre-wrap;
  overflow-wrap:anywhere}
pre.cmds{border:1px solid var(--line)}
footer{margin:46px auto 60px;padding-top:18px;border-top:1px solid var(--line);
  color:var(--mute);font-size:12.5px}
footer p{max-width:80ch}
@media print{
  .card,.back,.drill{display:none}
  .detail{display:block!important}
  .nse[open] pre{white-space:pre-wrap}
  body{background:#fff}
}
</style>
</head><body>"""

_SCRIPT = """
<script>
(function () {
  var details = Array.prototype.slice.call(document.querySelectorAll('[data-detail]'));
  var landing = ['summary', 'trust', 'hosts', 'down', 'followup'].map(function (id) {
    return document.getElementById(id);
  }).filter(Boolean);

  // Hiding is done here rather than in CSS so that with JavaScript disabled the
  // page is still a complete, readable report with every host expanded.
  function show(addr) {
    var found = false;
    details.forEach(function (d) {
      var match = d.getAttribute('data-detail') === addr;
      d.hidden = !match;
      found = found || match;
    });
    landing.forEach(function (s) { s.hidden = found; });
    if (found) { window.scrollTo(0, 0); }
  }

  document.querySelectorAll('.card').forEach(function (card) {
    card.addEventListener('click', function () {
      var addr = card.getAttribute('data-host');
      if (history.pushState) { history.pushState({ host: addr }, '', '#host-' + addr); }
      show(addr);
    });
  });

  document.querySelectorAll('[data-back]').forEach(function (b) {
    b.addEventListener('click', function () {
      if (history.pushState) { history.pushState({}, '', '#hosts'); }
      show(null);
    });
  });

  window.addEventListener('popstate', function () { fromHash(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { show(null); }
  });

  function fromHash() {
    var m = /^#host-(.+)$/.exec(window.location.hash);
    show(m ? decodeURIComponent(m[1]) : null);
  }
  fromHash();
})();
</script>
</body></html>"""


# --------------------------------------------------------------------------
# Diff page
#
# Same page furniture, different question. The changes come first and the full
# current-scan grid stays underneath, because the first thing anyone asks after
# "what changed" is "what does that host look like now" -- and making them open
# a second report to answer it is how the diff stops being used.
# --------------------------------------------------------------------------

_CHANGE_SECTIONS = [
    ("host-appeared", "New hosts"),
    ("port-opened", "Ports opened"),
    ("service-changed", "Services changed"),
    ("finding-new", "New review items"),
    ("version-changed", "Versions changed"),
    ("port-closed", "Ports closed or no longer open"),
    ("host-gone", "Hosts no longer responding"),
    ("finding-cleared", "Review items no longer reported"),
]


def html_diff(d, findings):
    """Render a Diff plus the current scan's hosts, as one self-contained page."""
    scan = d.new
    scan_wide, by_host = _assign(scan, findings)
    hosts = sorted(scan.up_hosts(),
                   key=lambda h: (RANK.get(_worst(by_host.get(h.label, [])), 9),
                                  -len(h.open_ports()), h.address))

    tags = {}
    for ch in d.changes:
        addr = ch.host.split(" ")[0]
        if ch.kind == "host-appeared":
            tags[addr] = "new"
        elif addr not in tags and ch.kind in ("port-opened", "service-changed"):
            tags[addr] = "changed"

    parts = [_HEAD, _diff_header(d), _diff_summary(d), _diff_sections(d),
             _grid(hosts, by_host, tags)]
    parts += [_detail(h, by_host.get(h.label, [])) for h in hosts]
    parts += [_down(scan), _footer(), _SCRIPT]
    return "\n".join(parts)


def _diff_header(d):
    rows = "\n".join(
        f'<div class="metarow"><dt>{k}</dt><dd>{v}</dd></div>' for k, v in [
            ("Baseline", f"<code>{esc(d.old.source)}</code>"),
            ("Current", f"<code>{esc(d.new.source)}</code>"),
            ("Baseline cmd", f"<code>{esc(d.old.args)}</code>" if d.old.args else "—"),
            ("Current cmd", f"<code>{esc(d.new.args)}</code>" if d.new.args else "—"),
        ])
    c = d.counts()
    chips = "".join(f'<span class="chip p-{p}">{c[p]} {BADGE[p].lower()}</span>'
                    for p in ("high", "medium", "low", "info") if c[p]) \
        or '<span class="chip p-info">no changes</span>'
    return f"""
<header>
  <div class="hwrap">
    <div>
      <h1>nmap review — changes</h1>
      <p class="sub">What moved since the baseline scan.</p>
    </div>
    <div class="chips">{chips}</div>
  </div>
  <dl class="meta">{rows}</dl>
</header>"""


def _diff_summary(d):
    old_open = sum(len(h.open_ports()) for h in d.old.up_hosts())
    new_open = sum(len(h.open_ports()) for h in d.new.up_hosts())
    tiles = [
        ("Hosts up", f"{len(d.old.up_hosts())} → {len(d.new.up_hosts())}",
         f"{len(d.by_kind('host-appeared'))} new · {len(d.by_kind('host-gone'))} gone"),
        ("Open ports", f"{old_open} → {new_open}",
         f"{len(d.by_kind('port-opened'))} opened · {len(d.by_kind('port-closed'))} closed"),
        ("Services changed", len(d.by_kind("service-changed")),
         "a different service is answering"),
        ("Versions changed", len(d.by_kind("version-changed")), "usually patching"),
        ("New review items", len(d.new_findings), "not present in the baseline"),
        ("Cleared", len(d.cleared_findings), "verify the scan covered them"),
    ]
    cells = "".join(
        f'<div class="tile"><span class="tnum">{v}</span>'
        f'<span class="tlab">{k}</span><span class="tsub">{s}</span></div>'
        for k, v, s in tiles)
    return f"""
<section id="summary">
  <h2>Summary of changes</h2>
  <div class="tiles">{cells}</div>
</section>"""


def _diff_sections(d):
    if d.unchanged:
        return """
<section id="trust">
  <h2>No changes</h2>
  <p class="lede">Every host, port state, service identity and review item
  matches the baseline. Before reading that as stability, check both scans used
  the same flags — a narrower scan produces no changes either.</p>
</section>"""
    blocks = []
    for kind, label in _CHANGE_SECTIONS:
        items = d.by_kind(kind)
        if not items:
            continue
        cards = "".join(_change_card(ch) for ch in items)
        blocks.append(f'<h3>{label} ({len(items)})</h3>{cards}')
    return f"""
<section id="trust">
  <h2>Changes</h2>
  <p class="lede">New exposure first. A cleared item is not proof of a fix — a
  narrower scan clears findings just as effectively as a remediation does.</p>
  {"".join(blocks)}
</section>"""


def _change_card(ch):
    delta = ""
    if ch.before or ch.after:
        delta = (f'<p class="delta"><span class="mono was">{esc(ch.before) or "—"}</span>'
                 f' <span class="arrow">→</span> '
                 f'<span class="mono now">{esc(ch.after) or "—"}</span></p>')
    where = esc(ch.host) + (f" · {esc(ch.port)}" if ch.port else "")
    return f"""
  <article class="finding p-{ch.priority}">
    <div class="fhead">
      <span class="badge p-{ch.priority}">{BADGE[ch.priority]}</span>
      <h4>{esc(ch.title)}</h4>
      <span class="frule mono">{esc(ch.kind)}</span>
    </div>
    <p class="ftarget mono">{where}</p>
    {delta}
    <p>{rich(ch.detail)}</p>
  </article>"""
