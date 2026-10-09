# nmap-review

A reporting wrapper around nmap that answers the question nmap doesn't: **what in
this scan still needs a human?**

nmap tells you what answered a probe. It does not tell you that the scan only
covered 1,000 of 65,535 ports, that half the service names are port-number
guesses rather than fingerprints, or that the one open port it couldn't identify
is the most interesting line in the output. Those are the things that get lost
between running a scan and writing it up — so this tool puts them first, above
the port tables, and names the follow-up check for each one.

```bash
# an HTML report: summary, host grid, click-through per host
./nmap-review report scan.xml -f html -o report.html

# review XML you already have
./nmap-review report scan.xml

# run the scan and review it in one step (everything after -- goes to nmap)
./nmap-review scan -- -sV -sC -p- 10.0.0.5

# markdown, terminal text, or JSON
./nmap-review report scan.xml -f md -o report.md
./nmap-review report scan.xml -f text
./nmap-review report scan.xml -f json | jq '.findings[] | select(.priority=="high")'
```

Example output, both generated from [`tests/fixtures/sample.xml`](tests/fixtures/sample.xml):
[**HTML report**](docs/sample-report.html) (open it in a browser) ·
[**markdown report**](docs/sample-report.md).

> ⚠️ Scan only systems you own or have written authorisation to test. This tool
> adds no probes of its own, but it does make it easier to run nmap — port
> scanning a network you don't have permission to scan is unlawful in most
> jurisdictions.

---

## The HTML report

`-f html` writes one self-contained file — no CDN, no fonts, no network, so it
renders on a jump box or an air-gapped laptop and survives being emailed around.

**Summary band.** Hosts scanned / up / not responding, total open ports,
distinct services, how many hosts carry a high-priority item, how many ports
still need identifying, how many states nmap could not resolve.

**Host grid.** One card per host, accent-coloured by its highest review
priority, with its open/filtered/unresolved counts, OS guess and service list.
The hosts that need attention are visible without reading anything.

**Drill-down.** Click a host for its own page: a port table with a column for
*how* each service was identified, each row marked with the review items
attached to it, then those findings in full, then the NSE output verbatim.
`Esc` or "← All hosts" goes back, and each host has its own URL fragment
(`#host-10.0.0.5`) so a specific host can be linked to directly.

Two details worth knowing: with JavaScript disabled the page is still a
complete report with every host expanded (hiding is applied by script, not by
CSS), and it prints sensibly — the cards drop out and every host detail
expands. Light and dark both supported.

## What it reports

Every report has the same four sections, in this order, and the order is the
argument:

**1. How far to trust this scan.** What the scan did not look at, and where its
answers are guesses. This comes first because it bounds what everything below it
is worth. A host with no interesting ports, scanned on nmap's default 1,000 TCP
ports with no `-sV`, has not been assessed — but a report that leads with a tidy
port table will be read as though it has.

**2. Review queue.** The target-side items, ranked by review urgency: a summary
table, then one entry each with what was observed, why it needs a decision, and
the specific next check.

**3. Inventory.** Per host, every non-closed port — with an explicit column for
**how** the service was identified (`probe` vs `port table`), so a guess is never
printed the way a fingerprint is. NSE output is kept verbatim in a collapsible
block, because the summary is not the evidence.

**4. Suggested follow-up scans.** Three or four whole commands derived from the
gaps actually found, not a generic checklist.

### Coverage rules (about the scan)

| Rule | Fires when | Why it matters |
|---|---|---|
| `COV-TRUNCATED` | the XML has no closing tag | the scan was interrupted; absent hosts are not clean hosts |
| `COV-PORTS-DEFAULT` | no `-p` given | 64,535 TCP ports were never probed |
| `COV-PORTS-FAST` | `-F` | 100 ports is triage, not inventory |
| `COV-NO-SV` | no `-sV`/`-A` | every service name is a port-table lookup |
| `COV-NO-UDP` | no UDP scan type | DNS, SNMP, NTP, TFTP, IKE cannot appear |
| `COV-NO-SCRIPTS` | no `-sC`/`--script` | the anonymous-login/cert/SMB evidence doesn't exist |
| `COV-TIMING` | `-T4`/`-T5` | short timeouts manufacture false "closed" |
| `COV-CONNECT-SCAN` | `-sT` | unprivileged: noisy, slower, no OS detection |
| `COV-ALL-DOWN` | every host down | usually a statement about the path, not the hosts |
| `COV-PN-NO-HOSTS` | `-Pn` and nothing responded | can't distinguish "empty range" from "never reached it" |
| `COV-FILTERED` | >90% filtered on a host | you measured a firewall |
| `COV-AMBIGUOUS` | `open|filtered` states | silence has two causes |
| `COV-GUESSED-SERVICES` | `method="table"` on open ports | the service name is a hypothesis |
| `COV-LOW-CONFIDENCE` | nmap's `conf` ≤ 5 | nmap probed and was unsure |
| `COV-OS-UNCERTAIN` | best OS match < 90% | don't quote the OS line as fact |

### Surface rules (about the target)

| Rule | Fires when |
|---|---|
| `SRF-UNIDENTIFIED` | an open port has no service name, or `tcpwrapped` — something is listening and nobody knows what |
| `SRF-SENSITIVE-SERVICE` | datastores, orchestration control planes, cleartext protocols, remote admin, file sharing — matched on the **service name**, so Redis on port 7777 is still caught |
| `SRF-SENSITIVE-PORT` | a known-sensitive port number (2375, 6443, 10250, 9200 …) even when nmap couldn't name the service |
| `SRF-SCRIPT-SIGNAL` | NSE output contains `VULNERABLE`, a CVE id, anonymous login, SSLv2/v3, expired/self-signed certs, unenforced SMB signing, open relay, default credentials, risky HTTP methods |
| `SRF-VERSION-AGE` | a banner shows an old major branch of OpenSSH, Apache, nginx, PHP, IIS, OpenSSL, MySQL, Samba, Exim, vsftpd, ProFTPD |
| `SRF-CLEARTEXT-HTTP` | HTTP with no TLS detected on the listener |
| `SRF-HTTP-ODD-PORT` | HTTP somewhere other than 80/443/8080/8443 — usually an admin UI or a dev build |
| `SRF-BROAD-SURFACE` | ≥15 open ports on one host |
| `SRF-MULTI-NAME` | the host answers to several names — scanning the IP can miss a vhost entirely |

## Design decisions worth knowing about

**It never claims a vulnerability.** nmap establishes that something answered a
probe. It does not establish exploitability, and a banner is not a patch level —
distributions backport fixes without changing it, and some services lie on
purpose. So `SRF-VERSION-AGE` says "compare this build against the vendor's
advisories", and script findings say "verify the claim directly; NSE produces
false positives and stale CVE mappings". A report that prints `VULNERABLE` from a
version string teaches its reader to ignore it, which is worse than printing
nothing.

**Priority is review urgency, not severity.** `HIGH` means *look at this first*.

**It parses XML, not `-oN` output.** The normal output is formatted for a human
and drops exactly the fields this tool depends on: `method`/`conf` (probed vs
guessed), the `extraports` summary (how much of the scan came back as silence),
and the per-port `reason`. The whole review pass rests on distinguishing "nmap
found X" from "nmap assumed X", and only the XML carries that.

**It passes your nmap arguments through untouched.** The wrapper appends `-oX`
and nothing else. Silently adding `-sV` or `-A` would send probes the operator
didn't authorise, and would also erase the coverage caveat that says the scan was
narrow — making the report describe a scan that never happened.

**Truncated XML is still parsed.** A long scan killed halfway through leaves an
unclosed document; that partial data is worth reviewing, so it is repaired, read,
and flagged `COV-TRUNCATED` at high priority. Silently ignoring the truncation
would turn "we never got there" into "nothing was found".

**The HTML report escapes everything from the target.** Service banners,
hostnames and NSE output are strings the scanned host chose. A host can put
`<script>` in its own HTTP server header, and a reporter that interpolates that
straight into a page runs the target's code on the analyst's machine. Every
interpolation goes through one escape helper, and a test feeds the renderer a
hostile banner and asserts the page still contains exactly one `<script>` — its
own.

**Stdlib only.** No dependencies, Python 3.8+, so it runs on whatever box the
scan ran on — which is usually not a box you want to `pip install` onto.

## CI use

Exit codes are meant for a pipeline: `0` clean, `1` review items at or above
`--fail-on`, `2` the tool itself failed. The distinction between 1 and 2 matters
— a parse failure must not be silently read as "no findings".

```bash
nmap-review report scan.xml -f json -o review.json --fail-on high
```

`--only coverage|surface` and `--min-priority` narrow what's reported and what
the gate considers.

## Development

```bash
make test     # 59 tests, offline, no nmap required
make check    # tests, then confirm the committed samples match the current rules
make sample   # regenerate the committed sample reports (markdown + HTML)
```

The test suite never runs nmap. The parser and the rules are exercised entirely
against committed XML, which also means the committed sample reports double as
golden files: change a rule's wording and `make check` shows it as a diff in the
report, not just as a test name.

Three of the tests exist to protect the tool's *altitude* rather than its logic —
`test_version_finding_does_not_assert_vulnerability`,
`test_unprobed_sensitive_service_is_downgraded` and
`test_target_controlled_text_is_escaped`. Those are the properties most
likely to erode as rules get added, and they are the reason anyone would trust
the output.

### Adding a rule

Rules live in [`nmap_review/rules.py`](nmap_review/rules.py) and return
`Finding` objects. A finding needs four things, and the fourth is the one people
skip: a stable `rule` id, a `priority`, a `detail` that says what was observed,
and a `next_step` naming the actual check. A finding without a next step is an
observation, and observations are what reports already have too many of.
