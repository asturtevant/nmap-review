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

# several files -- a TCP sweep, a UDP pass, an overnight -p- -- as one report
# (format is inferred from the -o extension; -f overrides)
./nmap-review report tcp.xml udp.xml full.xml -o report.html

# what changed since the baseline
./nmap-review diff baseline.xml latest.xml -f html -o changes.html

# review XML you already have
./nmap-review report scan.xml

# run the scan and review it in one step (everything after -- goes to nmap)
./nmap-review scan -- -sV -sC -p- 10.0.0.5

# markdown, terminal text, or JSON
./nmap-review report scan.xml -f md -o report.md
./nmap-review report scan.xml -f text
./nmap-review report scan.xml -f json | jq '.findings[] | select(.priority=="high")'
```

Example output, generated from [`tests/fixtures/sample.xml`](tests/fixtures/sample.xml):
[**HTML report**](docs/sample-report.html) (open it in a browser) ·
[**markdown report**](docs/sample-report.md) ·
[**HTML diff**](docs/sample-diff.html) ·
[**markdown diff**](docs/sample-diff.md) against
[`baseline.xml`](tests/fixtures/baseline.xml).

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

## Several scans, one report

An engagement does not produce one XML. It produces a quick TCP sweep, a UDP
pass, an overnight `-p-`, often one file per subnet. Pass them all to `report`
and they are merged by host before the rules run:

```bash
./nmap-review report tcp.xml udp.xml overnight.xml -f html -o report.html
```

This is not just convenience. Reviewed separately, the TCP report says *"no UDP
scan"* while the UDP results sit in the next file — the caveat is wrong about
the work that was actually done. Merging makes the coverage rules describe the
scan **set**.

Conflicts resolve toward evidence: a `-sV` run that identified `6379/tcp redis
5.0.7` beats a fast sweep that called the same port `open, no service`, because
the second one never asked. State wins first (`open` > `open|filtered` >
`filtered` > `closed`), then probed-over-guessed, then having a banner. NSE
output is unioned rather than replaced — two scans with different `--script`
sets each hold evidence the other lacks. Overlapping `extraports` counts take
the largest single-scan figure instead of summing, so two scans of the same
1,000 ports don't report 2,000 filtered.

One honest caveat, stated in the report header: merged coverage is the union.
A set containing one `-p-` scan won't warn about default port ranges even if
that `-p-` only covered one host of twelve. Where that distinction matters,
review the scans separately.

## Dropping hosts from a report

Scans pick up things the report should not carry: the scanning box itself, a
neighbour inside the same /24, a host the client has put out of scope.

```bash
./nmap-review report scan.xml --exclude-host 10.0.0.5
./nmap-review report scan.xml --exclude-host '*.corp.internal' -o report.html
./nmap-review report scan.xml --only-host 192.168.56.0/24 --exclude-host 192.168.56.1
```

A pattern is an exact address, a CIDR block, or a shell glob tried against the
address and every hostname. Both flags repeat, and both take comma-separated
lists the way nmap's own `--exclude` does:

```bash
./nmap-review report scan.xml --exclude-host 10.0.0.5,10.0.0.6,'*.corp.internal'
```
 `--only-host` is an allow-list
applied first, then `--exclude-host` removes from what is left — so the two
compose as "this subnet, except that box". A pattern that matches nothing warns
on stderr, because a typo in an exclude pattern means the host you meant to
drop is still in the report.

**Excluded hosts are never silently deleted.** They move into a recorded list,
and every format names them and the pattern that removed them in its header.
A host that is simply absent is indistinguishable from one that was never
scanned, and only one of those is a statement about the target — which is the
confusion the rest of this tool exists to prevent.

The filters apply to `scan` and to both sides of a `diff` too, so excluding a
decommissioned host stops it being reported as "no longer responding".

## What changed since last time

```bash
./nmap-review diff baseline.xml latest.xml -f html -o changes.html

# either side may be several files
./nmap-review diff old-tcp.xml old-udp.xml -- new-tcp.xml new-udp.xml
```

Nobody scans the same estate twice to read the same report twice. The diff
reports hosts appearing and disappearing, ports opening and closing, services
changing identity, versions moving, and review items arriving or clearing —
with the full current-scan host grid still underneath, because the next
question after *"what changed"* is always *"what does that host look like
now"*.

A service **name** change and a version change are reported separately and
ranked differently: a version bump is usually patching, while a different
service answering on the same port usually means something else is listening.

Two cautions are built into the wording rather than left to the reader. A host
that "disappeared" may just not have answered this time. And a cleared finding
is **not** proof of a fix — a narrower scan clears findings exactly as
effectively as a remediation does, so the diff says so on every cleared item.

Finding identity is `(rule, target)`, deliberately not the prose: `COV-FILTERED`
going from "989 ports filtered" to "991 ports filtered" is the same standing
finding, and reporting it as new every week is how a diff becomes noise.

### This is the form that belongs in CI

`--fail-on high` against a single scan fires forever — an estate's standing
exposures don't disappear between Tuesday and Wednesday, so the check gets
muted within a fortnight. The diff gate considers only what is *new*:

```bash
nmap-review diff baseline.xml latest.xml -f json -o changes.json --fail-on high
```

That is a check a team can leave switched on for a year.

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

### Host roles

A port list is not a host. "445/tcp, 3389/tcp, 5985/tcp on Windows Server" is
complete and useless — the reader still has to work out that it's a domain
controller before any of it means anything, and everything changes once that's
said: SMB signing stops being hygiene and becomes a path to the directory.

So each host is profiled, and the role is shown on its card, in the inventory,
and (for the roles that change the reading) as a review item:

| Role | Finding | Why it changes the review |
|---|---|---|
| Active Directory domain controller | HIGH | holds the credentials for everything that trusts it |
| Virtualization host | HIGH | management plane ≈ physical access to every guest |
| Kubernetes control plane | HIGH | API server + etcd *is* the cluster |
| Container host | HIGH | an exposed Docker API is unauthenticated host root |
| Mail server | MEDIUM | relay, spoofing and credential harvesting are decided here |
| Database server | MEDIUM | the value is the data, so the question is who can reach the listener |
| Network device | MEDIUM | sees and shapes other hosts' traffic; vendor defaults are routine |
| Network printer | MEDIUM | queued documents, cached directory credentials, never patched |
| Web / file / DNS server | — | shown as context; too common to be a finding |

Three restraints, because role inference is guesswork in a confident voice:

- **The signals are printed, not just the conclusion.** "Kerberos + LDAP +
  global catalog + kpasswd" lets a reader overrule the label without
  re-reading the port table.
- **Confidence is scored and shown** (`strong` / `likely` / `possible`), and a
  `possible` role is reported at a lower priority than a confirmed one — but
  still reported, because a possible domain controller is worth ten minutes of
  confirmation.
- **A hostname is worth almost nothing.** A box called `dc01` that speaks
  neither Kerberos nor LDAP is a label somebody typed, not a domain
  controller, and naming alone can never exceed `possible`. The sample scan
  contains exactly that case: `win-dc01.lab.internal` is **not** claimed as a
  DC, because its DC ports were all filtered and the scan therefore has no
  evidence — only a name.

Port-number signals work without `-sV`: 88 + 389 + 3268 is a domain controller
whether or not anything asked the services their names.

### Surface rules (about the target)

| Rule | Fires when |
|---|---|
| `SRF-HOST-ROLE` | the host looks like a domain controller, hypervisor, control plane, container host, mail server, database server, network device or printer (see above) |
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
the gate considers. For `diff`, `--fail-on` applies to changes only, never to
findings that were already true at the baseline.

## Development

```bash
make test     # 146 tests, offline, no nmap required
make check    # tests, then confirm the committed samples match the current rules
make sample   # regenerate the committed samples (report + diff, md + HTML)
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
