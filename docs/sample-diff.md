# nmap review — changes

- **Baseline:** `tests/fixtures/baseline.xml`
- **Current:** `tests/fixtures/sample.xml`
- **Hosts:** 3 up → 2 up
- **Open ports:** 6 → 9
- **Changes:** 24 (11 high · 6 medium · 2 low · 5 info)

## Ports opened (4)

#### HIGH — Port opened: 2375/tcp (unknown)

`192.168.56.10 (build01.lab.internal)` · `2375/tcp`

`—` → `open`

2375/tcp is open; it was not seen in the previous scan.

#### HIGH — Port opened: 3306/tcp (mysql)

`192.168.56.10 (build01.lab.internal)` · `3306/tcp`

`filtered` → `open`

3306/tcp is open; it was filtered.

#### HIGH — Port opened: 6379/tcp (redis)

`192.168.56.10 (build01.lab.internal)` · `6379/tcp`

`—` → `open`

6379/tcp is open running Redis key-value store 5.0.7; it was not seen in the previous scan.

#### HIGH — Port opened: 8081/tcp (http)

`192.168.56.10 (build01.lab.internal)` · `8081/tcp`

`—` → `open`

8081/tcp is open running nginx 1.14.2; it was not seen in the previous scan.

## Services changed (1)

#### HIGH — Service changed on 9999/tcp: http → tcpwrapped

`192.168.56.10 (build01.lab.internal)` · `9999/tcp`

`http` → `tcpwrapped`

A different service is answering on this port than last time. That is rarely a patch; something else is listening.

## Versions changed (1)

#### LOW — Version changed on 22/tcp

`192.168.56.10 (build01.lab.internal)` · `22/tcp`

`OpenSSH 7.2 protocol 2.0` → `OpenSSH 7.4 protocol 2.0`

OpenSSH 7.2 protocol 2.0 → OpenSSH 7.4 protocol 2.0. Usually patching; worth confirming it moved in the direction you expect.

## New review items (13)

#### HIGH — New review item: `smb2-security-mode` output needs review (host)

`192.168.56.10 (build01.lab.internal)`

SMB signing is not enforced; relay attacks are in scope. Matched: `3.1.1: Message signing enabled but not required`

#### HIGH — New review item: Port 2375/tcp is reachable

`192.168.56.10 (build01.lab.internal)` · `2375/tcp`

Docker API (plain HTTP) exposed; unauthenticated access is root on the host. Nothing probed this port, so the service is unconfirmed.

#### HIGH — New review item: Unidentified service on 2375/tcp

`192.168.56.10 (build01.lab.internal)` · `2375/tcp`

A port is open and nmap could not name the service.

#### HIGH — New review item: Key-value store exposed on 6379/tcp

`192.168.56.10 (build01.lab.internal)` · `6379/tcp`

`redis` -- Redis key-value store 5.0.7. Key-value store exposed; default config has no auth.

#### HIGH — New review item: Unidentified service on 9999/tcp

`192.168.56.10 (build01.lab.internal)` · `9999/tcp`

nmap saw a `tcpwrapped` response: the TCP handshake completed and the service then closed the connection without speaking, so what is behind it is unknown.

#### HIGH — New review item: `smb-vuln-ms17-010` output needs review (445/tcp)

`192.168.56.11 (win-dc01.lab.internal)` · `445/tcp`

An NSE script asserted a vulnerable state. Matched: `VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) State: V...`

#### MEDIUM — New review item: 1 service name(s) are port-table guesses

`192.168.56.10 (build01.lab.internal)`

These ports are labelled from nmap-services, not from a probe: 3306/tcp -> mysql. Treat the name as a hypothesis.

#### MEDIUM — New review item: Database exposed to the scanning position on 3306/tcp

`192.168.56.10 (build01.lab.internal)` · `3306/tcp`

`mysql` (service name inferred from the port number, not probed). Database exposed to the scanning position.

#### MEDIUM — New review item: `http-methods` output needs review (80/tcp)

`192.168.56.10 (build01.lab.internal)` · `80/tcp`

Risky HTTP method or WebDAV enabled. Matched: `...T HEAD POST OPTIONS TRACE Potentially risky methods: TRACE`

#### MEDIUM — New review item: Cleartext HTTP on 8081/tcp

`192.168.56.10 (build01.lab.internal)` · `8081/tcp`

No TLS was detected on this listener. Anything authenticated over it is recoverable on-path.

#### MEDIUM — New review item: nginx older than 1.20 on 8081/tcp

`192.168.56.10 (build01.lab.internal)` · `8081/tcp`

Banner: `nginx 1.14.2`. A banner is not a patch level -- distributions backport fixes without changing it, and some services lie deliberately -- so this is a version to *check*, not a vulnerability.

#### LOW — New review item: HTTP on a non-standard port (8081/tcp)

`192.168.56.10 (build01.lab.internal)` · `8081/tcp`

Web services on unexpected ports are usually admin interfaces, dev builds or appliances -- the things least likely to be in an asset inventory.

#### INFO — New review item: Host answers to several names

`192.168.56.10 (build01.lab.internal)`

build01.lab.internal, jenkins.lab.internal. Virtual hosting means the services reached by name may differ from what the IP serves -- scanning the IP can miss a vhost entirely.

## Hosts no longer responding (1)

#### MEDIUM — Host no longer responding: 192.168.56.13 (old-jump.lab.internal)

`192.168.56.13 (old-jump.lab.internal)`

It answered in the previous scan and did not this time. Decommissioned, powered off, moved, or simply not reached -- silence does not distinguish between them.

## Review items no longer reported (4)

#### INFO — No longer reported: Cleartext HTTP on 9999/tcp

`192.168.56.10 (build01.lab.internal)` · `9999/tcp`

This item does not appear in the new scan. Confirm it was fixed rather than merely not looked at -- a narrower scan clears findings just as effectively as a remediation does.

#### INFO — No longer reported: nginx older than 1.20 on 9999/tcp

`192.168.56.10 (build01.lab.internal)` · `9999/tcp`

This item does not appear in the new scan. Confirm it was fixed rather than merely not looked at -- a narrower scan clears findings just as effectively as a remediation does.

#### INFO — No longer reported: HTTP on a non-standard port (9999/tcp)

`192.168.56.10 (build01.lab.internal)` · `9999/tcp`

This item does not appear in the new scan. Confirm it was fixed rather than merely not looked at -- a narrower scan clears findings just as effectively as a remediation does.

#### INFO — No longer reported: Remote administration reachable from this position on 22/tcp

`192.168.56.13 (old-jump.lab.internal)` · `22/tcp`

This item does not appear in the new scan. Confirm it was fixed rather than merely not looked at -- a narrower scan clears findings just as effectively as a remediation does.

---

*A cleared finding is not proof of a fix: a narrower scan clears findings too. Compare the two commands above before claiming remediation.*
