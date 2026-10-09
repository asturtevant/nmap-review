# nmap review

- **Source:** `tests/fixtures/sample.xml`
- **Command:** `nmap -sS -sV -sC -oX sample.xml 192.168.56.10 192.168.56.11`
- **nmap:** 7.94
- **Started:** Tue Oct  6 09:00:00 2026
- **Finished:** Tue Oct  6 09:03:30 2026
- **Hosts:** 3 up of 4 scanned — **19 open port(s)** total
- **Review items:** 11 high · 22 medium · 2 low · 1 info

> This report says what answered a probe and what a human still has to check. It does not establish that anything is vulnerable: a banner is not a patch level, and an open port is not a finding until someone decides it should not be open.

## 1. How far to trust this scan

Each item below limits what the rest of this report can be used to claim. Read them before the inventory.

#### **HIGH** — Only nmap's default 1,000 ports were scanned

rule `COV-PORTS-DEFAULT`

No explicit port selection was given (`nmap -sS -sV -sC -oX sample.xml 192.168.56.10 192.168.56.11`), so 64,535 of the 65,535 TCP ports were never probed. Services deliberately placed on high ports are the ones most likely to be interesting and the ones this scan cannot see.

**Next step:** Re-run with `-p-` against the hosts that matter, even if only overnight.

#### **MEDIUM** — 1 port(s) in an unresolved state

`192.168.56.11 (win-dc01.lab.internal)`  ·  rule `COV-AMBIGUOUS`

nmap could not distinguish open from filtered on 3389/tcp. This is the normal outcome of a UDP scan and of a filtered TCP path: no response arrived, and silence has two causes.

**Next step:** Probe these individually with `-sV --version-all`, or a protocol-specific client, before deciding.

#### **MEDIUM** — Almost everything came back filtered

`192.168.56.11 (win-dc01.lab.internal)`  ·  rule `COV-FILTERED`

989 ports returned no response on 192.168.56.11 (win-dc01.lab.internal). Something on the path is dropping probes, so this host's port list is a statement about the firewall, not about the host.

**Next step:** Re-scan from a position inside the filtering boundary, or confirm with the network owner which device is dropping.

#### **MEDIUM** — 1 service name(s) are port-table guesses

`192.168.56.10 (build01.lab.internal)`  ·  rule `COV-GUESSED-SERVICES`

These ports are labelled from nmap-services, not from a probe: 3306/tcp -> mysql. Treat the name as a hypothesis.

**Next step:** Confirm with `-sV` on exactly these ports.

#### **MEDIUM** — 1 service name(s) are port-table guesses

`192.168.56.14 (dc01.lab.internal)`  ·  rule `COV-GUESSED-SERVICES`

These ports are labelled from nmap-services, not from a probe: 464/tcp -> kpasswd5. Treat the name as a hypothesis.

**Next step:** Confirm with `-sV` on exactly these ports.

#### **MEDIUM** — No UDP scan

rule `COV-NO-UDP`

DNS, SNMP, NTP, TFTP, IKE, NetBIOS and most amplification-capable services are UDP. None of them can appear in a TCP-only result.

**Next step:** Run a targeted `-sU --top-ports 50` pass; a full UDP sweep is rarely worth the time.

#### **LOW** — OS fingerprint is uncertain (85%)

`192.168.56.11 (win-dc01.lab.internal)`  ·  rule `COV-OS-UNCERTAIN`

Best guesses: Microsoft Windows Server 2008 R2 (85%). Below ~90% accuracy the OS line should not be quoted as fact.

**Next step:** Corroborate from a service banner, TTL, or an authenticated source before relying on the platform.

## 2. Review queue

| # | Priority | Target | Item |
|---|---|---|---|
| 1 | HIGH | `192.168.56.10 (build01.lab.internal)` | Looks like a Container host (likely match) |
| 2 | HIGH | `192.168.56.14 (dc01.lab.internal)` | Looks like an Active Directory domain controller (strong match) |
| 3 | HIGH | `192.168.56.10 (build01.lab.internal)` | `smb2-security-mode` output needs review (host) |
| 4 | HIGH | `192.168.56.10 (build01.lab.internal) 21/tcp` | `ftp-anon` output needs review (21/tcp) |
| 5 | HIGH | `192.168.56.11 (win-dc01.lab.internal) 445/tcp` | `smb-vuln-ms17-010` output needs review (445/tcp) |
| 6 | HIGH | `192.168.56.10 (build01.lab.internal) 2375/tcp` | Port 2375/tcp is reachable |
| 7 | HIGH | `192.168.56.10 (build01.lab.internal) 21/tcp` | Cleartext file transfer on 21/tcp |
| 8 | HIGH | `192.168.56.10 (build01.lab.internal) 6379/tcp` | Key-value store exposed on 6379/tcp |
| 9 | HIGH | `192.168.56.10 (build01.lab.internal) 2375/tcp` | Unidentified service on 2375/tcp |
| 10 | HIGH | `192.168.56.10 (build01.lab.internal) 9999/tcp` | Unidentified service on 9999/tcp |
| 11 | MEDIUM | `192.168.56.10 (build01.lab.internal) 80/tcp` | Cleartext HTTP on 80/tcp |
| 12 | MEDIUM | `192.168.56.10 (build01.lab.internal) 8081/tcp` | Cleartext HTTP on 8081/tcp |
| 13 | MEDIUM | `192.168.56.10 (build01.lab.internal)` | Looks like a Database server (strong match) |
| 14 | MEDIUM | `192.168.56.10 (build01.lab.internal) 80/tcp` | `http-methods` output needs review (80/tcp) |
| 15 | MEDIUM | `192.168.56.10 (build01.lab.internal) 22/tcp` | Remote administration reachable from this position on 22/tcp |
| 16 | MEDIUM | `192.168.56.10 (build01.lab.internal) 3306/tcp` | Database exposed to the scanning position on 3306/tcp |
| 17 | MEDIUM | `192.168.56.11 (win-dc01.lab.internal) 445/tcp` | SMB reachable on 445/tcp |
| 18 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 135/tcp` | RPC endpoint mapper reachable on 135/tcp |
| 19 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 139/tcp` | Legacy NetBIOS session service reachable on 139/tcp |
| 20 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 3268/tcp` | Directory exposed without TLS on 3268/tcp |
| 21 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 3389/tcp` | RDP reachable on 3389/tcp |
| 22 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 389/tcp` | Directory exposed without TLS on 389/tcp |
| 23 | MEDIUM | `192.168.56.14 (dc01.lab.internal) 445/tcp` | SMB reachable on 445/tcp |
| 24 | MEDIUM | `192.168.56.10 (build01.lab.internal) 21/tcp` | vsftpd 2.3.4 -- the backdoored release on 21/tcp |
| 25 | MEDIUM | `192.168.56.10 (build01.lab.internal) 22/tcp` | OpenSSH older than 8.x on 22/tcp |
| 26 | MEDIUM | `192.168.56.10 (build01.lab.internal) 80/tcp` | Apache httpd older than 2.4 on 80/tcp |
| 27 | MEDIUM | `192.168.56.10 (build01.lab.internal) 8081/tcp` | nginx older than 1.20 on 8081/tcp |
| 28 | LOW | `192.168.56.10 (build01.lab.internal) 8081/tcp` | HTTP on a non-standard port (8081/tcp) |
| 29 | INFO | `192.168.56.10 (build01.lab.internal)` | Host answers to several names |

#### **1. HIGH** — Looks like a Container host (likely match)

`192.168.56.10 (build01.lab.internal)`  ·  rule `SRF-HOST-ROLE`

Matched on: Docker API over plain HTTP (2375). An exposed Docker API is root on the host, with no authentication step in the default configuration. This is inferred from the scan, not confirmed -- read the signals above and decide whether they describe this host.

**Next step:** Confirm whether the daemon requires client certificates; an unauthenticated answer on 2375 is immediate compromise.

#### **2. HIGH** — Looks like an Active Directory domain controller (strong match)

`192.168.56.14 (dc01.lab.internal)`  ·  rule `SRF-HOST-ROLE`

Matched on: LDAP banner names Active Directory; Kerberos (88) and LDAP (389) both open; Global catalog (3268/3269) open; Kerberos password change (464) open; a script reports a Windows domain; LDAPS (636) open; DNS (53) served by a Windows host; SMB (445) and RPC endpoint mapper (135) open; hostname suggests a domain controller (weak on its own). A domain controller holds the credentials for everything that trusts it, so every other item on this host is read differently: SMB signing is a relay path to the directory rather than a hygiene note, an exposed administration service is a route to Domain Admin, and an unpatched SMB stack is the whole estate. This is inferred from the scan, not confirmed -- read the signals above and decide whether they describe this host.

**Next step:** Confirm the domain and the DC role (`--script smb-os-discovery,ldap-rootdse`), then review this host against DC hardening specifically: SMB signing required, LDAP channel binding and signing, no anonymous bind, print spooler, and the patch level of the SMB and Netlogon stacks.

#### **3. HIGH** — `smb2-security-mode` output needs review (host)

`192.168.56.10 (build01.lab.internal)`  ·  rule `SRF-SCRIPT-SIGNAL`

SMB signing is not enforced; relay attacks are in scope. Matched: `3.1.1: Message signing enabled but not required`

**Next step:** Read the full script output below and verify the claim directly; NSE reports both false positives and stale CVE mappings.

#### **4. HIGH** — `ftp-anon` output needs review (21/tcp)

`192.168.56.10 (build01.lab.internal) 21/tcp`  ·  rule `SRF-SCRIPT-SIGNAL`

Anonymous authentication accepted. Matched: `Anonymous FTP login allowed (FTP code 230)`

**Next step:** Read the full script output below and verify the claim directly; NSE reports both false positives and stale CVE mappings.

#### **5. HIGH** — `smb-vuln-ms17-010` output needs review (445/tcp)

`192.168.56.11 (win-dc01.lab.internal) 445/tcp`  ·  rule `SRF-SCRIPT-SIGNAL`

An NSE script asserted a vulnerable state. Matched: `VULNERABLE: Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010) State: V...`

**Next step:** Read the full script output below and verify the claim directly; NSE reports both false positives and stale CVE mappings.

#### **6. HIGH** — Port 2375/tcp is reachable

`192.168.56.10 (build01.lab.internal) 2375/tcp`  ·  rule `SRF-SENSITIVE-PORT`

Docker API (plain HTTP) exposed; unauthenticated access is root on the host. Nothing probed this port, so the service is unconfirmed.

**Next step:** Identify what is actually listening (`-sV -p 2375`), then decide whether this exposure is intended.

#### **7. HIGH** — Cleartext file transfer on 21/tcp

`192.168.56.10 (build01.lab.internal) 21/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`ftp` -- vsftpd 2.3.4. Cleartext file transfer; check for anonymous login.

**Next step:** `--script ftp-anon,ftp-syst -p 21`; check for anonymous and writable paths.

#### **8. HIGH** — Key-value store exposed on 6379/tcp

`192.168.56.10 (build01.lab.internal) 6379/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`redis` -- Redis key-value store 5.0.7. Key-value store exposed; default config has no auth.

**Next step:** `redis-cli -h <host> -p 6379 info` -- unauthenticated access shows immediately.

#### **9. HIGH** — Unidentified service on 2375/tcp

`192.168.56.10 (build01.lab.internal) 2375/tcp`  ·  rule `SRF-UNIDENTIFIED`

A port is open and nmap could not name the service.

**Next step:** Grab the banner by hand (`ncat -v <host> 2375`), then `-sV --version-all -p 2375`.

#### **10. HIGH** — Unidentified service on 9999/tcp

`192.168.56.10 (build01.lab.internal) 9999/tcp`  ·  rule `SRF-UNIDENTIFIED`

nmap saw a `tcpwrapped` response: the TCP handshake completed and the service then closed the connection without speaking, so what is behind it is unknown.

**Next step:** Grab the banner by hand (`ncat -v <host> 9999`), then `-sV --version-all -p 9999`.

#### **11. MEDIUM** — Cleartext HTTP on 80/tcp

`192.168.56.10 (build01.lab.internal) 80/tcp`  ·  rule `SRF-CLEARTEXT-HTTP`

No TLS was detected on this listener. Anything authenticated over it is recoverable on-path.

**Next step:** Check whether it redirects to HTTPS, and whether the redirect is enforced (HSTS) rather than advisory.

#### **12. MEDIUM** — Cleartext HTTP on 8081/tcp

`192.168.56.10 (build01.lab.internal) 8081/tcp`  ·  rule `SRF-CLEARTEXT-HTTP`

No TLS was detected on this listener. Anything authenticated over it is recoverable on-path.

**Next step:** Check whether it redirects to HTTPS, and whether the redirect is enforced (HSTS) rather than advisory.

#### **13. MEDIUM** — Looks like a Database server (strong match)

`192.168.56.10 (build01.lab.internal)`  ·  rule `SRF-HOST-ROLE`

Matched on: database listener open; a second database listener open; database software in a banner. The host's value is its data rather than its services, so the exposure question is who can reach the listener at all. This is inferred from the scan, not confirmed -- read the signals above and decide whether they describe this host.

**Next step:** Confirm authentication and network restriction on each database port; a listener reachable from a user network is the finding regardless of its version.

#### **14. MEDIUM** — `http-methods` output needs review (80/tcp)

`192.168.56.10 (build01.lab.internal) 80/tcp`  ·  rule `SRF-SCRIPT-SIGNAL`

Risky HTTP method or WebDAV enabled. Matched: `...T HEAD POST OPTIONS TRACE Potentially risky methods: TRACE`

**Next step:** Read the full script output below and verify the claim directly; NSE reports both false positives and stale CVE mappings.

#### **15. MEDIUM** — Remote administration reachable from this position on 22/tcp

`192.168.56.10 (build01.lab.internal) 22/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`ssh` -- OpenSSH 7.4 protocol 2.0. Remote administration reachable from this position.

**Next step:** `--script ssh2-enum-algos,ssh-auth-methods -p 22`; confirm password auth is disabled.

#### **16. MEDIUM** — Database exposed to the scanning position on 3306/tcp

`192.168.56.10 (build01.lab.internal) 3306/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`mysql` (service name inferred from the port number, not probed). Database exposed to the scanning position.

**Next step:** `--script mysql-info,mysql-empty-password -p 3306`.

#### **17. MEDIUM** — SMB reachable on 445/tcp

`192.168.56.11 (win-dc01.lab.internal) 445/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`microsoft-ds` -- Microsoft Windows Server 2008 R2 microsoft-ds. SMB reachable; review signing, SMBv1, and share ACLs.

**Next step:** `--script smb2-security-mode,smb-os-discovery,smb-enum-shares -p 445`.

#### **18. MEDIUM** — RPC endpoint mapper reachable on 135/tcp

`192.168.56.14 (dc01.lab.internal) 135/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`msrpc` -- Microsoft Windows RPC. RPC endpoint mapper reachable.

**Next step:** Confirm the service and its authentication on 135/tcp, then decide whether this exposure is intended.

#### **19. MEDIUM** — Legacy NetBIOS session service reachable on 139/tcp

`192.168.56.14 (dc01.lab.internal) 139/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`netbios-ssn` -- Microsoft Windows netbios-ssn. Legacy NetBIOS session service reachable.

**Next step:** Confirm the service and its authentication on 139/tcp, then decide whether this exposure is intended.

#### **20. MEDIUM** — Directory exposed without TLS on 3268/tcp

`192.168.56.14 (dc01.lab.internal) 3268/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`ldap` -- Microsoft Windows Active Directory LDAP Domain: lab.internal0., Site: Default-First-Site-Name. Directory exposed without TLS; check for anonymous bind.

**Next step:** `--script ldap-rootdse -p 3268`; test for anonymous bind.

#### **21. MEDIUM** — RDP reachable on 3389/tcp

`192.168.56.14 (dc01.lab.internal) 3389/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`ms-wbt-server` -- Microsoft Terminal Services. RDP reachable; review NLA and lockout policy.

**Next step:** `--script rdp-ntlm-info,rdp-enum-encryption -p 3389`; confirm NLA is required.

#### **22. MEDIUM** — Directory exposed without TLS on 389/tcp

`192.168.56.14 (dc01.lab.internal) 389/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`ldap` -- Microsoft Windows Active Directory LDAP Domain: lab.internal0., Site: Default-First-Site-Name. Directory exposed without TLS; check for anonymous bind.

**Next step:** `--script ldap-rootdse -p 389`; test for anonymous bind.

#### **23. MEDIUM** — SMB reachable on 445/tcp

`192.168.56.14 (dc01.lab.internal) 445/tcp`  ·  rule `SRF-SENSITIVE-SERVICE`

`microsoft-ds` -- Windows Server 2019 Standard. SMB reachable; review signing, SMBv1, and share ACLs.

**Next step:** `--script smb2-security-mode,smb-os-discovery,smb-enum-shares -p 445`.

#### **24. MEDIUM** — vsftpd 2.3.4 -- the backdoored release on 21/tcp

`192.168.56.10 (build01.lab.internal) 21/tcp`  ·  rule `SRF-VERSION-AGE`

Banner: `vsftpd 2.3.4`. A banner is not a patch level -- distributions backport fixes without changing it, and some services lie deliberately -- so this is a version to *check*, not a vulnerability.

**Next step:** Compare the exact build against the vendor's advisories, or confirm the patch level from the host itself.

#### **25. MEDIUM** — OpenSSH older than 8.x on 22/tcp

`192.168.56.10 (build01.lab.internal) 22/tcp`  ·  rule `SRF-VERSION-AGE`

Banner: `OpenSSH 7.4 protocol 2.0`. A banner is not a patch level -- distributions backport fixes without changing it, and some services lie deliberately -- so this is a version to *check*, not a vulnerability.

**Next step:** Compare the exact build against the vendor's advisories, or confirm the patch level from the host itself.

#### **26. MEDIUM** — Apache httpd older than 2.4 on 80/tcp

`192.168.56.10 (build01.lab.internal) 80/tcp`  ·  rule `SRF-VERSION-AGE`

Banner: `Apache httpd 2.2.15`. A banner is not a patch level -- distributions backport fixes without changing it, and some services lie deliberately -- so this is a version to *check*, not a vulnerability.

**Next step:** Compare the exact build against the vendor's advisories, or confirm the patch level from the host itself.

#### **27. MEDIUM** — nginx older than 1.20 on 8081/tcp

`192.168.56.10 (build01.lab.internal) 8081/tcp`  ·  rule `SRF-VERSION-AGE`

Banner: `nginx 1.14.2`. A banner is not a patch level -- distributions backport fixes without changing it, and some services lie deliberately -- so this is a version to *check*, not a vulnerability.

**Next step:** Compare the exact build against the vendor's advisories, or confirm the patch level from the host itself.

#### **28. LOW** — HTTP on a non-standard port (8081/tcp)

`192.168.56.10 (build01.lab.internal) 8081/tcp`  ·  rule `SRF-HTTP-ODD-PORT`

Web services on unexpected ports are usually admin interfaces, dev builds or appliances -- the things least likely to be in an asset inventory.

**Next step:** Open it and identify the application; run `--script http-title,http-headers` at minimum.

#### **29. INFO** — Host answers to several names

`192.168.56.10 (build01.lab.internal)`  ·  rule `SRF-MULTI-NAME`

build01.lab.internal, jenkins.lab.internal. Virtual hosting means the services reached by name may differ from what the IP serves -- scanning the IP can miss a vhost entirely.

**Next step:** Re-scan web services by hostname, and check for others (certificate SANs, `--script http-vhosts`).

## 3. Inventory

### 192.168.56.10 (build01.lab.internal)

*Appears to be: Database server (strong), Container host (likely), Web server (likely) · OS guess: Linux 3.2 - 4.9 (92%) · 1 hop(s) away · not shown: 986 closed*

| Port | State | Service | Version | Identified by |
|---|---|---|---|---|
| 21/tcp | open | ftp | vsftpd 2.3.4 | probe |
| 22/tcp | open | ssh | OpenSSH 7.4 protocol 2.0 | probe |
| 80/tcp | open | http | Apache httpd 2.2.15 | probe |
| 2375/tcp | open | unknown | — | port table |
| 3306/tcp | open | mysql | — | port table |
| 6379/tcp | open | redis | Redis key-value store 5.0.7 | probe |
| 8081/tcp | open | http | nginx 1.14.2 | probe |
| 9999/tcp | open | tcpwrapped | — | probe |

<details><summary>NSE script output</summary>

**host · smb2-security-mode**

```
3.1.1: 
    Message signing enabled but not required
```

**21/tcp · ftp-anon**

```
Anonymous FTP login allowed (FTP code 230)
```

**22/tcp · ssh-auth-methods**

```
Supported authentication methods: 
  publickey
  password
```

**80/tcp · http-title**

```
Jenkins [Dashboard]
```

**80/tcp · http-methods**

```
Supported Methods: GET HEAD POST OPTIONS TRACE
  Potentially risky methods: TRACE
```

</details>

### 192.168.56.11 (win-dc01.lab.internal)

*Appears to be: File server (possible) · OS guess: Microsoft Windows Server 2008 R2 (85%) · not shown: 988 filtered*

| Port | State | Service | Version | Identified by |
|---|---|---|---|---|
| 445/tcp | open | microsoft-ds | Microsoft Windows Server 2008 R2 microsoft-ds | probe |
| 3389/tcp | open|filtered | ms-wbt-server | — | port table |
| 5985/tcp | filtered | winrm | — | port table |

<details><summary>NSE script output</summary>

**445/tcp · smb-vuln-ms17-010**

```
VULNERABLE:
  Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
    State: VULNERABLE
    IDs:  CVE:CVE-2017-0143
```

</details>

### 192.168.56.14 (dc01.lab.internal)

*Appears to be: Active Directory domain controller (strong), DNS server (likely), File server (possible) · OS guess: Microsoft Windows Server 2019 (96%) · not shown: 985 closed*

| Port | State | Service | Version | Identified by |
|---|---|---|---|---|
| 53/tcp | open | domain | Simple DNS Plus | probe |
| 88/tcp | open | kerberos-sec | Microsoft Windows Kerberos server time: 2026-10-06 09:01:12Z | probe |
| 135/tcp | open | msrpc | Microsoft Windows RPC | probe |
| 139/tcp | open | netbios-ssn | Microsoft Windows netbios-ssn | probe |
| 389/tcp | open | ldap | Microsoft Windows Active Directory LDAP Domain: lab.internal0., Site: Default-First-Site-Name | probe |
| 445/tcp | open | microsoft-ds | Windows Server 2019 Standard | probe |
| 464/tcp | open | kpasswd5 | — | port table |
| 636/tcp | open | ldapssl | — | probe |
| 3268/tcp | open | ldap | Microsoft Windows Active Directory LDAP Domain: lab.internal0., Site: Default-First-Site-Name | probe |
| 3389/tcp | open | ms-wbt-server | Microsoft Terminal Services | probe |

<details><summary>NSE script output</summary>

**host · smb-os-discovery**

```
OS: Windows Server 2019 Standard
  Computer name: dc01
  Domain name: lab.internal
  Forest name: lab.internal
  FQDN: dc01.lab.internal
```

**host · smb2-security-mode**

```
3.1.1: 
    Message signing enabled and required
```

**389/tcp · ldap-rootdse**

```
LDAP Results
  <ROOT>
      domainFunctionality: 7
      dnsHostName: dc01.lab.internal
      defaultNamingContext: DC=lab,DC=internal
```

</details>

## 4. Suggested follow-up scans

```bash
nmap -p- -sV -T3 -oX full-tcp.xml 192.168.56.10 192.168.56.11 192.168.56.14   # the 64,535 ports this scan skipped
sudo nmap -sU --top-ports 50 -sV -oX udp.xml 192.168.56.10 192.168.56.11 192.168.56.14
nmap -sV --version-all -p 464,2375,3306,9999 -oX unknown-services.xml 192.168.56.10 192.168.56.11 192.168.56.14
```

---

*Generated by `nmap-review`. Scan only systems you are authorised to test.*
