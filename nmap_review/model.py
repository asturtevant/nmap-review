"""The scan, as data.

A small typed layer between nmap's XML and everything downstream. The rules and
the renderers never see an ElementTree, so a change in nmap's schema is a change
in one file (`parse.py`) rather than a change everywhere.

Fields that nmap may legitimately omit are modelled as `None` or empty, never as
a plausible-looking default. An empty `product` means "nmap did not identify
this", which is itself one of the strongest signals that something needs human
review -- so it must not be indistinguishable from "identified as blank".
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Script:
    """One NSE script's output for a port or host."""
    id: str
    output: str


@dataclass
class Port:
    number: int
    protocol: str               # tcp | udp | sctp
    state: str                  # open | filtered | open|filtered | closed ...
    reason: str = ""            # syn-ack, no-response, admin-prohibited ...
    service: str = ""           # nmap's service name (may be a port guess)
    product: str = ""           # only present with -sV
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""            # "ssl" when nmap saw TLS on this port
    method: str = ""            # "table" (guessed from port) | "probed" (-sV)
    confidence: Optional[int] = None
    scripts: list = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.number}/{self.protocol}"

    @property
    def banner(self) -> str:
        """Human-readable service string, as much of it as nmap actually found."""
        parts = [p for p in (self.product, self.version, self.extrainfo) if p]
        return " ".join(parts)

    @property
    def probed(self) -> bool:
        """True when this service was fingerprinted, not inferred from the port.

        `method="table"` means nmap looked the port number up in nmap-services
        and printed the *conventional* service for it. That is a guess, and the
        whole report has to label it as one.
        """
        return self.method == "probed"


@dataclass
class Host:
    address: str
    addresses: list = field(default_factory=list)   # [(addr, type)]
    hostnames: list = field(default_factory=list)   # [(name, type)]
    state: str = "unknown"                          # up | down | skipped
    os_matches: list = field(default_factory=list)  # [(name, accuracy)]
    ports: list = field(default_factory=list)
    extraports: list = field(default_factory=list)  # [(state, count, reasons)]
    scripts: list = field(default_factory=list)     # host-level NSE output
    distance: Optional[int] = None

    @property
    def label(self) -> str:
        if self.hostnames:
            return f"{self.address} ({self.hostnames[0][0]})"
        return self.address

    def open_ports(self) -> list:
        return [p for p in self.ports if p.state == "open"]

    def ambiguous_ports(self) -> list:
        """States nmap could not resolve: it saw nothing and cannot say why."""
        return [p for p in self.ports if "|" in p.state]

    def count_extra(self, state: str) -> int:
        return sum(c for s, c, _ in self.extraports if s == state)


@dataclass
class Scan:
    """A whole nmap run: what was asked for, and what came back."""
    args: str = ""
    version: str = ""
    start: str = ""
    finished: str = ""
    exit_status: str = ""
    scan_types: list = field(default_factory=list)  # [(type, protocol, services)]
    hosts: list = field(default_factory=list)
    source: str = ""                                # where the XML came from

    def up_hosts(self) -> list:
        return [h for h in self.hosts if h.state == "up"]
