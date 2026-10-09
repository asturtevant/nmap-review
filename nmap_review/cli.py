#!/usr/bin/env python3
"""Command line entry point.

Two verbs, because there are two situations:

    nmap-review report scan.xml              # XML you already have
    nmap-review scan -- -sV -p- 10.0.0.5     # run nmap, then report on it

Everything after `--` in `scan` goes to nmap untouched (see runner.py for why).

Exit codes are meant for CI: 0 clean, 1 review items found at or above
`--fail-on`, 2 the tool itself failed. So a pipeline can gate on "no new HIGH
review items" without parsing the report.
"""

import argparse
import sys

from . import __version__
from .parse import ParseError, parse_file, parse_string
from .report import markdown, text, to_json
from .rules import PRIORITY_ORDER, review
from .runner import NmapFailed, NmapNotFound, run


def build_parser():
    p = argparse.ArgumentParser(
        prog="nmap-review",
        description="Turn nmap output into a report that says what still needs review.",
        epilog="Scan only systems you are authorised to test.",
    )
    p.add_argument("--version", action="version", version=f"nmap-review {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-f", "--format", choices=("md", "text", "json"), default="md",
                        help="output format (default: md)")
    common.add_argument("-o", "--out", metavar="PATH",
                        help="write the report here instead of stdout")
    common.add_argument("--fail-on", choices=("high", "medium", "low", "info", "never"),
                        default="never",
                        help="exit 1 if any review item is at this priority or above "
                             "(default: never)")
    common.add_argument("--only", choices=("coverage", "surface"),
                        help="restrict the report to one class of finding")
    common.add_argument("--min-priority", choices=("high", "medium", "low", "info"),
                        default="info", help="drop findings below this priority")

    rep = sub.add_parser("report", parents=[common],
                         help="review an existing nmap XML file ('-' for stdin)")
    rep.add_argument("xml", help="path to nmap -oX output, or - for stdin")

    scn = sub.add_parser("scan", parents=[common],
                         help="run nmap and review the result")
    scn.add_argument("--keep-xml", metavar="PATH",
                     help="also save the raw nmap XML here")
    scn.add_argument("nmap_args", nargs=argparse.REMAINDER,
                     help="arguments passed to nmap verbatim (put them after --)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        if args.command == "report":
            if args.xml == "-":
                scan = parse_string(sys.stdin.read(), source="<stdin>")
            else:
                scan = parse_file(args.xml)
        else:
            nmap_args = [a for a in args.nmap_args if a != "--"]
            if not nmap_args:
                print("nmap-review scan: give nmap's arguments after `--`, e.g.\n"
                      "  nmap-review scan -- -sV -sC -p- 10.0.0.5", file=sys.stderr)
                return 2
            xml, cmd = run(nmap_args, keep_xml=args.keep_xml,
                           echo=lambda line: print(line, file=sys.stderr))
            scan = parse_string(xml, source=" ".join(cmd))
    except (ParseError, NmapNotFound, NmapFailed) as exc:
        print(f"nmap-review: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"nmap-review: no such file: {args.xml}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:                      # pragma: no cover
        print("\nnmap-review: interrupted", file=sys.stderr)
        return 2

    findings = review(scan)
    if args.only:
        findings = [f for f in findings if f.kind == args.only]
    floor = PRIORITY_ORDER[args.min_priority]
    findings = [f for f in findings if PRIORITY_ORDER[f.priority] <= floor]

    renderer = {"md": markdown, "text": text, "json": to_json}[args.format]
    out = renderer(scan, findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"nmap-review: wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(out)

    if args.fail_on != "never":
        gate = PRIORITY_ORDER[args.fail_on]
        if any(PRIORITY_ORDER[f.priority] <= gate for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
