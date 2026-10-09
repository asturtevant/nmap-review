#!/usr/bin/env python3
"""Command line entry point.

Three verbs, because there are three situations:

    nmap-review report scan.xml                  # XML you already have
    nmap-review report tcp.xml udp.xml full.xml  # several files, one report
    nmap-review scan -- -sV -p- 10.0.0.5         # run nmap, then report on it
    nmap-review diff baseline.xml latest.xml     # what changed

Everything after `--` in `scan` goes to nmap untouched (see runner.py for why).
`report` with several files merges them first (see merge.py), which is what
makes the coverage rules describe the whole scan set rather than one file of
it. `diff` takes a baseline and a current scan, and either side may itself be
several files, separated by `--`:

    nmap-review diff old-tcp.xml old-udp.xml -- new-tcp.xml new-udp.xml

Exit codes are meant for CI: 0 clean, 1 review items found at or above
`--fail-on`, 2 the tool itself failed. So a pipeline can gate on "no new HIGH
review items" without parsing the report.
"""

import argparse
import sys

from . import __version__
from .diff import diff_scans
from .html import html_diff, html_report
from .merge import merge_scans
from .parse import ParseError, parse_file, parse_string
from .report import (markdown, markdown_diff, text, text_diff, to_json,
                     to_json_diff)
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
    common.add_argument("-f", "--format", choices=("md", "text", "json", "html"),
                        default="md",
                        help="output format (default: md). html is a single "
                             "self-contained file with host drill-down")
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
                         help="review existing nmap XML ('-' for stdin); "
                              "several files are merged into one report")
    rep.add_argument("xml", nargs="+",
                     help="paths to nmap -oX output, or - for stdin")

    scn = sub.add_parser("scan", parents=[common],
                         help="run nmap and review the result")
    scn.add_argument("--keep-xml", metavar="PATH",
                     help="also save the raw nmap XML here")
    scn.add_argument("nmap_args", nargs=argparse.REMAINDER,
                     help="arguments passed to nmap verbatim (put them after --)")

    dif = sub.add_parser("diff", parents=[common],
                         help="compare a baseline scan against a current one")
    dif.add_argument("xml", nargs="+",
                     help="BASELINE CURRENT, or several of each separated by --")
    return p


# argparse swallows the first bare `--` it sees, so by the time the file list
# reaches us the separator between a diff's two sides is gone. Swapping it for
# a sentinel before parsing keeps the documented `old.xml -- new.xml` spelling
# working without giving the separator an option-looking name.
_SIDE_SEP = "\x00side"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "diff":
        argv = [_SIDE_SEP if a == "--" else a for a in argv]
    args = build_parser().parse_args(argv)

    try:
        if args.command == "report":
            scan = merge_scans([_load(path) for path in args.xml])
        elif args.command == "diff":
            sides = _split_sides(args.xml)
            if sides is None:
                print("nmap-review diff: give a baseline and a current scan, e.g.\n"
                      "  nmap-review diff baseline.xml latest.xml\n"
                      "  nmap-review diff old1.xml old2.xml -- new1.xml new2.xml",
                      file=sys.stderr)
                return 2
            old = merge_scans([_load(p) for p in sides[0]])
            new = merge_scans([_load(p) for p in sides[1]])
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
    except FileNotFoundError as exc:
        print(f"nmap-review: no such file: {exc.filename}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:                      # pragma: no cover
        print("\nnmap-review: interrupted", file=sys.stderr)
        return 2

    if args.command == "diff":
        return _emit_diff(args, old, new)

    findings = review(scan)
    if args.only:
        findings = [f for f in findings if f.kind == args.only]
    floor = PRIORITY_ORDER[args.min_priority]
    findings = [f for f in findings if PRIORITY_ORDER[f.priority] <= floor]

    renderer = {"md": markdown, "text": text, "json": to_json,
                "html": html_report}[args.format]
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


def _load(path):
    if path == "-":
        return parse_string(sys.stdin.read(), source="<stdin>")
    return parse_file(path)


def _split_sides(paths):
    """Split `diff`'s file list into (baseline, current).

    With a `--` separator each side may hold several files. Without one, the
    only unambiguous reading is exactly two files, so anything else is a usage
    error rather than a guess about which half is the baseline.
    """
    if _SIDE_SEP in paths or "--" in paths:
        i = paths.index(_SIDE_SEP if _SIDE_SEP in paths else "--")
        old, new = paths[:i], paths[i + 1:]
        return (old, new) if old and new else None
    if len(paths) == 2:
        return ([paths[0]], [paths[1]])
    return None


def _emit_diff(args, old, new):
    """Render a diff and gate on NEW changes only.

    The gate deliberately ignores everything that was already true at the
    baseline: a diff that fails CI for standing exposure fails every run, and a
    check that always fails is a check nobody reads.
    """
    d = diff_scans(old, new, review(old), review(new))

    changes = d.changes
    if args.min_priority:
        floor = PRIORITY_ORDER[args.min_priority]
        changes = [c for c in changes if PRIORITY_ORDER[c.priority] <= floor]
    d.changes = changes

    if args.format == "html":
        out = html_diff(d, review(new))
    else:
        out = {"md": markdown_diff, "text": text_diff, "json": to_json_diff}[args.format](d)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"nmap-review: wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(out)

    if args.fail_on != "never":
        gate = PRIORITY_ORDER[args.fail_on]
        if any(PRIORITY_ORDER[c.priority] <= gate for c in d.changes):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
