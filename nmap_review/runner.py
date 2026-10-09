"""Running nmap, when we are the one running it.

The wrapper adds nothing to the command line that changes what gets sent to the
target. It appends `-oX <tmpfile>` so the output can be parsed, and that is the
only edit. Two reasons, both of them about trust: a scan is an action against
someone else's network, so the operator has to own exactly what was sent; and
the coverage rules report on the *actual* flags -- silently adding `-sV` or
`-A` would make the report describe a scan the operator did not authorise and
quietly erase the caveat that says the scan was narrow.
"""

import os
import shutil
import subprocess
import tempfile


class NmapNotFound(Exception):
    pass


class NmapFailed(Exception):
    pass


def nmap_path():
    path = shutil.which("nmap")
    if not path:
        raise NmapNotFound(
            "nmap is not on PATH. Install it, or point this tool at XML that "
            "already exists: nmap-review report scan.xml")
    return path


def run(nmap_args, keep_xml=None, echo=None):
    """Run nmap with the given args and return (xml_text, command_list).

    `nmap_args` is passed through verbatim. `-oX` is appended; if the caller
    already specified an XML output path we respect theirs and read it back,
    rather than writing the scan twice.
    """
    binary = nmap_path()
    args = list(nmap_args)

    own_xml = None
    for i, a in enumerate(args):
        if a == "-oX" and i + 1 < len(args):
            own_xml = args[i + 1]
        elif a == "-oA" and i + 1 < len(args):
            own_xml = args[i + 1] + ".xml"

    tmp = None
    if own_xml is None:
        fd, tmp = tempfile.mkstemp(prefix="nmap-review-", suffix=".xml")
        os.close(fd)
        args += ["-oX", tmp]
        xml_path = tmp
    else:
        xml_path = own_xml

    cmd = [binary] + args
    if echo:
        echo("+ " + " ".join(cmd))

    try:
        # stdout is nmap's human output; let it through so a long scan still
        # shows progress. Only the XML is consumed programmatically.
        proc = subprocess.run(cmd, check=False)
        if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
            raise NmapFailed(
                f"nmap exited {proc.returncode} and wrote no XML. "
                "The arguments or the target specification are probably wrong.")
        with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
            xml = f.read()
    finally:
        if tmp and keep_xml:
            try:
                shutil.copyfile(tmp, keep_xml)
            except OSError:                       # pragma: no cover - best effort
                pass
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)

    return xml, cmd
