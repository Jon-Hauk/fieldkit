"""Local remote-support evidence; sanctioning requires the client's inventory."""

import re

from ..common import Unavailable, Verdict

TOOLS = (
    ("TeamViewer", ("teamviewer", "teamviewerd"), ("/opt/teamviewer",)),
    ("AnyDesk", ("anydesk",), ("/etc/anydesk",)),
    ("RustDesk", ("rustdesk",), ("/etc/rustdesk",)),
    ("ngrok", ("ngrok",), ("/etc/ngrok.yml", "/etc/ngrok")),
)


def unit_candidates(text):
    """Return source paths and signatures, never command lines or credentials.

    systemctl cat includes fragments and drop-ins. These are configuration
    candidates, not proof that a command is effective, running or reachable.
    """
    candidates = set()
    source = "unit fragment"
    section = ""
    # Unit continuation lines can contain options on subsequent physical lines.
    text = re.sub(r"\\\n\s*", " ", text)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# /"):
            source = line[2:]
            section = ""
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
            continue
        if section != "[Service]" or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() not in (
            "ExecStart",
            "ExecStartPre",
            "ExecStartPost",
            "ExecReload",
        ):
            continue
        for label, pattern in (
            ("TeamViewer command", r"(?<![\w-])teamviewerd?(?![\w-])"),
            ("AnyDesk command", r"(?<![\w-])anydesk(?![\w-])"),
            ("RustDesk command", r"(?<![\w-])rustdesk(?![\w-])"),
            ("ngrok command", r"(?<![\w-])ngrok(?![\w-])"),
        ):
            if re.search(pattern, value, re.IGNORECASE):
                candidates.add(source + ": " + label)
        if re.search(r"(?<![\w-])(?:auto)?ssh(?![\w-])", value):  # noqa: SIM102 - nesting mirrors the two distinct conditions being reported
            if re.search(r"(?:^|\s|[\"'])-[A-Za-z]*R", value) or re.search(
                r"RemoteForward\s*(?:=|\s)", value, re.IGNORECASE
            ):
                candidates.add(source + ": SSH reverse-forward candidate")
    return candidates


def remote_access(host):
    candidates = set()
    gaps = set()
    units = set()
    masked = set()
    for label, binaries, paths in TOOLS:
        for binary in binaries:
            if host.which(binary):
                candidates.add(label + ": binary " + binary)
        for path in paths:
            try:
                if host.exists(path):
                    candidates.add(label + ": path " + path)
            except PermissionError:
                gaps.add(path + ": needs root to read")
            except OSError as exc:
                gaps.add(path + ": unreadable (" + type(exc).__name__ + ")")

    def collect(args, label):
        try:
            return host.command(args)
        except PermissionError:
            gaps.add(label + ": needs root to read")
        except Unavailable:
            # Do not copy command stderr into this finding: a failing unit
            # query might echo sensitive contents supplied by the host.
            if not host.which(args[0]):
                gaps.add(label + ": missing binary: " + args[0])
            else:
                gaps.add(label + ": source unavailable or timed out")
        return ""

    for verb in ("list-unit-files", "list-units"):
        args = ["systemctl", verb, "--type=service", "--no-legend", "--no-pager"]
        if verb == "list-units":
            args.extend(["--all", "--plain"])
        for line in collect(args, verb).splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0].endswith(".service"):
                if fields[1] in ("masked", "masked-runtime"):
                    masked.add(fields[0])
                    continue
                if fields[1] == "not-found":
                    continue
                units.add(fields[0])
    ordered = sorted(units - masked)
    for start in range(0, len(ordered), 32):
        batch = ordered[start : start + 32]
        text = collect(
            ["systemctl", "cat", "--no-pager", "--"] + batch,
            f"unit fragments batch {start // 32 + 1}",
        )
        candidates.update(unit_candidates(text))

    scope = (
        " Scope: known binaries/paths and system-manager service fragments/drop-ins. "
        "User services, containers, SSH config files, scripts and dynamic arguments "
        "are not inspected; fragment matches may be overridden. "
        "Presence does not prove authorization, execution or reachability."
    )
    detail = (
        "Review candidates: " + "; ".join(sorted(candidates))
        if candidates
        else "No known remote-access candidates found in inspected sources."
    )
    if gaps:
        return Verdict(
            "UNKN", detail + scope + " Visibility gaps: " + "; ".join(sorted(gaps))
        )
    return Verdict("WARN" if candidates else "INFO", detail + scope)
