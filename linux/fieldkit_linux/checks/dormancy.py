"""Local last-login review candidates, correlated with conventional key files."""

import re
from datetime import datetime, timedelta, timezone

from ..common import Unavailable, Verdict
from .identity import local_accounts
from .ssh_keys import key_metadata


def login_state(output, days, now):
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) != 2 or not lines[0].startswith("Username"):
        raise Unavailable("lastlog: unrecognized account record")
    if "**Never logged in**" in lines[1]:
        return "no recorded login"
    match = re.search(
        r"[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\s+\d{4}$",
        lines[1],
    )
    if not match:
        raise Unavailable("lastlog: unrecognized timestamp")
    stamp = datetime.strptime(match.group(), "%a %b %d %H:%M:%S %z %Y")
    if stamp > now:
        raise Unavailable("lastlog: future timestamp; verify host clock")
    return (
        "older than threshold"
        if now - stamp > timedelta(days=days)
        else "within threshold"
    )


def standard_key_count(host, home):
    count = 0
    for basename in ("authorized_keys", "authorized_keys2"):
        path = home.rstrip("/") + "/.ssh/" + basename
        real = host.root / path.lstrip("/")
        if real.is_symlink() or any(parent.is_symlink() for parent in real.parents):
            raise Unavailable("symlinked key source not evaluated")
        try:
            content = host.read_text(path)
        except FileNotFoundError:
            continue
        for line in content.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                key_metadata(line)
            except (ValueError, UnicodeError, StopIteration):
                raise Unavailable("unsupported/malformed authorized-key record")
            count += 1
    return count


def dormant_accounts(host, days=90, now=None):
    now = now or datetime.now(timezone.utc)
    accounts = local_accounts(host)
    shells = {
        line.strip()
        for line in host.read_text("/etc/shells").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    if not shells:
        raise Unavailable("login-shell inventory is empty")
    details = []
    gaps = []
    candidates = False
    for name, uid, gid, home, shell in sorted(accounts):
        if shell not in shells:
            continue
        try:
            state = login_state(host.command(["lastlog", "--user", name]), days, now)
            if state == "within threshold":
                details.append(name + ": login within threshold")
                continue
            candidates = True
            keys = standard_key_count(host, home)
            details.append(
                f"{name}: {state}; conventional authorized-key entries={keys}"
            )
        except PermissionError:
            gaps.append(name + ": needs root to read")
        except (Unavailable, OSError) as exc:
            gaps.append(
                name
                + ": "
                + (str(exc) if isinstance(exc, Unavailable) else "source unavailable")
            )
    homes = {home.rstrip("/") for name, uid, gid, home, shell in accounts}
    try:
        for path in sorted((host.root / "home").iterdir()):
            home = "/home/" + path.name
            if home in homes or path.is_symlink() or not path.is_dir():
                continue
            try:
                keys = standard_key_count(host, home)
                if keys:
                    candidates = True
                    details.append(
                        f"{home}: no local account uses this home; conventional authorized-key entries={keys}"
                    )
            except PermissionError:
                gaps.append(home + ": needs root to read")
            except (Unavailable, OSError):
                gaps.append(home + ": key correlation unavailable")
    except FileNotFoundError:
        pass
    except PermissionError:
        gaps.append("orphan-home discovery: needs root to read")
    detail = f"Dormancy review threshold={days} days. " + (
        "; ".join(details) or "No account login state established"
    )
    detail += (
        ". Scope: local accounts with shells listed in /etc/shells and immediate orphan-home candidates. "
        "Missing/old lastlog records do not prove inactivity or offboarding; key presence does not "
        "prove accepted login. Nested/alternate key sources, directory accounts and account-lock state are not evaluated."
    )
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    return Verdict("WARN" if candidates else "INFO", detail)
