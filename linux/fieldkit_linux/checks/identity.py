"""Local access evidence; no password hashes or credential contents are read."""

import re
import shlex
from pathlib import PurePosixPath

from ..common import Unavailable, Verdict


def local_accounts(host):
    accounts = []
    for line in host.read_text("/etc/passwd").splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) != 7 or not fields[2].isdigit() or not fields[3].isdigit():
            raise Unavailable("local passwd inventory contains an unrecognized record")
        accounts.append(
            (fields[0], int(fields[2]), int(fields[3]), fields[5], fields[6])
        )
    if not accounts:
        raise Unavailable("local passwd inventory is empty")
    return accounts


def privileged_accounts(host):
    accounts = local_accounts(host)
    zero = sorted(name for name, uid, gid, home, shell in accounts if uid == 0)
    groups = []
    for line in host.read_text("/etc/group").splitlines():
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) != 4 or not fields[2].isdigit():
            return Verdict(
                "UNKN", "local group inventory contains an unrecognized record"
            )
        if fields[0] in ("sudo", "wheel", "admin"):
            members = set(filter(None, fields[3].split(",")))
            members.update(
                name
                for name, uid, gid, home, shell in accounts
                if gid == int(fields[2])
            )
            groups.append(fields[0] + "=[" + ", ".join(sorted(members)) + "]")
    detail = "Local UID 0 accounts=[{}]; privilege-related groups: {}".format(
        ", ".join(zero), "; ".join(sorted(groups)) or "none observed"
    )
    detail += ". Scope: local passwd/group files, including primary group membership; directory identities and effective sudo authorization are not evaluated."
    if len(zero) > 1:
        return Verdict("FAIL", detail)
    if not zero:
        return Verdict("UNKN", detail + " No local UID 0 account was found.")
    return Verdict("WARN" if zero != ["root"] else "INFO", detail)


def sudo_policy(host):
    visited = set()
    rules = []
    bypasses = []
    gaps = []

    def visit(path):
        if path in visited:
            gaps.append("sudoers include repeats or cycles: " + path)
            return
        if len(visited) >= 64:
            gaps.append("sudoers include limit reached")
            return
        visited.add(path)
        try:
            content = host.read_text(path)
        except PermissionError:
            gaps.append(path + ": needs root to read")
            return
        except (Unavailable, OSError):
            gaps.append(path + ": unavailable")
            return
        # Record source locations, never command arguments or embedded secrets.
        continuation = ""
        first = 0
        for number, physical in enumerate(content.splitlines(), 1):
            if not continuation:
                first = number
            continuation += physical.strip()
            if continuation.endswith("\\"):
                continuation = continuation[:-1] + " "
                continue
            line = continuation
            continuation = ""
            directive = re.match(r"^[#@](include|includedir)\s+(.+)$", line)
            if directive:
                try:
                    parts = shlex.split(directive.group(2), comments=True)
                except ValueError:
                    parts = []
                if len(parts) != 1 or "%" in parts[0]:
                    gaps.append(path + ": unresolved include syntax")
                    continue
                target = PurePosixPath(parts[0])
                if not target.is_absolute():
                    target = PurePosixPath(path).parent / target
                if ".." in target.parts:
                    gaps.append(path + ": include with parent traversal not evaluated")
                    continue
                if directive.group(1) == "include":
                    visit(str(target))
                else:
                    try:
                        for child in sorted(
                            (host.root / str(target).lstrip("/")).iterdir()
                        ):
                            if (
                                "." not in child.name
                                and not child.name.endswith("~")
                                and child.is_file()
                            ):
                                visit(str(target / child.name))
                    except PermissionError:
                        gaps.append(str(target) + ": needs root to read")
                    except OSError:
                        gaps.append(str(target) + ": include directory unavailable")
                continue
            if not line or line.startswith("#"):
                continue
            location = f"{path}:{first}"
            # This is an inventory of candidate grants, not a sudoers evaluator.
            if "=" in line and not line.startswith(
                ("Defaults", "User_Alias", "Host_Alias", "Runas_Alias", "Cmnd_Alias")
            ):
                rules.append(location)
            if re.search(r"\bNOPASSWD\s*:", line) or (
                line.startswith("Defaults") and "!authenticate" in line
            ):
                bypasses.append(location)
        if continuation:
            gaps.append(path + ": unfinished continuation")

    visit("/etc/sudoers")
    detail = f"Sudoers files inspected/attempted={len(visited)}; grant candidates={len(rules)}; authentication-bypass candidates={len(bypasses)}"
    if rules:
        detail += ". Grant locations: " + "; ".join(sorted(set(rules)))
    if bypasses:
        detail += ". Review bypass locations: " + "; ".join(sorted(set(bypasses)))
    detail += (
        ". Scope: local sudoers and resolved includes; candidate locations only. "
        "Aliases, tag scope/overrides, comments within entries, command restrictions, "
        "directory policy and effective user authorization are not evaluated."
    )
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    return Verdict("WARN" if bypasses else "INFO", detail)
