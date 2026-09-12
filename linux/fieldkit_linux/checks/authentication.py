"""Local identity integration and authentication evidence, without login tests."""

import re

from ..common import Unavailable, Verdict


def pam_mfa(host):
    references = []
    gaps = []
    relaxed = False
    try:
        files = sorted((host.root / "etc/pam.d").iterdir())
    except FileNotFoundError:
        return Verdict("UNKN", "PAM service directory unavailable")
    if len(files) > 256:
        return Verdict("UNKN", "PAM service inventory exceeds 256-file limit")
    for path in files:
        if not path.is_file():
            continue
        name = "/etc/pam.d/" + path.name
        try:
            content = host.read_text(name)
        except PermissionError:
            gaps.append(name + ": needs root to read")
            continue
        except (Unavailable, OSError, UnicodeError):
            gaps.append(name + ": unreadable")
            continue
        for number, line in enumerate(content.splitlines(), 1):
            line = line.split("#", 1)[0]
            match = re.search(
                r"\bpam_(google_authenticator|oath|u2f|duo|yubico)\.so\b", line
            )
            if match:
                references.append(f"{name}:{number} {match.group()}")
                relaxed = relaxed or bool(
                    re.search(r"\b(optional|sufficient|nullok)\b", line)
                )
    detail = "Recognized PAM MFA references: " + (
        "; ".join(references) or "none observed"
    )
    detail += (
        ". Scope: local PAM file references only; service selection, include/control flow, "
        "enrollment and actual MFA enforcement are not established. External/SSSD MFA "
        "and SSH hardware-key user verification are outside scope."
    )
    if relaxed:
        detail += " Review: optional/sufficient/nullok appears on an MFA-module line."
    if gaps:
        return Verdict("UNKN", detail + " Visibility gaps: " + "; ".join(gaps))
    return Verdict("WARN" if relaxed else "INFO", detail)


def ssh_authentication(host):
    output = host.command(["sshd", "-T"])
    names = (
        "pubkeyauthentication",
        "passwordauthentication",
        "kbdinteractiveauthentication",
        "gssapiauthentication",
        "hostbasedauthentication",
        "authenticationmethods",
    )
    values = {}
    for line in output.splitlines():
        parts = line.split(None, 1)
        if parts and parts[0] in names:
            if len(parts) != 2 or parts[0] in values:
                return Verdict(
                    "UNKN", "sshd authentication output incomplete or duplicated"
                )
            values[parts[0]] = parts[1]
    if set(values) != set(names) or any(
        values[name] not in ("yes", "no") for name in names[:-1]
    ):
        return Verdict("UNKN", "sshd authentication directives missing or unrecognized")
    if not re.fullmatch(r"[a-z0-9,: -]+", values["authenticationmethods"]):
        return Verdict("UNKN", "sshd AuthenticationMethods syntax unrecognized")
    key_only = values["pubkeyauthentication"] == "yes" and (
        values["authenticationmethods"] == "publickey"
        or (
            values["authenticationmethods"] == "any"
            and all(values[name] == "no" for name in names[1:-1])
        )
    )
    detail = "; ".join(name + "=" + values[name] for name in names)
    detail += "; global key-only configuration=" + (
        "yes" if key_only else "not established"
    )
    detail += (
        ". Scope: default on-disk global sshd configuration; Match rules, alternate configs, "
        "running-daemon state and successful authentication are not verified. "
        "Key-only login is not proof of MFA or hardware-key user verification."
    )
    return Verdict("PASS" if key_only else "INFO", detail)


def directory_enrollment(host):
    evidence = []
    gaps = []
    for label, args in (
        (
            "SSSD",
            [
                "systemctl",
                "show",
                "--no-pager",
                "--property=LoadState,ActiveState,SubState",
                "--",
                "sssd.service",
            ],
        ),
        ("realmd", ["realm", "list", "--name-only"]),
    ):
        try:
            output = host.command(args)
            if label == "SSSD":
                values = dict(
                    line.split("=", 1) for line in output.splitlines() if "=" in line
                )
                if not all(
                    name in values for name in ("LoadState", "ActiveState", "SubState")
                ):
                    gaps.append("SSSD: incomplete service state")
                    continue
                running = (
                    values["LoadState"] == "loaded"
                    and values["ActiveState"] == "active"
                    and values["SubState"] == "running"
                )
                evidence.append("SSSD running=" + ("yes" if running else "no"))
            else:
                evidence.append(
                    "realmd-listed realms=" + str(len(set(output.splitlines())))
                )
        except PermissionError:
            gaps.append(label + ": needs root to read")
        except Unavailable as exc:
            gaps.append(label + ": " + str(exc))
    detail = "; ".join(evidence) or "No directory-integration state established"
    detail += (
        ". Scope: local SSSD service and realmd realm-list evidence; tenant names are omitted. "
        "Directory reachability, trust health, active enrollment, user authentication and "
        "MFA policy are not verified; no directory login or join is attempted."
    )
    if gaps:
        return Verdict("UNKN", detail + " Visibility gaps: " + "; ".join(gaps))
    return Verdict("INFO", detail)
