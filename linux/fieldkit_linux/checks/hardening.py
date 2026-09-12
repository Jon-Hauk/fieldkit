"""Kernel-reported mandatory-access-control state; never modifies policy."""

import re
from collections import Counter

from ..common import Unavailable, Verdict


def apparmor_profiles(text):
    modes = Counter()
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r".+ \((enforce|complain|kill|unconfined|prompt)\)", line)
        if not match:
            return Verdict("UNKN", "AppArmor: unrecognized profile mode or record")
        modes[match.group(1)] += 1
    if not modes:
        return Verdict("WARN", "AppArmor active but no profiles loaded")
    detail = "AppArmor loaded profile modes: " + ", ".join(
        f"{mode}={count}" for mode, count in sorted(modes.items())
    )
    detail += ". Profile presence does not prove coverage of every workload."
    if any(modes[mode] for mode in ("complain", "unconfined", "prompt")):
        return Verdict("WARN", detail)
    return Verdict("PASS", detail)


def selinux_mode(text):
    mode = text.strip()
    if mode == "0":
        return Verdict("WARN", "SELinux global mode: permissive (not enforcing)")
    if mode == "1":
        return Verdict(
            "PASS",
            "SELinux global mode: enforcing. Per-domain permissive "
            "exceptions and policy coverage are not inspected.",
        )
    return Verdict("UNKN", "SELinux: unrecognized kernel enforcement value")


def mac_enforcement(host):
    def read(path):
        try:
            return host.read_text(path)
        except FileNotFoundError:
            raise Unavailable(path + ": kernel interface unavailable")

    # The active-LSM list prevents an installed but inactive framework from
    # being mistaken for protection, or from masking another active framework.
    modules = {
        part.strip() for part in read("/sys/kernel/security/lsm").strip().split(",")
    }
    if not modules or "" in modules:
        return Verdict("UNKN", "Active LSM list is empty or malformed")
    checks = []
    for name, path, parse in (
        ("apparmor", "/sys/kernel/security/apparmor/profiles", apparmor_profiles),
        ("selinux", "/sys/fs/selinux/enforce", selinux_mode),
    ):
        if name not in modules:
            continue
        try:
            checks.append(parse(read(path)))
        except PermissionError:
            checks.append(Verdict("UNKN", name + ": needs root to read"))
        except Unavailable as exc:
            checks.append(Verdict("UNKN", str(exc)))
    if not checks:
        return Verdict(
            "FAIL",
            "Neither AppArmor nor SELinux appears in the kernel's active LSM list",
        )
    # Unknown active-framework state must not silently turn into a pass.
    status = next(
        (
            s
            for s in ("UNKN", "WARN", "PASS")
            if any(check.Status == s for check in checks)
        ),
        "UNKN",
    )
    return Verdict(status, "; ".join(check.Detail for check in checks))


def sshd_configuration(host):
    """Ask sshd to parse its default on-disk config, without starting a server."""
    output = host.command(["sshd", "-T"])
    expected = {
        "permitrootlogin": {
            "yes",
            "no",
            "prohibit-password",
            "without-password",
            "forced-commands-only",
        },
        "passwordauthentication": {"yes", "no"},
        "pubkeyauthentication": {"yes", "no"},
    }
    observed = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or fields[0].lower() not in expected:
            continue
        name = fields[0].lower()
        if len(fields) != 2 or name in observed or fields[1] not in expected[name]:
            return Verdict(
                "UNKN", "sshd -T returned an unrecognized or duplicate " + name
            )
        observed[name] = fields[1]
    missing = sorted(set(expected) - set(observed))
    if missing:
        return Verdict("UNKN", "sshd -T did not report: " + ", ".join(missing))
    detail = "; ".join(name + "=" + observed[name] for name in sorted(observed))
    detail += (
        ". Scope: default on-disk global configuration parsed by sshd -T. "
        "Connection-specific Match rules, alternate daemon configurations and "
        "running-daemon reload state are not evaluated. PasswordAuthentication=no "
        "alone does not prove key-only login."
    )
    if observed["permitrootlogin"] == "yes":
        return Verdict("FAIL", detail)
    if (
        observed["permitrootlogin"] != "no"
        or observed["passwordauthentication"] != "no"
        or observed["pubkeyauthentication"] != "yes"
    ):
        return Verdict("WARN", detail)
    return Verdict("PASS", detail)
