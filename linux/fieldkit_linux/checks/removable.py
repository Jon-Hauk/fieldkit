"""Read USBGuard runtime policy and udev blocking-rule candidates."""

import re

from ..common import Unavailable, Verdict


def udev_block_candidate(text):
    text = re.sub(r"\\\n\s*", " ", text)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        storage_match = re.search(r'DRIVERS?\s*==\s*"usb-storage"', line) or re.search(
            r'ATTRS?\{bInterfaceClass\}\s*==\s*"08"', line
        )
        if storage_match and re.search(r'ATTR\{authorized\}\s*:?=\s*"0"', line):
            return True
    return False


def removable_storage(host):
    evidence = []
    gaps = []
    non_enforcing = False
    for parameter, accepted in (
        ("ImplicitPolicyTarget", {"allow", "block", "reject"}),
        ("InsertedDevicePolicy", {"apply-policy", "allow", "block", "reject", "keep"}),
    ):
        try:
            value = host.command(["usbguard", "get-parameter", parameter]).strip()
            if value not in accepted:
                gaps.append("USBGuard " + parameter + ": unrecognized runtime value")
                continue
            evidence.append("USBGuard " + parameter + "=" + value)
            non_enforcing = non_enforcing or value in ("allow", "keep")
        except PermissionError:
            gaps.append("USBGuard: needs root to read")
        except Unavailable as exc:
            gaps.append("USBGuard: " + str(exc))

    # Resolve same-name udev overrides by directory precedence. These remain
    # candidates: rule order, parent-device semantics and runtime state matter.
    files = {}
    for directory in (
        "/usr/lib/udev/rules.d",
        "/lib/udev/rules.d",
        "/usr/local/lib/udev/rules.d",
        "/run/udev/rules.d",
        "/etc/udev/rules.d",
    ):
        try:
            for path in sorted((host.root / directory.lstrip("/")).iterdir()):
                if path.name.endswith(".rules"):
                    files[path.name] = path
        except FileNotFoundError:
            continue
        except PermissionError:
            gaps.append(directory + ": needs root to read")
        except OSError:
            gaps.append(directory + ": unavailable")
    candidates = []
    for name, path in sorted(files.items()):
        relative = "/" + str(path.relative_to(host.root))
        try:
            if udev_block_candidate(host.read_text(relative)):
                candidates.append(relative)
        except PermissionError:
            gaps.append(relative + ": needs root to read")
        except (Unavailable, OSError, UnicodeError):
            gaps.append(relative + ": unreadable rule file")
    evidence.append("udev storage-deauthorization candidates=" + str(len(candidates)))
    if candidates:
        evidence.append("review paths: " + "; ".join(candidates))
    detail = "; ".join(evidence)
    detail += (
        ". Scope: USBGuard runtime defaults and narrow udev rule signatures. "
        "USBGuard allow exceptions, existing-device policy, udev rule execution, "
        "UAS devices and actual removable-media access are not established. "
        "Candidate rules do not prove effective blocking."
    )
    if non_enforcing:
        detail += " Review: USBGuard allows or preserves authorization in at least one runtime default."
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    return Verdict("WARN" if non_enforcing else "INFO", detail)
