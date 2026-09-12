"""Read audit service state and journal storage/retention evidence."""

import os
import re

from ..common import Unavailable, Verdict


def journal_settings(text):
    settings = {}
    section = ""
    text = re.sub(r"\\\n\s*", " ", text)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            section = line
        elif section == "[Journal]" and "=" in line:
            name, value = line.split("=", 1)
            if name.strip() in (
                "Storage",
                "MaxRetentionSec",
                "SystemMaxUse",
                "SystemKeepFree",
                "SystemMaxFiles",
                "MaxFileSec",
            ):
                settings[name.strip()] = value.strip()
    return settings


def persistent_journal_present(host):
    machine_id = host.read_text("/etc/machine-id").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32}", machine_id):
        raise Unavailable("journal: invalid or unavailable machine ID")
    directory = host.root / "var/log/journal" / machine_id
    try:
        with os.scandir(str(directory)) as entries:
            return any(
                entry.name.endswith(".journal") and entry.is_file(follow_symlinks=False)
                for entry in entries
            )
    except FileNotFoundError:
        return False


def audit_trail(host):
    details = []
    warnings = []
    gaps = []

    def observe(check, label):
        try:
            return check()
        except PermissionError:
            gaps.append(label + ": needs root to read")
        except FileNotFoundError:
            gaps.append(label + ": source unavailable")
        except Unavailable as exc:
            gaps.append(label + ": " + str(exc))
        except (OSError, UnicodeError):
            gaps.append(label + ": unreadable source")
        return None

    for service in ("auditd.service", "systemd-journald.service"):
        output = observe(
            lambda: host.command(
                [
                    "systemctl",
                    "show",
                    "--no-pager",
                    "--property=LoadState,ActiveState,SubState",
                    "--",
                    service,  # noqa: B023 - onerror is consumed by os.walk within this iteration
                ]
            ),
            service,
        )
        if output is None:
            continue
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if not all(name in values for name in ("LoadState", "ActiveState", "SubState")):
            gaps.append(service + ": incomplete service state")
            continue
        running = (
            values["LoadState"] == "loaded"
            and values["ActiveState"] == "active"
            and values["SubState"] == "running"
        )
        details.append(service + " running=" + ("yes" if running else "no"))
        if not running:
            warnings.append(service + " not observed running")

    config = observe(
        lambda: host.command(
            ["systemd-analyze", "cat-config", "systemd/journald.conf"]
        ),
        "journal configuration",
    )
    if config is not None:
        settings = journal_settings(config)
        storage = settings.get("Storage") or "auto"
        if storage not in ("auto", "persistent", "volatile", "none"):
            gaps.append("journal Storage: unrecognized value")
        else:
            details.append("journal Storage=" + storage)
            if storage in ("volatile", "none"):
                warnings.append("journal storage is not configured persistent")
        for key in (
            "MaxRetentionSec",
            "SystemMaxUse",
            "SystemKeepFree",
            "SystemMaxFiles",
            "MaxFileSec",
        ):
            value = settings.get(key)
            # Never report arbitrary configuration payloads as trusted limits.
            if value and not re.fullmatch(r"[0-9A-Za-z. %+-]+", value):
                gaps.append("journal " + key + ": unrecognized limit syntax")
            else:
                details.append(
                    key + "=" + (value or "default (not explicitly configured)")
                )
        if not settings.get("MaxRetentionSec") or not settings.get("SystemMaxUse"):
            warnings.append("explicit journal age/space retention budget is incomplete")
    persistent = observe(
        lambda: persistent_journal_present(host), "persistent journal files"
    )
    if persistent is not None:
        details.append(
            "current-machine persistent journal files="
            + ("yes" if persistent else "not found")
        )
        if not persistent:
            warnings.append("no current-machine persistent .journal files observed")
    detail = "; ".join(details)
    detail += (
        ". Scope: service state, merged on-disk journal configuration and persistent-file presence. "
        "Retention limits are upper bounds, not guaranteed retained days. Actual oldest "
        "events, daemon reload state, audit rules/loss/rotation and remote log copies are not evaluated."
    )
    if warnings:
        detail += " Review: " + "; ".join(warnings)
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    # Even fully configured caps do not prove an adequate evidence window.
    return Verdict("WARN" if warnings else "INFO", detail)
