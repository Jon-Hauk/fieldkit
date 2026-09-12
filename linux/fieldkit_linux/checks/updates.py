"""Ubuntu/Debian unattended-upgrades evidence; no update commands are run."""

import shlex

from ..common import Unavailable, Verdict


def automatic_updates(host):
    observations = []
    warnings = []
    gaps = []

    def command(args, label):
        try:
            return host.command(args)
        except PermissionError:
            gaps.append(label + ": needs root to read")
        except Unavailable as exc:
            gaps.append(label + ": " + str(exc))
        return None

    package = command(
        ["dpkg-query", "-W", "-f=${Status}", "unattended-upgrades"], "package"
    )
    if package is not None:
        installed = package.strip() == "install ok installed"
        observations.append(
            "unattended-upgrades installed=" + ("yes" if installed else "no")
        )
        if not installed:
            warnings.append("package not fully installed")

    config = command(["apt-config", "dump"], "APT configuration")
    if config is not None:
        settings = {}
        origins = []
        for line in config.splitlines():
            if not line.startswith(
                (
                    "APT::Periodic::",
                    "Unattended-Upgrade::Allowed-Origins::",
                    "Unattended-Upgrade::Origins-Pattern::",
                )
            ):
                continue
            try:
                parts = shlex.split(line.rstrip(";"))
            except ValueError:
                gaps.append("APT configuration: malformed relevant directive")
                continue
            if len(parts) != 2:
                gaps.append("APT configuration: malformed relevant directive")
                continue
            name, value = parts
            if name.startswith("APT::Periodic::"):
                settings[name] = value
            else:
                origins.append(value)
        for name, default in (
            ("Enable", "1"),
            ("Update-Package-Lists", "0"),
            ("Unattended-Upgrade", "0"),
        ):
            value = settings.get("APT::Periodic::" + name, default)
            # apt.systemd.daily accepts 'always' for intervals, not Enable.
            if not value.isdigit() and not (name != "Enable" and value == "always"):
                gaps.append("APT periodic " + name + ": unrecognized value")
            else:
                observations.append("APT periodic " + name + "=" + value)
                if value.isdigit() and int(value) == 0:
                    warnings.append("APT periodic " + name + " disabled")
        security = any(
            value.split(":")[-1].endswith("-security")
            for value in origins
            if ":" in value and "=" not in value
        )
        security = security or any(
            pair.strip().startswith(("archive=", "suite=", "a="))
            and pair.strip().split("=", 1)[1].endswith("-security")
            for value in origins
            for pair in value.split(",")
        )
        observations.append(
            "explicit security origin=" + ("yes" if security else "not established")
        )
        if not security:
            warnings.append(
                "review security-origin coverage; broad/custom patterns are not resolved"
            )

    for timer in ("apt-daily.timer", "apt-daily-upgrade.timer"):
        output = command(
            [
                "systemctl",
                "show",
                "--no-pager",
                "--property=LoadState,UnitFileState,ActiveState",
                "--",
                timer,
            ],
            timer,
        )
        if output is None:
            continue
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if not all(
            name in values for name in ("LoadState", "UnitFileState", "ActiveState")
        ):
            gaps.append(timer + ": incomplete state")
            continue
        good = (
            values["LoadState"] == "loaded"
            and values["UnitFileState"] == "enabled"
            and values["ActiveState"] == "active"
        )
        observations.append(timer + " enabled-and-active=" + ("yes" if good else "no"))
        if not good:
            warnings.append(
                timer
                + ": review persistent scheduling (custom/cron schedules not inspected)"
            )

    completed = False
    for path in (
        "/var/log/unattended-upgrades/unattended-upgrades.log",
        "/var/log/unattended-upgrades/unattended-upgrades.log.1",
    ):
        try:
            contents = host.read_text(path)
        except FileNotFoundError:
            continue
        except PermissionError:
            gaps.append("update logs: needs root to read")
            continue
        except (Unavailable, OSError, UnicodeError):
            gaps.append("update logs: unavailable or exceeds collection limit")
            continue
        completed = completed or any(
            marker in contents
            for marker in (
                "All upgrades installed",
                "No packages found that can be upgraded unattended",
            )
        )
    observations.append(
        "completion/no-op log evidence=" + ("yes" if completed else "not found")
    )
    if not completed:
        warnings.append(
            "no successful/no-op run found in current and previous plain-text logs"
        )
    detail = "; ".join(observations)
    detail += ". Scope: Ubuntu/Debian standard APT timers and English log markers; "
    detail += "historical completion does not prove recent success, patch currency or repository trust."
    if warnings:
        detail += " Review: " + "; ".join(warnings)
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    return Verdict("WARN" if warnings else "PASS", detail)
