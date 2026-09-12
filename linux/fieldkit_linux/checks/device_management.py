"""Report management evidence without pretending it proves console ownership."""

from ..common import Unavailable, Verdict

# Only names and presence are collected. Config contents can contain tokens.
AGENTS = (
    ("Ansible pull", ("ansible-pull",), ("/etc/ansible",), ("ansible-pull.service",)),
    ("Chef", ("chef-client",), ("/etc/chef",), ("chef-client.service", "chef.service")),
    (
        "cloud-init",
        ("cloud-init",),
        ("/etc/cloud",),
        ("cloud-init.service", "cloud-final.service", "cloud-init-local.service"),
    ),
    ("JumpCloud", ("jcagent",), ("/opt/jc",), ("jcagent.service",)),
    (
        "Landscape",
        ("landscape-client",),
        ("/etc/landscape",),
        ("landscape-client.service",),
    ),
    (
        "osquery / Fleet",
        ("osqueryd", "fleetd", "orbit"),
        ("/etc/osquery", "/opt/orbit"),
        ("osqueryd.service", "orbit.service", "fleetd.service"),
    ),
    (
        "Puppet",
        ("puppet",),
        ("/etc/puppet", "/etc/puppetlabs", "/opt/puppetlabs/bin/puppet"),
        ("puppet.service",),
    ),
    ("Salt", ("salt-minion",), ("/etc/salt",), ("salt-minion.service",)),
)


def config_management(host):
    evidence = []
    gaps = []
    installed = {}
    runtime = {}
    commands = (
        (
            "unit files",
            [
                "systemctl",
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
            ],
            installed,
            2,
        ),
        (
            "unit states",
            [
                "systemctl",
                "list-units",
                "--all",
                "--type=service",
                "--plain",
                "--no-legend",
                "--no-pager",
            ],
            runtime,
            4,
        ),
    )
    for label, args, destination, minimum in commands:
        try:
            for line in host.command(args).splitlines():
                fields = line.split()
                if len(fields) >= minimum and fields[0].endswith(".service"):
                    destination[fields[0]] = (
                        fields[1] if minimum == 2 else "/".join(fields[1:4])
                    )
        except PermissionError:
            gaps.append(label + ": needs root to read")
        except Unavailable as exc:
            gaps.append(label + ": " + str(exc))

    for label, binaries, paths, units in AGENTS:
        signals = []
        for binary in binaries:
            if host.which(binary):
                signals.append("binary " + binary)
        for path in paths:
            try:
                if host.exists(path):
                    signals.append("path " + path)
            except PermissionError:
                gaps.append(path + ": needs root to read")
            except OSError as exc:
                gaps.append(path + ": unreadable (" + type(exc).__name__ + ")")
        for unit in units:
            if unit in installed:
                signals.append(unit + "=" + installed[unit])
            if unit in runtime:
                signals.append(unit + "=" + runtime[unit])
        if signals:
            evidence.append(label + " [" + ", ".join(sorted(signals)) + "]")

    detail = "; ".join(evidence) if evidence else "No known management evidence found."
    detail += (
        " Presence does not prove enrollment, current policy, or console ownership."
    )
    if gaps:
        return Verdict(
            "UNKN", detail + " Visibility gaps: " + "; ".join(sorted(set(gaps)))
        )
    if not evidence:
        return Verdict(
            "UNKN", detail + " Custom agents and schedules are outside this inventory."
        )
    return Verdict("INFO", detail)
