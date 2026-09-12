"""Command line orchestration; importing this module does not collect state."""

import argparse
import os
import platform
import sys
from pathlib import Path

from .checks.audit import audit_trail
from .checks.authentication import directory_enrollment, pam_mfa, ssh_authentication
from .checks.containers import ContainerPosture
from .checks.device_management import config_management
from .checks.dlp import disk_encryption, key_escrow
from .checks.dormancy import dormant_accounts
from .checks.firewall import host_firewall
from .checks.hardening import mac_enforcement, sshd_configuration
from .checks.identity import privileged_accounts, sudo_policy
from .checks.network_exposure import listening_sockets
from .checks.persistence import persistence_surface
from .checks.remote_access import remote_access
from .checks.removable import removable_storage
from .checks.ssh_keys import authorized_key_inventory
from .checks.updates import automatic_updates
from .common import STATUSES, Host, run_check
from .report import export


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only Linux diagnostics (incremental preview)."
    )
    parser.add_argument("--client-name", default="Diagnostic report")
    parser.add_argument(
        "--dormant-days",
        type=int,
        default=90,
        help="last-login review threshold in days (default: 90)",
    )
    parser.add_argument(
        "--report-path",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "reports",
    )
    parser.add_argument(
        "--docker-socket",
        default="/var/run/docker.sock",
        help="absolute local Docker Unix socket (remote contexts ignored)",
    )
    parser.add_argument(
        "--compose-root",
        type=Path,
        action="append",
        default=[],
        help="approved Compose search directory; repeatable, bounded scan",
    )
    parser.add_argument(
        "--containers-only",
        action="store_true",
        help="collect only container posture findings",
    )
    args = parser.parse_args(argv)
    if not args.docker_socket.startswith("/"):
        parser.error("--docker-socket must be an absolute local path")
    args.compose_root = [path.absolute() for path in args.compose_root]
    if not 1 <= args.dormant_days <= 36500:
        parser.error("--dormant-days must be between 1 and 36500")
    if platform.system() != "Linux":
        print("Fieldkit Linux requires Linux.", file=sys.stderr)
        return 2
    host = Host()
    findings = (
        []
        if args.containers_only
        else [
            run_check(
                "Device management",
                "Config-management ownership",
                lambda: config_management(host),
            ),
            run_check(
                "Device management",
                "Remote-access review",
                lambda: remote_access(host),
                "Confirm each candidate against the approved support-tool inventory; "
                "have the operator investigate unapproved tools or forwarding units.",
            ),
            run_check(
                "Hardening",
                "MAC framework enforcement",
                lambda: mac_enforcement(host),
                "Have the operator review workload policy coverage and validate "
                "an enforcing AppArmor or SELinux policy before changing host configuration.",
            ),
            run_check(
                "Hardening",
                "SSH daemon configuration",
                lambda: sshd_configuration(host),
                "Have the operator review root access and authentication policy, "
                "including Match rules and MFA; validate an alternate login before changes.",
            ),
            run_check(
                "Hardening",
                "Automatic security updates",
                lambda: automatic_updates(host),
                "Have the operator review package status, APT security origins, periodic "
                "settings, scheduling and completion logs before planning any changes.",
            ),
            run_check(
                "Hardening",
                "Host firewall inbound defaults",
                lambda: host_firewall(host),
                "Have the operator review IPv4/IPv6 inbound defaults and allowed traffic; "
                "preserve an alternate access path before any firewall changes.",
            ),
            run_check(
                "Persistence and audit",
                "Persistence surface",
                lambda: persistence_surface(host),
                "Have the operator reconcile non-package-owned persistence paths "
                "with approved local changes; investigate unknown entries before removal.",
            ),
            run_check(
                "Persistence and audit",
                "Audit trail and retention",
                lambda: audit_trail(host),
                "Have the operator agree an evidence-retention window, verify audit rules "
                "and retained events, then plan persistence and storage limits accordingly.",
            ),
            run_check(
                "DLP",
                "Root and data disk encryption",
                lambda: disk_encryption(host),
                "Have the operator review root/data encryption coverage and plan recovery "
                "and backups before any disk-encryption changes.",
            ),
            run_check("DLP", "Encryption key escrow", key_escrow),
            run_check(
                "DLP",
                "Removable-storage controls",
                lambda: removable_storage(host),
                "Have the operator review approved USB devices and effective storage "
                "policy before changes; preserve keyboard and recovery access.",
            ),
            run_check(
                "Identity and access",
                "Local privileged accounts",
                lambda: privileged_accounts(host),
                "Have the operator reconcile UID 0 accounts and privileged groups "
                "with approved administrators before changing access.",
            ),
            run_check(
                "Identity and access",
                "Sudo policy inventory",
                lambda: sudo_policy(host),
                "Have the operator review authentication-bypass candidates and effective "
                "sudo grants, preserving a tested administrative access path.",
            ),
            run_check(
                "Identity and access",
                "SSH authorized-key inventory",
                lambda: authorized_key_inventory(host),
                "Have the operator reconcile key owners, weak algorithms and writable "
                "key files with approved access; test replacement access before removal.",
            ),
            run_check(
                "Identity and access",
                "Dormant accounts and leftover keys",
                lambda: dormant_accounts(host, args.dormant_days),
                "Have the operator confirm account ownership and login evidence, then "
                "review leftover keys before any offboarding changes.",
            ),
            run_check(
                "Identity and access",
                "PAM MFA inventory",
                lambda: pam_mfa(host),
                "Have the operator verify effective PAM control flow, MFA enrollment "
                "and bypass exceptions using a tested recovery-access plan.",
            ),
            run_check(
                "Identity and access",
                "SSH authentication methods",
                lambda: ssh_authentication(host),
            ),
            run_check(
                "Identity and access",
                "Directory enrollment evidence",
                lambda: directory_enrollment(host),
            ),
            run_check(
                "Network exposure",
                "Listening socket bindings",
                lambda: listening_sockets(host),
            ),
        ]
    )
    findings.extend(
        ContainerPosture(host, args.docker_socket, args.compose_root).findings()
    )
    for finding in findings:
        print(f"[{finding.Status}] {finding.Name}: {finding.Detail}")
        if finding.Status in ("FAIL", "WARN") and finding.Remediation:
            print("  -> " + finding.Remediation)
    if any(
        f.Status == "UNKN"
        and (
            "needs root to read" in f.Detail or "needs docker group or root" in f.Detail
        )
        for f in findings
    ):
        print(
            "Some controls need root to read. Re-run with sudo to read this; "
            "Fieldkit never elevates itself."
        )
    print(", ".join(f"{sum(f.Status == s for f in findings)} {s}" for s in STATUSES))
    try:
        paths = export(
            findings,
            args.client_name,
            platform.node(),
            os.geteuid() == 0,
            args.report_path,
        )
    except OSError as exc:
        print("Report export failed: " + str(exc), file=sys.stderr)
        return 2
    for path in paths:
        print("Report: " + str(path))
    return 1 if any(f.Status == "FAIL" for f in findings) else 0
