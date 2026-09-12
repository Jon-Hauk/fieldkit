<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Fieldkit Linux diagnostic report \- operator persistence missing\-tool validation

Host: example-host; root: no

Preview: management inventory, remote access, MAC, SSH, updates, firewall defaults and persistence inventory only; remaining Linux controls are not implemented\.

0 PASS, 0 FAIL, 1 WARN, 6 UNKN, 0 INFO


## Device management

| Status | Check | Detail |
|---|---|---|
| UNKN | Config\-management ownership | No known management evidence found\. Presence does not prove enrollment, current policy, or console ownership\. Visibility gaps: unit files: missing binary: systemctl; unit states: missing binary: systemctl |
| UNKN | Remote\-access review | No known remote\-access candidates found in inspected sources\. Scope: known binaries/paths and system\-manager service fragments/drop\-ins\. User services, containers, SSH config files, scripts and dynamic arguments are not inspected; fragment matches may be overridden\. Presence does not prove authorization, execution or reachability\. Visibility gaps: list\-unit\-files: missing binary: systemctl; list\-units: missing binary: systemctl |

## Hardening

| Status | Check | Detail |
|---|---|---|
| UNKN | Automatic security updates | completion/no\-op log evidence=yes\. Scope: Ubuntu/Debian standard APT timers and English log markers; historical completion does not prove recent success, patch currency or repository trust\. Visibility gaps: APT configuration: missing binary: apt\-config; apt\-daily\-upgrade\.timer: missing binary: systemctl; apt\-daily\.timer: missing binary: systemctl; package: missing binary: dpkg\-query |
| UNKN | Host firewall inbound defaults | nft: missing binary: nft; UFW: missing binary: ufw |
| WARN | MAC framework enforcement | SELinux global mode: permissive \(not enforcing\)<br>Remediation: Have the operator review workload policy coverage and validate an enforcing AppArmor or SELinux policy before changing host configuration\. |
| UNKN | SSH daemon configuration | missing binary: sshd |

## Persistence and audit

| Status | Check | Detail |
|---|---|---|
| UNKN | Persistence surface | Persistence files inventoried=575; package\-owned=0; not package\-owned=0; ownership unresolved=575\. Scope: system/user unit and timer files, drop\-ins, cron spools/directories, crontab, anacrontab and rc\.local; user units limited to local root/UID&gt;=1000 homes\. Package ownership does not establish vendor provenance, file integrity, authorization or execution\. Generated files and enablement symlinks may be legitimate; symlinked directories and transient in\-memory units are not inspected\. Visibility gaps: /home/analyst/\.config/systemd/user: needs root to read; /root/\.config/systemd/user: needs root to read; /var/spool/cron: needs root to read; missing binary: dpkg\-query |
