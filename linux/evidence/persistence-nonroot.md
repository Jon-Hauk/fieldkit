<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Fieldkit Linux diagnostic report \- operator persistence validation

Host: example-host; root: no

Preview: management inventory, remote access, MAC, SSH, updates, firewall defaults and persistence inventory only; remaining Linux controls are not implemented\.

1 PASS, 0 FAIL, 1 WARN, 4 UNKN, 1 INFO


## Device management

| Status | Check | Detail |
|---|---|---|
| UNKN | Config\-management ownership | No known management evidence found\. Presence does not prove enrollment, current policy, or console ownership\. Custom agents and schedules are outside this inventory\. |
| INFO | Remote\-access review | No known remote\-access candidates found in inspected sources\. Scope: known binaries/paths and system\-manager service fragments/drop\-ins\. User services, containers, SSH config files, scripts and dynamic arguments are not inspected; fragment matches may be overridden\. Presence does not prove authorization, execution or reachability\. |

## Hardening

| Status | Check | Detail |
|---|---|---|
| PASS | Automatic security updates | unattended\-upgrades installed=yes; APT periodic Enable=1; APT periodic Update\-Package\-Lists=1; APT periodic Unattended\-Upgrade=1; explicit security origin=yes; apt\-daily\.timer enabled\-and\-active=yes; apt\-daily\-upgrade\.timer enabled\-and\-active=yes; completion/no\-op log evidence=yes\. Scope: Ubuntu/Debian standard APT timers and English log markers; historical completion does not prove recent success, patch currency or repository trust\. |
| UNKN | Host firewall inbound defaults | nft: needs root to read; UFW: needs root to read |
| WARN | MAC framework enforcement | SELinux global mode: permissive \(not enforcing\)<br>Remediation: Have the operator review workload policy coverage and validate an enforcing AppArmor or SELinux policy before changing host configuration\. |
| UNKN | SSH daemon configuration | sshd unavailable \(exit 1\): sshd: no hostkeys available \-\- exiting\. |

## Persistence and audit

| Status | Check | Detail |
|---|---|---|
| UNKN | Persistence surface | Persistence files inventoried=575; package\-owned=467; not package\-owned=108; ownership unresolved=0\. Review paths: /etc/systemd/system/serial\-getty@ttyGS0\.service\.d/autologin\.conf; /etc/systemd/system/serial\-getty@ttyTCU0\.service\.d/autologin\.conf; /etc/systemd/system/bluetooth\.target\.wants/bluetooth\.service; /etc/systemd/system/cloud\-final\.service\.wants/snapd\.seeded\.service; /etc/systemd/system/dbus\-fi\.w1\.wpa\_supplicant1\.service; /etc/systemd/system/dbus\-org\.bluez\.service; /etc/systemd/system/dbus\-org\.freedesktop\.Avahi\.service; /etc/systemd/system/dbus\-org\.freedesktop\.ModemManager1\.service; /etc/systemd/system/dbus\-org\.freedesktop\.nm\-dispatcher\.service; /etc/systemd/system/dbus\-org\.freedesktop\.oom1\.service; /etc/systemd/system/dbus\-org\.freedesktop\.resolve1\.service; /etc/systemd/system/dbus\-org\.freedesktop\.timesync1\.service; /etc/systemd/system/default\.target\.wants/nvidia\-pva\-allowd\.service; /etc/systemd/system/default\.target\.wants/nvmefc\-boot\-connections\.service; /etc/systemd/system/default\.target\.wants/nvmf\-autoconnect\.service; /etc/systemd/system/display\-manager\.service; /etc/systemd/system/emergency\.target\.wants/grub\-initrd\-fallback\.service; /etc/systemd/system/final\.target\.wants/snapd\.system\-shutdown\.service; /etc/systemd/system/getty\.target\.wants/getty@tty1\.service; /etc/systemd/system/getty\.target\.wants/serial\-getty@ttyTCU0\.service; /etc/systemd/system/graphical\.target\.wants/accounts\-daemon\.service; /etc/systemd/system/graphical\.target\.wants/power\-profiles\-daemon\.service; /etc/systemd/system/graphical\.target\.wants/switcheroo\-control\.service; /etc/systemd/system/graphical\.target\.wants/udisks2\.service; /etc/systemd/system/grub\-common\.service; /etc/systemd/system/grub\-initrd\-fallback\.service; /etc/systemd/system/multi\-user\.target\.wants/ModemManager\.service; /etc/systemd/system/multi\-user\.target\.wants/NetworkManager\.service; /etc/systemd/system/multi\-user\.target\.wants/anacron\.service; /etc/systemd/system/multi\-user\.target\.wants/avahi\-daemon\.service; /etc/systemd/system/multi\-user\.target\.wants/binfmt\-support\.service; /etc/systemd/system/multi\-user\.target\.wants/console\-setup\.service; /etc/systemd/system/multi\-user\.target\.wants/containerd\.service; /etc/systemd/system/multi\-user\.target\.wants/cron\.service; /etc/systemd/system/multi\-user\.target\.wants/dmesg\.service; /etc/systemd/system/multi\-user\.target\.wants/docker\.service; /etc/systemd/system/multi\-user\.target\.wants/e2scrub\_reap\.service; /etc/systemd/system/multi\-user\.target\.wants/fail2ban\.service; /etc/systemd/system/multi\-user\.target\.wants/grub\-common\.service; /etc/systemd/system/multi\-user\.target\.wants/grub\-initrd\-fallback\.service; 68 additional paths omitted from display \(regular files shown before symlinks\)\. Scope: system/user unit and timer files, drop\-ins, cron spools/directories, crontab, anacrontab and rc\.local; user units limited to local root/UID&gt;=1000 homes\. Package ownership does not establish vendor provenance, file integrity, authorization or execution\. Generated files and enablement symlinks may be legitimate; symlinked directories and transient in\-memory units are not inspected\. Visibility gaps: /home/analyst/\.config/systemd/user: needs root to read; /root/\.config/systemd/user: needs root to read; /var/spool/cron: needs root to read |
