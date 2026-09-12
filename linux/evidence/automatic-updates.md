<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Automatic-update validation — 2026-09-07

## Live non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator updates validation'
```

[VERIFIED] Exact new finding, tally and report paths; exit code 0:

```text
[PASS] Automatic security updates: unattended-upgrades installed=yes; APT periodic Enable=1; APT periodic Update-Package-Lists=1; APT periodic Unattended-Upgrade=1; explicit security origin=yes; apt-daily.timer enabled-and-active=yes; apt-daily-upgrade.timer enabled-and-active=yes; completion/no-op log evidence=yes. Scope: Ubuntu/Debian standard APT timers and English log markers; historical completion does not prove recent success, patch currency or repository trust.
1 PASS, 0 FAIL, 1 WARN, 2 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-k2d8pv1o/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-k2d8pv1o/report.html
```

## Deliberate missing-tool run

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator updates missing-tool validation'
```

[VERIFIED] Exact new finding from that run:

```text
[UNKN] Automatic security updates: completion/no-op log evidence=yes. Scope: Ubuntu/Debian standard APT timers and English log markers; historical completion does not prove recent success, patch currency or repository trust. Visibility gaps: APT configuration: missing binary: apt-config; apt-daily-upgrade.timer: missing binary: systemctl; apt-daily.timer: missing binary: systemctl; package: missing binary: dpkg-query
```

## Tests and mechanism verification

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07: 60 tests pass. Update fixtures cover complete evidence, installed
but never completed, disabled periodic execution, disabled timers, missing
logs, denied logs, missing tools, absent security origins, malformed intervals,
origin patterns and successful no-op runs. Non-operational cases score WARN;
missing visibility scores UNKN.

[VERIFIED] The commands below, run 2026-09-07, confirmed the local APT
periodic defaults and completion-marker strings used by this collector:

```bash
rg -n -C 3 'unattended-upgrades-stamp|Unattended-Upgrade|APT::Periodic::Enable' /usr/lib/apt/apt.systemd.daily
rg -n 'All upgrades installed|No packages found|Starting unattended|Allowed origins' /usr/bin/unattended-upgrade
```

[UNVERIFIED] This does not establish freshness of successful execution,
current patch state, repository authenticity, custom/cron schedulers, or
unresolved broad/custom origin patterns. Only current and previous plain-text
English logs are searched. Raw logs and origin values are not copied into
reports. No apt update, upgrade, install or service operation is executed.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[PASS] Automatic security updates: unattended-upgrades installed=yes; APT periodic Enable=1; APT periodic Update-Package-Lists=1; APT periodic Unattended-Upgrade=1; explicit security origin=yes; apt-daily.timer enabled-and-active=yes; apt-daily-upgrade.timer enabled-and-active=yes; completion/no-op log evidence=yes. Scope: Ubuntu/Debian standard APT timers and English log markers; historical completion does not prove recent success, patch currency or repository trust.
1 PASS, 0 FAIL, 2 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-uyv6jpdz/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-uyv6jpdz/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-07]
Automatic-update findings match. Root/non-root output, deliberate missing-tool
UNKN and disabled/never-completed WARN fixtures satisfy check 5's validation
prerequisite. Root reports were not independently opened by the agent.
