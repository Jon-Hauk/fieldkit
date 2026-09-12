<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Audit and retention validation — 2026-09-08

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator audit validation'
```

[VERIFIED] Exact new finding, remediation, tally and paths; exit code 0:

```text
[WARN] Audit trail and retention: auditd.service running=no; systemd-journald.service running=yes; journal Storage=auto; MaxRetentionSec=default (not explicitly configured); SystemMaxUse=default (not explicitly configured); SystemKeepFree=default (not explicitly configured); SystemMaxFiles=default (not explicitly configured); MaxFileSec=default (not explicitly configured); current-machine persistent journal files=not found. Scope: service state, merged on-disk journal configuration and persistent-file presence. Retention limits are upper bounds, not guaranteed retained days. Actual oldest events, daemon reload state, audit rules/loss/rotation and remote log copies are not evaluated. Review: auditd.service not observed running; explicit journal age/space retention budget is incomplete; no current-machine persistent .journal files observed
  -> Have the operator agree an evidence-retention window, verify audit rules and retained events, then plan persistence and storage limits accordingly.
1 PASS, 0 FAIL, 2 WARN, 4 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-epv75b50/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-epv75b50/report.html
```

## Deliberate missing-tool run

[VERIFIED] Command, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator audit missing-tool validation'
```

[VERIFIED] Exact new finding:

```text
[UNKN] Audit trail and retention: current-machine persistent journal files=not found. Scope: service state, merged on-disk journal configuration and persistent-file presence. Retention limits are upper bounds, not guaranteed retained days. Actual oldest events, daemon reload state, audit rules/loss/rotation and remote log copies are not evaluated. Review: no current-machine persistent .journal files observed Visibility gaps: auditd.service: missing binary: systemctl; journal configuration: missing binary: systemd-analyze; systemd-journald.service: missing binary: systemctl
```

## Tests and scope

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 85 tests pass. Audit fixtures cover configured caps as INFO,
inactive services, volatile storage, missing explicit caps and persistent
files as WARN, denied files/missing tools as UNKN, configuration sections and
drop-in overrides, and matching the local machine ID to persistent files.

[ASSUMED] An explicit retention age/space budget is a review baseline, not a
claim that upstream defaults are unsafe. Actual retained duration is not
established by configured upper bounds. A configured evidence window must be
validated against retained events and workload log volume separately.

[UNVERIFIED] Audit-rule coverage, event loss, auditd rotation, oldest retained
events, remote copies and whether on-disk settings are loaded are outside
scope. This check reads service metadata and file presence, not log content.
No service or logging configuration is changed.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[WARN] Audit trail and retention: auditd.service running=no; systemd-journald.service running=yes; journal Storage=auto; MaxRetentionSec=default (not explicitly configured); SystemMaxUse=default (not explicitly configured); SystemKeepFree=default (not explicitly configured); SystemMaxFiles=default (not explicitly configured); MaxFileSec=default (not explicitly configured); current-machine persistent journal files=not found. Scope: service state, merged on-disk journal configuration and persistent-file presence. Retention limits are upper bounds, not guaranteed retained days. Actual oldest events, daemon reload state, audit rules/loss/rotation and remote log copies are not evaluated. Review: auditd.service not observed running; explicit journal age/space retention budget is incomplete; no current-machine persistent .journal files observed
  -> Have the operator agree an evidence-retention window, verify audit rules and retained events, then plan persistence and storage limits accordingly.
2 PASS, 0 FAIL, 4 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-s_uw6gon/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-s_uw6gon/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08] Audit
and retention findings match. Root/non-root evidence, missing-tool UNKN and
non-operational WARN cases satisfy check 8's validation prerequisite. Private
root report files were not independently opened by the agent.
