<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Remote-access check validation — 2026-09-07

## Real unprivileged run

[VERIFIED] Command, outside the execution sandbox, from
`/home/operator/fieldkit`, 2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator remote-access validation'
```

[VERIFIED] Exact command output; exit code 0:

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Custom agents and schedules are outside this inventory.
[INFO] Remote-access review: No known remote-access candidates found in inspected sources. Scope: known binaries/paths and system-manager service fragments/drop-ins. User services, containers, SSH config files, scripts and dynamic arguments are not inspected; fragment matches may be overridden. Presence does not prove authorization, execution or reachability.
0 PASS, 0 FAIL, 0 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-ly4b13kk/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-ly4b13kk/report.html
```

## Deliberate missing-tool run

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator remote missing-tool validation'
```

[VERIFIED] Exact remote-access finding from that command; exit code 0:

```text
[UNKN] Remote-access review: No known remote-access candidates found in inspected sources. Scope: known binaries/paths and system-manager service fragments/drop-ins. User services, containers, SSH config files, scripts and dynamic arguments are not inspected; fragment matches may be overridden. Presence does not prove authorization, execution or reachability. Visibility gaps: list-unit-files: missing binary: systemctl; list-units: missing binary: systemctl
```

## What failed and was corrected

[VERIFIED] The initial live command above returned `UNKN` for all eleven
fragment-query batches, 2026-09-07. The inventory included masked and
not-found units. Excluding those from fragment queries removed those errors;
the next run returned the `INFO` finding recorded above. A regression test
checks that these units do not reach `systemctl cat`.

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -v`,
2026-09-07: 29 tests pass. Remote-access fixtures cover `ssh -R`, combined
flags, `autossh`, `RemoteForward`, shell wrappers, line continuations,
comments, local-only forwarding, drop-in overrides, known tools, missing
commands and permission failures. Candidate cases return `WARN`; raw
addresses, ports and example tokens are excluded from findings.

[ASSUMED] An enforcing/permissive distinction does not apply to this check.
Authorization review is the recommendation; the host cannot prove whether a
remote-support tool is sanctioned.

## Root validation and acceptance

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Custom agents and schedules are outside this inventory.
[INFO] Remote-access review: No known remote-access candidates found in inspected sources. Scope: known binaries/paths and system-manager service fragments/drop-ins. User services, containers, SSH config files, scripts and dynamic arguments are not inspected; fragment matches may be overridden. Presence does not prove authorization, execution or reachability.
0 PASS, 0 FAIL, 0 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-judanpp0/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-judanpp0/report.html
```

[VERIFIED: comparison of supplied output with the live run above, 2026-09-07]
Root and non-root findings match. The root transcript, non-root run, deliberate
missing-tool case and fixture tests satisfy check 2's validation prerequisite.
The private root reports were not independently opened by the agent.
