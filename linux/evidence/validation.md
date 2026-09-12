<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Linux preview validation — 2026-09-07

[VERIFIED] Work is on `fieldkit/linux-port` (`git branch --show-current`,
2026-09-07). Python is 3.10.12 (`python3 --version`, 2026-09-07). The session
is unprivileged (`id`, 2026-09-07: `uid=1001(operator) gid=1001(operator)`).

## Real non-root run, outside the execution sandbox

[VERIFIED] Command, from `/home/operator/fieldkit`, 2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator local validation'
```

[VERIFIED] Exact console output of that command; exit code 0:

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Custom agents and schedules are outside this inventory.
0 PASS, 0 FAIL, 0 WARN, 1 UNKN, 0 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-van5foln/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-van5foln/report.html
```

[VERIFIED] The Markdown identifies `root: no` (`cat
fieldkit/reports/example-host-linux-van5foln/report.md`, 2026-09-07). Report
files remain under the existing ignored `reports/` directory.

## Real missing-tool path

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator missing-tool validation'
```

[VERIFIED] Exact console output of that command; exit code 0:

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Visibility gaps: unit files: missing binary: systemctl; unit states: missing binary: systemctl
0 PASS, 0 FAIL, 0 WARN, 1 UNKN, 0 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-vtqqjv4n/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-vtqqjv4n/report.html
```

## Sandbox visibility failure

[VERIFIED] The first command above was also run inside the execution sandbox,
2026-09-07. It returned this finding and one privilege hint:

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Visibility gaps: unit files: needs root to read; unit states: needs root to read
Some controls need root to read. Re-run with sudo to read this; Fieldkit never elevates itself.
```

[VERIFIED] The direct probe `systemctl list-unit-files --type=service
--no-legend --no-pager` initially returned `Failed to connect to bus: Operation
not permitted`; the approved outside-sandbox retry succeeded, 2026-09-07.
This was a sandbox restriction, not proof the host requires root for service
enumeration. The collector classifies permission errors as required by its
contract; it cannot distinguish every confinement policy from Unix privilege.

## Automated checks

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -v`,
2026-09-07: 19 tests pass. Coverage includes missing tools, denied commands
and paths, timeouts, partial evidence, disabled/inactive agents, empty and
broken checks, unknown verdicts, report escaping, stable content, private
permissions, exit codes, unsupported platforms, and Python 3.8 syntax parsing.

[UNVERIFIED] Python 3.8 runtime execution and repository-wide pre-commit/CI
checks have not run. Ruff is not available on PATH or in the searched local
tool caches; no dependencies were installed.

## Operator-supplied root run

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[UNKN] Config-management ownership: No known management evidence found. Presence does not prove enrollment, current policy, or console ownership. Custom agents and schedules are outside this inventory.
0 PASS, 0 FAIL, 0 WARN, 1 UNKN, 0 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-my7nyad1/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-my7nyad1/report.html
```

[VERIFIED: comparison of that supplied output with the non-root command above,
2026-09-07] The finding is identical in root and non-root modes. This is a
no-known-evidence result, not a permission failure. The pasted command output
is the provenance; the private root-owned report files were not independently
opened by the agent.

## Acceptance status

[VERIFIED: commands and operator transcript above, 2026-09-07] Check 1 now has
real root and non-root output, plus a deliberately exercised missing-binary
path. Its validation prerequisite is satisfied. This evidence accompanies the
first-check implementation; subsequent controls require their own live runs.

[ASSUMED] The enforcing/permissive acceptance case does not apply to this
presence inventory. When MAC/firewall/security controls are added, their
non-enforcing states will need their own `WARN` evidence.
