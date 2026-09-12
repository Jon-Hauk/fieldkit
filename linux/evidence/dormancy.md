<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Dormancy and leftover-key validation — 2026-09-08

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator dormancy validation'
```

[VERIFIED] Exact new finding, tally and paths; exit code 0:

```text
[UNKN] Dormant accounts and leftover keys: Dormancy review threshold=90 days. operator: login within threshold; analyst: login within threshold. Scope: local accounts with shells listed in /etc/shells and immediate orphan-home candidates. Missing/old lastlog records do not prove inactivity or offboarding; key presence does not prove accepted login. Nested/alternate key sources, directory accounts and account-lock state are not evaluated. Visibility gaps: root: needs root to read
1 PASS, 0 FAIL, 3 WARN, 9 UNKN, 2 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-i2r4pd4c/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-i2r4pd4c/report.html
```

## Deliberate missing-tool case

[VERIFIED] Command, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator dormancy missing-tool validation'
```

[VERIFIED] Exact new finding:

```text
[UNKN] Dormant accounts and leftover keys: Dormancy review threshold=90 days. No account login state established. Scope: local accounts with shells listed in /etc/shells and immediate orphan-home candidates. Missing/old lastlog records do not prove inactivity or offboarding; key presence does not prove accepted login. Nested/alternate key sources, directory accounts and account-lock state are not evaluated. Visibility gaps: operator: missing binary: lastlog; analyst: missing binary: lastlog; root: missing binary: lastlog
```

## Tests and scope

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 120 tests pass. Dormancy fixtures cover recent/old/no-record
lastlog data, malformed and future timestamps, stale-account key correlation,
orphan-home key candidates, and missing binaries. No accounts or keys change.

[ASSUMED] Ninety days is a configurable review threshold (`--dormant-days`),
not a universal offboarding policy. Missing lastlog data does not prove an
account was never used. A key entry does not prove the server accepts it.
[UNVERIFIED] Nested/alternate key sources, directory accounts, account locks,
and the business status of account owners are outside this correlation.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[WARN] Dormant accounts and leftover keys: Dormancy review threshold=90 days. operator: login within threshold; analyst: login within threshold; root: no recorded login; conventional authorized-key entries=0. Scope: local accounts with shells listed in /etc/shells and immediate orphan-home candidates. Missing/old lastlog records do not prove inactivity or offboarding; key presence does not prove accepted login. Nested/alternate key sources, directory accounts and account-lock state are not evaluated.
  -> Have the operator confirm account ownership and login evidence, then review leftover keys before any offboarding changes.
2 PASS, 0 FAIL, 6 WARN, 3 UNKN, 4 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-dwi690eq/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-dwi690eq/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08] Root
removes the correlation visibility gap. Operator and analyst remain within the
threshold; root has no recorded login and no conventional key entries. Root/
non-root evidence and the missing-tool UNKN case satisfy check 13's prerequisite.
The WARN is an account-review candidate, not proof that root should be removed.
Private root reports were not independently opened by the agent.
