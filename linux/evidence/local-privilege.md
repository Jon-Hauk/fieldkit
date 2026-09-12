<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Local privilege validation — 2026-09-08

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator privilege validation'
```

[VERIFIED] Exact new findings, tally and report paths; exit code 0:

```text
[INFO] Local privileged accounts: Local UID 0 accounts=[root]; privilege-related groups: sudo=[operator, analyst]. Scope: local passwd/group files, including primary group membership; directory identities and effective sudo authorization are not evaluated.
[UNKN] Sudo policy inventory: Sudoers files inspected/attempted=1; grant candidates=0; authentication-bypass candidates=0. Scope: local sudoers and resolved includes; candidate locations only. Aliases, tag scope/overrides, comments within entries, command restrictions, directory policy and effective user authorization are not evaluated. Visibility gaps: /etc/sudoers: needs root to read
1 PASS, 0 FAIL, 3 WARN, 7 UNKN, 2 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-30i7fi74/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-30i7fi74/report.html
```

## Deliberate unreadable-file case and fixtures

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 109 tests pass. The real unreadable-sudoers test creates an isolated
temporary file, removes its read permissions and confirms UNKN with a root
hint. It restores permission and removes only its test directory afterward.
This test skips when run as root, which can bypass file mode bits.

[VERIFIED] The same command tests duplicate UID 0 FAIL, primary and
supplementary group membership, local includes, ignored include-directory
backup files, NOPASSWD/!authenticate WARN, comments, include cycles and
credential-safe source-location output.

[UNVERIFIED] This is not a sudoers policy evaluator. Aliases, command scope,
tag overrides, inline comment semantics, directory policy and effective user
authorization are not resolved. Include paths with host expansion or parent
traversal produce unknown; recursion is limited to 64 files. No shadow file,
password hash or command arguments are collected.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[INFO] Local privileged accounts: Local UID 0 accounts=[root]; privilege-related groups: sudo=[operator, analyst]. Scope: local passwd/group files, including primary group membership; directory identities and effective sudo authorization are not evaluated.
[INFO] Sudo policy inventory: Sudoers files inspected/attempted=2; grant candidates=3; authentication-bypass candidates=0. Grant locations: /etc/sudoers:44; /etc/sudoers:47; /etc/sudoers:50. Scope: local sudoers and resolved includes; candidate locations only. Aliases, tag scope/overrides, comments within entries, command restrictions, directory policy and effective user authorization are not evaluated.
2 PASS, 0 FAIL, 5 WARN, 3 UNKN, 3 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-s6sh2a7x/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-s6sh2a7x/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08] Account
metadata matches. Root resolves the sudoers visibility gap and exposes three
grant candidates without authentication-bypass candidates. Root/non-root
evidence and the deliberately unreadable-file UNKN test satisfy check 11's
prerequisite. Private root reports were not independently opened by the agent.
