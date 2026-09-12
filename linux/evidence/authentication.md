<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Authentication inventory validation — 2026-09-08

## Real non-root run

[VERIFIED] Command from the repository root, 2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator authentication validation'
```

[VERIFIED] Exact report rows:

| UNKN | Directory enrollment evidence | SSSD running=no\. Scope: local SSSD service and realmd realm\-list evidence; tenant names are omitted\. Directory reachability, trust health, active enrollment, user authentication and MFA policy are not verified; no directory login or join is attempted\. Visibility gaps: realmd: missing binary: realm |
| INFO | PAM MFA inventory | Recognized PAM MFA references: none observed\. Scope: local PAM file references only; service selection, include/control flow, enrollment and actual MFA enforcement are not established\. External/SSSD MFA and SSH hardware\-key user verification are outside scope\. |
| UNKN | SSH authentication methods | sshd unavailable \(exit 1\): sshd: no hostkeys available \-\- exiting\. |

Report: `fieldkit/reports/example-host-linux-hh1omd3k/report.md`. Exit code 0.

## Deliberate missing-tool run

[VERIFIED] Command from the repository root, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator authentication missing-tool validation'
```

[VERIFIED] Exact report rows:

| UNKN | Directory enrollment evidence | No directory\-integration state established\. Scope: local SSSD service and realmd realm\-list evidence; tenant names are omitted\. Directory reachability, trust health, active enrollment, user authentication and MFA policy are not verified; no directory login or join is attempted\. Visibility gaps: SSSD: missing binary: systemctl; realmd: missing binary: realm |
| INFO | PAM MFA inventory | Recognized PAM MFA references: none observed\. Scope: local PAM file references only; service selection, include/control flow, enrollment and actual MFA enforcement are not established\. External/SSSD MFA and SSH hardware\-key user verification are outside scope\. |
| UNKN | SSH authentication methods | missing binary: sshd |

Report: `fieldkit/reports/example-host-linux-mswj4qf5/report.md`. Exit code 0.

## Tests and limits

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 125 tests pass. Fixtures cover PAM reference redaction and relaxed
controls, commented modules, SSH non-key authentication paths, incomplete
output, directory-name omission and missing binaries.

[UNVERIFIED] Module presence does not prove MFA enforcement or enrollment.
Global SSH settings do not establish Match-specific or running-daemon policy.
Directory evidence does not establish active enrollment or trust health.

## Root validation

[VERIFIED: operator-supplied output, 2026-09-08] Command:

```bash
sudo /usr/bin/python3 -B /home/operator/fieldkit/linux/fieldkit-linux --client-name "operator root validation"
```

```text
[INFO] PAM MFA inventory: Recognized PAM MFA references: none observed. Scope: local PAM file references only; service selection, include/control flow, enrollment and actual MFA enforcement are not established. External/SSSD MFA and SSH hardware-key user verification are outside scope.
[INFO] SSH authentication methods: pubkeyauthentication=yes; passwordauthentication=yes; kbdinteractiveauthentication=no; gssapiauthentication=no; hostbasedauthentication=no; authenticationmethods=any; global key-only configuration=not established. Scope: default on-disk global sshd configuration; Match rules, alternate configs, running-daemon state and successful authentication are not verified. Key-only login is not proof of MFA or hardware-key user verification.
[UNKN] Directory enrollment evidence: SSSD running=no. Scope: local SSSD service and realmd realm-list evidence; tenant names are omitted. Directory reachability, trust health, active enrollment, user authentication and MFA policy are not verified; no directory login or join is attempted. Visibility gaps: realmd: missing binary: realm
2 PASS, 0 FAIL, 6 WARN, 4 UNKN, 6 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-m40x906y/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-m40x906y/report.html
```

[VERIFIED: comparison with non-root evidence above, 2026-09-08] Root resolves
SSH configuration visibility. PAM and directory findings match. The root
report files were not independently opened.
