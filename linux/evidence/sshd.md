<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# SSH configuration validation — 2026-09-07

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator SSH validation'
```

[VERIFIED] Exact new finding, tally and report paths; exit code 0:

```text
[UNKN] SSH daemon configuration: sshd unavailable (exit 1): sshd: no hostkeys available -- exiting.
0 PASS, 0 FAIL, 1 WARN, 2 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-ne70auxm/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-ne70auxm/report.html
```

[UNVERIFIED] The host-key error alone cannot distinguish inaccessible keys
from missing keys. Fieldkit does not generate keys, alter permissions, or
substitute test keys. Root validation will provide additional evidence.

## Missing binary and policy cases

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator SSH missing-tool validation'
```

[VERIFIED] Exact new finding from that run:

```text
[UNKN] SSH daemon configuration: missing binary: sshd
```

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07: 50 tests pass. SSH fixtures cover restrictive global directives,
unrestricted root login, restricted root login, password authentication,
disabled public-key authentication, missing/duplicate/malformed directives,
missing binaries, and unavailable host keys. Review cases produce `WARN`.

[ASSUMED] The selected baseline is `PermitRootLogin=no`,
`PasswordAuthentication=no`, `PubkeyAuthentication=yes`. Restricted root
login and password authentication require contextual review, so they yield
`WARN`; unrestricted root login yields `FAIL`. This is a baseline decision,
not proof of a breach or a claim that every password login lacks MFA.

## Scope

[UNVERIFIED] This is the default on-disk global configuration parsed by sshd,
not proof of the configuration currently loaded by a running daemon.
Connection-specific Match rules and alternate `-f` paths are not evaluated.
PasswordAuthentication=no alone does not exclude keyboard-interactive
authentication or establish key-only login. The report states these limits.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[WARN] SSH daemon configuration: passwordauthentication=yes; permitrootlogin=no; pubkeyauthentication=yes. Scope: default on-disk global configuration parsed by sshd -T. Connection-specific Match rules, alternate daemon configurations and running-daemon reload state are not evaluated. PasswordAuthentication=no alone does not prove key-only login.
  -> Have the operator review root access and authentication policy, including Match rules and MFA; validate an alternate login before changes.
0 PASS, 0 FAIL, 2 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-ecc3nn36/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-ecc3nn36/report.html
```

[VERIFIED: comparison of the supplied output with the non-root run,
2026-09-07] Root successfully parsed the configuration; the unprivileged
invocation could not obtain usable host keys. The root result supplies a
real WARN case for enabled password authentication. Check 4 now has the
required root/non-root and deliberate missing-tool evidence. The private root
reports were not separately opened by the agent.
