<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# MAC enforcement validation — 2026-09-07

## Real non-root and non-enforcing case

[VERIFIED] Command, from `/home/operator/fieldkit`, outside the execution
sandbox, 2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator MAC validation'
```

[VERIFIED] Exact new finding, remediation, tally and report paths from that
command; exit code 0:

```text
[WARN] MAC framework enforcement: SELinux global mode: permissive (not enforcing)
  -> Have the operator review workload policy coverage and validate an enforcing AppArmor or SELinux policy before changing host configuration.
0 PASS, 0 FAIL, 1 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-x9aw_ptw/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-x9aw_ptw/report.html
```

[VERIFIED] This exercises the required non-enforcing `WARN` case on the real
host, without changing host configuration. The direct probes
`cat /sys/fs/selinux/enforce` and `cat /sys/kernel/security/lsm` also returned
`0` and `capability,yama,selinux`, respectively, 2026-09-07.

## Unknown and fixture coverage

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -v`,
2026-09-07: 42 tests pass. The real unreadable-file test creates an isolated
temporary LSM-list fixture, removes its read permissions, and runs the
collector as the unprivileged user. It asserts `UNKN "needs root to read"`.
The test restores permissions and removes only its temporary files. It skips
this permission test under root, which could otherwise bypass those bits.

[VERIFIED] The same test command covers AppArmor enforce, complain, kill,
unconfined, prompt, empty and unknown profile modes; SELinux enforcing,
permissive and malformed values; inactive frameworks; and partial visibility.
The unreadable active-framework case cannot silently produce `PASS`.

## Interpretation and references

[VERIFIED: reference review via web search, 2026-09-07] The
[kernel AppArmor documentation](https://kernel.org/doc/html/latest/admin-guide/LSM/apparmor.html)
distinguishes loaded policy from unconfined workloads. The
[AppArmor technical documentation](https://sources.debian.org/src/apparmor/2.11.0-3%2Bdeb9u2/parser/techdoc.pdf/)
describes the securityfs profile list with enforce/complain suffixes.
The [SELinux project's policy troubleshooting guide](https://github.com/SELinuxProject/selinux/wiki/Fix-Policy-Problems)
distinguishes enforcing and permissive operation. The local `aa-status --help`
output, 2026-09-07, also identifies kill-mode profiles as enforcing and
special-unconfined profiles as non-enforcing.

[UNVERIFIED] Workload coverage and SELinux per-domain permissive exceptions
are outside this check. Missing kernel interfaces remain unknown, including
when securityfs is hidden or unmounted. The collector never mounts it or
changes policy to obtain visibility. Python 3.8 runtime execution and full
repository CI remain unverified.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[WARN] MAC framework enforcement: SELinux global mode: permissive (not enforcing)
  -> Have the operator review workload policy coverage and validate an enforcing AppArmor or SELinux policy before changing host configuration.
0 PASS, 0 FAIL, 1 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-krp471f6/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-krp471f6/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-07] Root
and non-root MAC findings match. Check 3 has root/non-root evidence, a real
non-enforcing WARN case, and a deliberate unreadable-file UNKN test. Its
validation prerequisite is satisfied. Root report contents were not separately
read by the agent; the supplied console transcript is the evidence.
