<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Removable-storage validation — 2026-09-08

## Live non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator USB validation'
```

[VERIFIED] Exact new finding, tally and report paths; exit code 0:

```text
[UNKN] Removable-storage controls: udev storage-deauthorization candidates=0. Scope: USBGuard runtime defaults and narrow udev rule signatures. USBGuard allow exceptions, existing-device policy, udev rule execution, UAS devices and actual removable-media access are not established. Candidate rules do not prove effective blocking. Visibility gaps: USBGuard: missing binary: usbguard
1 PASS, 0 FAIL, 3 WARN, 6 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-w_1qr62h/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-w_1qr62h/report.html
```

## Deliberate missing-tool run

[VERIFIED] Command, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator USB missing-tool validation'
```

[VERIFIED] This returned the identical removable-storage UNKN finding above.
The tool was also missing in the normal run; neither case triggered an install.

## Tests and interpretation

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 101 tests pass. Removable-storage fixtures cover blocking-rule
candidates, comments/unrelated rules, restrictive runtime defaults as INFO,
permissive defaults as WARN, missing tools and permission denial as UNKN, and
same-name udev rule overrides. No command mutates devices or policy.

[VERIFIED: web reference review, 2026-09-08] The
[USBGuard manual](https://github.com/USBGuard/usbguard/blob/main/doc/man/usbguard.1.adoc)
documents read-only `get-parameter` queries for ImplicitPolicyTarget and
InsertedDevicePolicy. The
[USBGuard configuration documentation](https://usbguard.github.io/documentation/configuration)
distinguishes runtime/default policy from handling already-present devices.

[UNVERIFIED] Default policy is not full enforcement proof: allow exceptions,
already-connected devices, UAS, and actual udev execution are outside scope.
The scanner recognizes direct mass-storage/authorization patterns only; a
different control could exist. Missing USBGuard is unknown, not a failed
control or authorization to install it.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[UNKN] Removable-storage controls: udev storage-deauthorization candidates=0. Scope: USBGuard runtime defaults and narrow udev rule signatures. USBGuard allow exceptions, existing-device policy, udev rule execution, UAS devices and actual removable-media access are not established. Candidate rules do not prove effective blocking. Visibility gaps: USBGuard: missing binary: usbguard
2 PASS, 0 FAIL, 5 WARN, 3 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-xb181c58/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-xb181c58/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08]
Removable-storage findings match. Root does not resolve the absent USBGuard
binary. Root/non-root evidence, deliberately missing-tool UNKN and permissive
WARN fixtures satisfy check 10's prerequisite. Private root reports were not
independently opened by the agent.
