<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Disk encryption validation — 2026-09-08

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator disk validation'
```

[VERIFIED] Exact new findings, tally and report paths; exit code 0:

```text
[WARN] Root and data disk encryption: /: no LUKS layer observed. Scope: lsblk-reported mounted block-device ancestry; boot, loop and optical devices excluded. Unmounted volumes, alternate mounts, network/overlay filesystems, file-level/hardware encryption and cipher strength are not evaluated.
  -> Have the operator review root/data encryption coverage and plan recovery and backups before any disk-encryption changes.
[UNKN] Encryption key escrow: Key escrow cannot be established from host encryption metadata. Obtain operator evidence of recovery-key custody, authorized access and a tested recovery procedure. No keys or recovery material are collected.
1 PASS, 0 FAIL, 3 WARN, 5 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-i44bq3gj/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-i44bq3gj/report.html
```

## Deliberate missing-tool run

[VERIFIED] Command, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator disk missing-tool validation'
```

[VERIFIED] Exact disk finding:

```text
[UNKN] Root and data disk encryption: missing binary: lsblk
```

## Tests and scope

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 94 tests pass. Disk fixtures cover LUKS-backed root PASS, plain
root/data WARN, ambiguous crypt mapping UNKN, missing root/type information,
excluded boot/loop volumes, malformed device trees, missing binaries, and the
separate escrow unknown. The collector invokes only lsblk's metadata listing.

[UNVERIFIED] Root's missing LUKS layer is not proof that every possible
encryption mechanism is absent. File-level/hardware encryption, unmounted
volumes, alternate mounts, network/overlay filesystems and cipher strength
remain outside scope. Key custody cannot be inferred from host metadata.
Encryption and recovery material are never changed or collected.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[WARN] Root and data disk encryption: /: no LUKS layer observed. Scope: lsblk-reported mounted block-device ancestry; boot, loop and optical devices excluded. Unmounted volumes, alternate mounts, network/overlay filesystems, file-level/hardware encryption and cipher strength are not evaluated.
  -> Have the operator review root/data encryption coverage and plan recovery and backups before any disk-encryption changes.
[UNKN] Encryption key escrow: Key escrow cannot be established from host encryption metadata. Obtain operator evidence of recovery-key custody, authorized access and a tested recovery procedure. No keys or recovery material are collected.
2 PASS, 0 FAIL, 5 WARN, 2 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-9j7st5yb/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-9j7st5yb/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08] Disk
and escrow findings match. Root/non-root evidence, missing-tool UNKN and plain
filesystem WARN cases satisfy check 9's validation prerequisite. Private root
reports were not independently opened by the agent. Escrow remains unknown;
root access is not evidence of recovery-key custody.
