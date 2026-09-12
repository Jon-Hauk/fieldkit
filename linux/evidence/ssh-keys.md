<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# SSH authorized-key validation — 2026-09-08

## Real non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator key validation'
```

[VERIFIED] Exact new finding, tally and report paths; exit code 0:

```text
[UNKN] SSH authorized-key inventory: /home/operator/.ssh/authorized_keys: owner=operator (uid 1001); keys=4; types=ssh-ed25519=4; weak=0; group/other-writable=no. Scope: local root/UID>=1000 homes and immediate /home directories; bounded recursive discovery without symlink traversal. RSA<2048 and DSA require review. Certificate/security-key records, sshd alternate key sources, key options and actual login acceptance are not evaluated. Key blobs and comments are omitted. Visibility gaps: /home/operator: needs root to read; /home/analyst/.ssh/authorized_keys2: needs root to read; /home/analyst/.ssh/authorized_keys: needs root to read; /home/analyst: needs root to read; /root/.ssh/authorized_keys2: needs root to read; /root/.ssh/authorized_keys: needs root to read; /root: needs root to read
1 PASS, 0 FAIL, 3 WARN, 8 UNKN, 2 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-2s2_4mlf/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-2s2_4mlf/report.html
```

## Deliberate unreadable-file case and fixtures

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 116 tests pass. A test creates an isolated authorized_keys file,
removes read permissions, confirms UNKN and the root hint, then restores
permissions and removes only its fixture directory. It skips under root.
Other fixtures cover quoted key options, comments, RSA sizes, DSA, Ed25519,
malformed wire records, nested discovery, redaction, missing and symlinked homes.

[VERIFIED] The initial live run incorrectly marked a nonexistent home as a
directory gap. The corrected code skips absent homes before recursive
discovery and avoids symlinked home roots; the final command above verifies
that correction, 2026-09-08.

[ASSUMED] RSA<2048 and DSA are review thresholds. File-owner mapping and
group/other write permissions provide evidence, not proof of exploitation.
[UNVERIFIED] Certificate/security-key records, SSH policy acceptance,
authorized-key options, nonlocal identity homes and alternate key sources are
outside scope. Discovery is capped at 100000 directory/file entries and uses
no symlink traversal. A capped scan remains unknown. No private-key contents,
public-key blobs, command options or comments appear in reports.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[INFO] SSH authorized-key inventory: /home/operator/.ssh/authorized_keys: owner=operator (uid 1001); keys=4; types=ssh-ed25519=4; weak=0; group/other-writable=no; /home/analyst/.ssh/authorized_keys: owner=analyst (uid 1000); keys=3; types=ssh-ed25519=3; weak=0; group/other-writable=no. Scope: local root/UID>=1000 homes and immediate /home directories; bounded recursive discovery without symlink traversal. RSA<2048 and DSA require review. Certificate/security-key records, sshd alternate key sources, key options and actual login acceptance are not evaluated. Key blobs and comments are omitted.
2 PASS, 0 FAIL, 5 WARN, 3 UNKN, 4 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-gnoa4tv7/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-gnoa4tv7/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08] Root
resolves directory visibility and adds analyst's three Ed25519 entries. Root/
non-root evidence and the deliberately unreadable-key UNKN test satisfy check
12's prerequisite. Private root reports were not independently opened by the
agent. Neither metadata count proves current login authorization.
