<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Persistence inventory validation — 2026-09-07

## Non-root run

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator persistence validation'
```

[VERIFIED] The full generated Markdown is retained in
[persistence-nonroot.md](persistence-nonroot.md). The live inventory contains
575 paths: 467 package-owned and 108 unowned. Restricted local homes and the
cron spool produce visibility gaps, so the verdict is UNKN. Unowned paths
include enablement symlinks; they are review candidates, not malware claims.

## Deliberate missing-tool case

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator persistence missing-tool validation'
```

[VERIFIED] The generated Markdown is retained in
[persistence-missing-tool.md](persistence-missing-tool.md). It reports 575
inventoried paths, 575 unresolved ownership classifications and `missing
binary: dpkg-query`. Missing visibility does not become an unowned finding.

## What failed and was corrected

[VERIFIED] The initial test/live runs of the commands above, 2026-09-07,
queried the package database once per path and ran too slowly. Those two
agent-started processes were interrupted with Ctrl-C. The collector originally
printed a KeyboardInterrupt traceback; the entry point now handles interruption
with a short message and exit 130. Ownership queries now use bounded directory
patterns and cache the resulting exact-path sets for the current run.

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07: 77 tests pass. Persistence fixtures cover unit/timer/drop-in files,
cron, rc.local, local user units, exact ownership, unowned WARN, owned INFO,
incomplete-visibility UNKN, missing tools, and directory-query caching.

[UNVERIFIED] Package provenance and content integrity are not verified.
Symlinked directories and transient in-memory units are outside scope. Only
the first 40 unowned paths are displayed, regular files before symlinks; counts
include all collected classifications. The 2000-file scan limit produces an
explicit visibility gap. The enforcing/permissive distinction does not apply
to a persistence-path inventory. Full repository CI remains unverified.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

[VERIFIED: that supplied output, 2026-09-08] The finding was WARN with
`Persistence files inventoried=575; package-owned=467; not package-owned=108;
ownership unresolved=0`. The 40 review paths and scope text match the
[non-root report](persistence-nonroot.md), with its three visibility gaps
absent. The root run added this remediation:

```text
  -> Have the operator reconcile non-package-owned persistence paths with approved local changes; investigate unknown entries before removal.
2 PASS, 0 FAIL, 3 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-4ymauzdk/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-4ymauzdk/report.html
```

[VERIFIED: comparison of supplied output with the recorded non-root run,
2026-09-08] Root removes the restricted-home and cron-spool visibility gaps.
Counts and review paths remain unchanged. Root/non-root evidence, missing-tool
UNKN and unowned-path WARN fixtures satisfy check 7's prerequisite. Private
root reports were not independently opened by the agent.
