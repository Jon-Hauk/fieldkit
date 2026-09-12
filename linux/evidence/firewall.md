<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Firewall-default validation — 2026-09-07

## Non-root execution

[VERIFIED] Command outside the execution sandbox, from the repository root,
2026-09-07:

```bash
linux/fieldkit-linux --client-name 'operator firewall validation'
```

[VERIFIED] Exact new finding, hint, tally and paths; exit code 0:

```text
[UNKN] Host firewall inbound defaults: nft: needs root to read; UFW: needs root to read
Some controls need root to read. Re-run with sudo to read this; Fieldkit never elevates itself.
1 PASS, 0 FAIL, 1 WARN, 3 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-7mitfjg0/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-7mitfjg0/report.html
```

## Deliberate missing-tool case

[VERIFIED] Command, 2026-09-07:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator firewall missing-tool validation'
```

[VERIFIED] Exact new finding:

```text
[UNKN] Host firewall inbound defaults: nft: missing binary: nft; UFW: missing binary: ufw
```

## Tests and interpretation

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-07: 71 tests pass. Firewall fixtures include dual-stack drop defaults,
IPv4-only defaults, empty rulesets, accept policies, unconditional accept,
conditional accept with explicit scope, malformed JSON/schema, UFW active
deny, inactive UFW, allow defaults, disabled IPv6, unreadable state, and missing
tools. Non-enforcing cases produce WARN and unavailable state produces UNKN.

[VERIFIED: web reference review, 2026-09-07] The
[nftables project's chain documentation](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
describes base-chain hooks and policies; the
[published JSON schema](https://manpages.ubuntu.com/manpages/jammy/man5/libnftables-json.5.html)
documents the chain and rule fields used here.

[UNVERIFIED] This is a default-policy inventory, not a packet-path proof.
Conditional rules, jumps, sets, other namespaces and remote reachability are
outside scope. UFW's reported default and IPv6 configuration do not establish
the complete effective kernel ruleset. Reports omit raw addresses, rule
names and counters. No rules, services or network settings are changed.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-07] Jon ran:

```bash
sudo /usr/bin/python3 -B \
  /home/operator/fieldkit/linux/fieldkit-linux \
  --client-name "operator root validation"
```

```text
[PASS] Host firewall inbound defaults: UFW reports active; incoming default=deny; configured IPv6=yes. Scope: UFW-reported default and configured IPv6 support; allow rules, kernel IPv6 state, other namespaces and reachability are not evaluated. nft observation: nft input base chains=0; IPv4+IPv6 drop defaults=not established; direct unconditional accept=not detected. Scope: input default policies and simple unconditional accepts only; conditional rules, jumps, sets, other namespaces and reachability are not evaluated.
2 PASS, 0 FAIL, 2 WARN, 1 UNKN, 1 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-gfkx2dls/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-gfkx2dls/report.html
```

[VERIFIED: comparison with the recorded non-root run, 2026-09-07] Root
exposes firewall defaults that the unprivileged run could not read. UFW
reports deny inbound; the nft input-chain inventory alone does not establish
that baseline. Root/non-root output, missing-tool UNKN and non-enforcing WARN
fixtures satisfy check 6's validation prerequisite. Private root reports were
not independently opened by the agent.
