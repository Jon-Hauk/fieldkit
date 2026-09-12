<!--
Redacted for publication. This file records a real run on the author's own
Linux host; the machine name, account names, home directory paths and the
tailnet address have been replaced with placeholders (example-host, operator,
analyst, 100.64.0.1). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original run.
-->

# Socket-binding validation — 2026-09-08

## Non-root run

[VERIFIED] Command from repository root, 2026-09-08:

```bash
linux/fieldkit-linux --client-name 'operator sockets validation'
```

[VERIFIED] Exact report row:

| INFO | Listening socket bindings | TCP listening / UDP unconnected bindings=18\. tcp 0\.0\.0\.0:111 \[IPv4 wildcard\]; tcp 0\.0\.0\.0:22 \[IPv4 wildcard\]; tcp 100.64.0.1:41935 \[interfaces=tailscale0\]; tcp 127\.0\.0\.1:35631 \[loopback\]; tcp 127\.0\.0\.1:43105 \[loopback\]; tcp 127\.0\.0\.53%lo:53 \[loopback\]; tcp \[::\]:111 \[IPv6 wildcard\]; tcp \[::\]:22 \[IPv6 wildcard\]; udp \*:111 \[wildcard \(family unspecified\)\]; udp \*:41641 \[wildcard \(family unspecified\)\]; udp \*:47197 \[wildcard \(family unspecified\)\]; udp \*:5353 \[wildcard \(family unspecified\)\]; udp 0\.0\.0\.0:111 \[IPv4 wildcard\]; udp 0\.0\.0\.0:37086 \[IPv4 wildcard\]; udp 0\.0\.0\.0:41641 \[IPv4 wildcard\]; udp 0\.0\.0\.0:5353 \[IPv4 wildcard\]; udp 0\.0\.0\.0:67 \[IPv4 wildcard\]; udp 127\.0\.0\.53:53 \[loopback\]\. Scope: current network namespace, TCP listeners and unconnected UDP sockets; interface mapping uses local address equality, not SO\_BINDTODEVICE\. tailscale0 is an interface name, not proof of overlay\-only access\. Wildcard IPv6 dual\-stack behavior, firewall/NAT policy, other namespaces, process ownership and remote reachability are not evaluated\. No connection probes are sent\. |

[VERIFIED] Exit code 0; tally: `1 PASS, 0 FAIL, 3 WARN, 11 UNKN, 4 INFO`.
Reports: `fieldkit/reports/example-host-linux-s9xidp16/report.md` and sibling `report.html`.

## Deliberate missing-tool run

[VERIFIED] Command from repository root, 2026-09-08:

```bash
PATH=/nonexistent /usr/bin/python3 -B linux/fieldkit-linux --client-name 'operator sockets missing-tool validation'
```

[VERIFIED] Exact report row:

| UNKN | Listening socket bindings | missing binary: ss |

[VERIFIED] Exit code 0; tally: `0 PASS, 0 FAIL, 1 WARN, 16 UNKN, 2 INFO`.
Reports: `fieldkit/reports/example-host-linux-kzb295rs/report.md` and sibling `report.html`.

## Fixtures and scope

[VERIFIED] `python3 -B -m unittest discover -s linux/tests -q`,
2026-09-08: 131 tests pass. Socket fixtures exercise IPv4/IPv6 wildcard and
loopback bindings, scoped IPv6 interface matching, tailnet address mapping,
malformed output, missing commands, denied interface metadata, empty results
and deterministic ordering.

[ASSUMED] Interface names and equal local addresses are inventory evidence;
they do not establish SO_BINDTODEVICE or authenticated overlay membership.
[UNVERIFIED] Remote reachability, firewall/NAT policy, other namespaces,
process ownership and IPv6 wildcard dual-stack behavior are outside scope.

## Root validation

[VERIFIED: operator-supplied console output, 2026-09-08] Command:

```bash
sudo /usr/bin/python3 -B /home/operator/fieldkit/linux/fieldkit-linux --client-name "operator root validation"
```

```text
[INFO] Listening socket bindings: TCP listening / UDP unconnected bindings=18. tcp 0.0.0.0:111 [IPv4 wildcard]; tcp 0.0.0.0:22 [IPv4 wildcard]; tcp 100.64.0.1:41935 [interfaces=tailscale0]; tcp 127.0.0.1:35631 [loopback]; tcp 127.0.0.1:43105 [loopback]; tcp 127.0.0.53%lo:53 [loopback]; tcp [::]:111 [IPv6 wildcard]; tcp [::]:22 [IPv6 wildcard]; udp *:111 [wildcard (family unspecified)]; udp *:41641 [wildcard (family unspecified)]; udp *:47197 [wildcard (family unspecified)]; udp *:5353 [wildcard (family unspecified)]; udp 0.0.0.0:111 [IPv4 wildcard]; udp 0.0.0.0:37086 [IPv4 wildcard]; udp 0.0.0.0:41641 [IPv4 wildcard]; udp 0.0.0.0:5353 [IPv4 wildcard]; udp 0.0.0.0:67 [IPv4 wildcard]; udp 127.0.0.53:53 [loopback]. Scope: current network namespace, TCP listeners and unconnected UDP sockets; interface mapping uses local address equality, not SO_BINDTODEVICE. tailscale0 is an interface name, not proof of overlay-only access. Wildcard IPv6 dual-stack behavior, firewall/NAT policy, other namespaces, process ownership and remote reachability are not evaluated. No connection probes are sent.
2 PASS, 0 FAIL, 6 WARN, 4 UNKN, 7 INFO
Report: /home/operator/fieldkit/reports/example-host-linux-cukfmbm5/report.md
Report: /home/operator/fieldkit/reports/example-host-linux-cukfmbm5/report.html
```

[VERIFIED: comparison with the recorded non-root command, 2026-09-08]
The socket finding matches exactly. Root/non-root evidence and deliberate
missing-tool UNKN satisfy check 15's acceptance requirement. Root-owned report
files were not independently opened.
