# fieldkit

**Read-only Windows diagnostics for client engagements.** Run one command on an
unfamiliar machine, hand the client one report.

42 checks across system inventory, network fault isolation, and a security
baseline. Windows PowerShell 5.1, no dependencies, nothing installed on the
target machine and nothing on it modified.

Built for freelance and MSP work: arrive, establish ground truth, leave a
document that justifies the invoice.

## Quick start

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-FieldKit.ps1 -ClientName "Northgate Dental"
```

Two files land in `reports\`: an HTML report to send the client, and a
Markdown copy to keep. The Markdown diffs cleanly between visits, which is how
you show what actually changed since last time.

Run elevated for a complete picture. Unelevated works fine and reports `UNKN`
for the handful of controls it cannot read.

## Sample output

```
Security baseline - WORKSTATION-04

Malware defence
  [PASS] Defender real-time protection          real-time=True
  [PASS] Antivirus signature age                0 day(s) old
Host hardening
  [PASS] Firewall on (all profiles)             Domain, Private, Public
  [UNKN] BitLocker on system drive              needs admin to read
         -> re-run as Administrator to read this
Remote access and exposure
  [WARN] Services listening on all interfaces   listening wide: 22, 135
         -> Bind to 127.0.0.1 or a VPN interface, or firewall these
Patching
  [PASS] Last successful update                 2026-08-12 (3 days ago)

17 checks: 11 pass, 0 fail, 1 warn, 4 unknown, 1 informational
```

Each run also writes a self-contained HTML report to hand the client, and a
Markdown copy to keep - which diffs cleanly between visits, so you can show
what actually changed since last time.

## What is in the kit

| Script | Answers |
|---|---|
| `checks\Get-SystemSnapshot.ps1` | What is this machine, how long has it been up, is the disk dying |
| `checks\Test-NetworkHealth.ps1` | Which hop is broken - adapter, DHCP, gateway, DNS, or upstream |
| `checks\Test-SecurityBaseline.ps1` | Twenty findings that actually come up on SMB endpoints |
| `Invoke-FieldKit.ps1` | All of the above, one report |

Each check also runs standalone and writes its own report:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\checks\Test-NetworkHealth.ps1
```

## Rules this kit follows

**Read-only, always.** Nothing here modifies the target host. The only thing
written is the report. This is not politeness - it is what lets you say, at
the end of a visit, that everything still broken was broken when you arrived.

**`UNKN` is not `FAIL`.** A control that cannot be read reports unknown. A
tool that reports false failures gets ignored, and then the real finding gets
ignored along with it.

**Windows PowerShell 5.1.** No ternary, no `??`, no `&&`, no `-AsHashtable`.
Client machines run 5.1 far more often than 7.x, and a parser error on arrival
is not the first impression you want.

**ASCII source only.** PowerShell 5.1 reads `.ps1` and `.psm1` as the system
ANSI codepage unless there is a BOM, so a UTF-8 em-dash becomes mojibake and
then a parse error. Keeping the source to ASCII removes the dependency on a
BOM surviving every copy, paste and email attachment. Check before committing:

```powershell
Get-ChildItem -Recurse -Include *.ps1,*.psm1 | ForEach-Object { $n=$_.FullName; [System.IO.File]::ReadAllText($n).ToCharArray() | Where-Object { [int]$_ -gt 127 } | ForEach-Object { "$n : U+{0:X4}" -f [int]$_ } }
```

## Traffic that leaves the machine

Only `Test-NetworkHealth.ps1` sends anything, and only this:

- the host's own default gateway (ICMP)
- `1.1.1.1` (ICMP)
- the host's own configured DNS servers (a query for `www.microsoft.com`)
- `https://www.microsoft.com` (GET, proves TLS egress works)
- `http://www.msftconnecttest.com/connecttest.txt` (GET, detects a captive portal)

No client data is transmitted. Pass `-NoInternet` to keep the run entirely on
the local network, which is the right call on an air-gapped or sensitive site.

## Before you run this on someone else's network

Get the engagement in writing first. Scanning and enumeration on a network you
do not own is the kind of thing that is fine right up until it is not, and a
one-line email confirming scope is enough. `Test-NetworkHealth.ps1` is the
only script that touches the network at all, and even that is limited to the
hosts listed above - but the authorization matters more than the packet count.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No `FAIL` findings |
| 1 | At least one `FAIL` |
| 2 | The sweep could not complete |

Suitable for driving from a scheduler or RMM, where a non-zero code raises the
ticket.

## Adding a check

Checks share one harness, so a new one is a few lines. Group it with
`Set-FieldKitSection`, then:

```powershell
Test-Control 'Short imperative name' {
    $thing = Get-Something -ErrorAction SilentlyContinue
    if (-not $thing) { return Unknown 'not readable here' }
    Verdict ($thing.IsGood) ("state={0}" -f $thing.State)
} 'The command or action that fixes it'
```

Return `Pass`, `Fail`, `Warn`, `Unknown`, `Info`, or `Verdict $bool "detail"`.
The remediation string is shown only under `FAIL` and `WARN` - write it as the
action to take, not a restatement of the problem.

Two things worth doing every time:

- Run it unelevated as well as elevated. Half of these controls read
  differently, and the unelevated path is the one that ships broken.
- Point it at a machine where you know the answer, and confirm it reports the
  answer you know. A check that has never disagreed with you has not been
  tested.

## Reports

`reports\` is gitignored. Client findings should not end up in version
control - name the machine, the software it runs and the holes in it, and you
have written a target package.

## License

Apache-2.0. See [LICENSE](LICENSE).

Chosen over MIT for the explicit patent grant, which is what makes this
adoptable inside a company rather than only readable. Note what the licence
does and does not do: it disclaims warranty on the code, and it is not a
substitute for an engagement agreement when you run this on someone else's
network. See "Before you run this on someone else's network" above.
