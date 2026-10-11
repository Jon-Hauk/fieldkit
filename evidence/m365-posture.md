# M365 posture offline evidence — 2026-09-13

[VERIFIED] The new collector, evaluator and report writer ran under Windows
PowerShell 5.1.26100.9444 in a temporary copy on the Windows worksite. This is
offline implementation evidence only. No real tenant was contacted.

## Commands and result

Executed over the existing SSH route on 2026-09-13, from the temporary copy:

```powershell
$ErrorActionPreference = 'Stop'
$PSVersionTable.PSVersion.ToString()
& powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0
$files = @(Get-ChildItem fieldkit -Recurse -File | Where-Object Extension -in '.ps1','.psm1')
$issues = @($files | ForEach-Object { Invoke-ScriptAnalyzer -Path $_.FullName -Severity Error })
if ($issues.Count) { $issues | Format-Table RuleName,ScriptName,Line,Message -AutoSize; exit 1 }
$files | Sort-Object FullName | ForEach-Object { Get-FileHash $_.FullName -Algorithm SHA256 }
```

[VERIFIED] The outer shell also used process-only `-ExecutionPolicy Bypass`.
The final complete test/lint wrapper exited 0 with no stderr. Output excerpts
below omit only the temporary directory from the test summary:

```text
5.1.26100.9444
PASS: pagination accumulates every page
PASS: empty collection remains a valid empty array
PASS: missing-scope endpoints never contacted
PASS: partial results discarded after a later page fails
PASS: tenant switch between pages aborts assessment
PASS: no request sent after session tenant switch
PASS: email-only registration does not imply MFA
PASS: duplicate assignments counted as one principal
PASS: group assignments are not mislabeled as human admins
PASS: report-only policy is not enforced
PASS: recent failed attempt does not reset successful-sign-in dormancy
PASS: string false is not coerced to a valid boolean
PASS: missing enabled-user report rows stay unknown
PASS: PSCustomObject responses supported
PASS: Markdown deterministic across input order and repeat export
PASS: reports omit raw object identifiers and license IDs
PASS: HTML encodes untrusted fields
PASS: Markdown escapes table separators
All 71 M365 assertions passed. No tenant contacted.
PSScriptAnalyzer 1.25.0: 3 files; 0 Error-severity findings.
```

[VERIFIED] SHA-256 hashes from that same clean Windows run:

```text
94143DDCC4DC23AC2EEE47C8BB3DCEEC7191B68C048953AB4B9B6A9AE80DE65A  fieldkit/checks/Test-M365Posture.ps1
8CC8227F05F85D5E25CBEE779B9F3004F6F99D4DDBB1FD2723654CF638728626  fieldkit/modules/FieldKit.Entra.psm1
5120976D40EA6C93362F03B94082FEF3521CB73DD7EF1738B56A71E5C6C4ED67  fieldkit/tests/Test-M365Posture.ps1
```

## Defects the first execution found

[VERIFIED: local commands, 2026-09-13] `git diff --check` passed;
`python3 ci/validate_coverage.py` reported 20 registered/20 tracked projects
and no manifest drift; `git ls-files '*.ps1' '*.psm1' '*.psd1' | wc -l`
reported 26, above the unchanged floor of 15. Local `sha256sum` matched
all three Windows hashes. Changes remain uncommitted; CI has not run.

[VERIFIED: the Windows commands above and source corrections, 2026-09-13]
The first request wrapper recursively resolved a callback parameter through
PowerShell dynamic scope; its owned test process was stopped and the helper
parameter renamed. The next run exposed empty/singleton array unrolling in
the property helper. Preserving property values and explicitly enumerating
collections corrected it. The initial lint wrapper lacked process execution
policy bypass and misleadingly printed a success line after import failure.
That run is not evidence; the final wrapper catches errors and repeats both
tests and lint. No machine-wide execution policy was changed.

## Oracle and remaining-work register

| Check | Offline evidence | Independent live oracle / limitation |
|---|---|---|
| MFA registration | True/false/missing/string booleans, missing rows, per-user aliases | [UNVERIFIED] Compare operator-owned portal inventory with report; P1/P2 reporting access is required. Full method types and privileged-role correlation remain unfinished. |
| Privileged roles | Duplicate assignments and group principal adversary | [UNVERIFIED] Portal active/eligible assignments and group-derived effective membership. No PIM collection or role-holder license/staleness evaluation yet. |
| Conditional Access | Report-only, enabled, unknown state and apparent defaults overlap | [UNVERIFIED] Licensed-tenant portal policy states; no effective-policy evaluation. |
| Security defaults | Missing flag, true flag and enabled CA overlap | [UNVERIFIED] Compare Graph boolean to portal setting. No claim about individual MFA enforcement. |
| Legacy authentication | Explicit UNKN finding | [UNVERIFIED] Service-level effective protocol collector and independent sign-in evidence remain unimplemented. |
| External sharing | Explicit UNKN finding | [UNVERIFIED] SharePoint/OneDrive sharing collector and portal oracle remain unimplemented. |
| Guests | Guest count, restrictive role, unknown role | [UNVERIFIED] Portal guest default plus a separately authorized guest enumeration test. Default role GUID mapping was checked against Microsoft documentation, not a live tenant. |
| Dormancy | Old successful activity despite recent attempted sign-in; null/invalid/future history | [UNVERIFIED] Historical successful activity on a licensed tenant. New-user history cannot prove elapsed dormancy. |
| Lab leftovers | None | [UNVERIFIED] Independent inventory, ownership ledger and guarded live Up/Down remain unfinished. |

[UNVERIFIED] SDK authentication, actual delegated permissions/reader roles,
zero-disk authentication persistence, full live entry-point execution, and
GitHub Actions have not been exercised. Fixture coverage is not exhaustive
for every future Graph response or branch. This is a working offline
milestone, not the completed Weekender or a tenant-security assessment.

## Judge

[ASSUMED: prioritization] Preserve existing authentication and security
defaults. Finish privileged identity/MFA correlation and obtain authorized
live read evidence before adding mutation code. Treat licensing and missing
history as visibility limits; leave legacy-auth and external-sharing results
unknown until their actual service paths can be collected. Keep lab creation
and deletion disabled until ownership and independent leftover auditing are
implemented. This prioritizes reliable identity findings without weakening
an existing tenant to make a demonstration work.
