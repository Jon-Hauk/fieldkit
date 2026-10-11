<!--
Redacted for publication. This file records real runs in the author's own lab;
host names, account names, home directory paths and tenant identifiers have
been replaced with placeholders (operator, example-host, analyst, 100.64.0.x,
example-tenant). Verdicts, counts, command lines, scope statements and
limitations are unchanged from the original runs.
-->

# M365 gate evidence

[VERIFIED: Windows PowerShell 5.1, 2026-09-14] From an isolated Git checkout
on Windows, executed:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
```

Pester 3.4.0 output for B4:

```text
Describing B4 local storage and seven-day retention
 [+] sets a UTC deadline seven days after this run and never renews an old run
 [+] blocks collection until expired data is swept and preserves signatures and unexpired data
 [+] refuses malformed and extended deadlines without deleting data
 [+] does not trust a manifest planted beside the signed pack
 [+] rejects git ancestry including a worktree marker file
 [+] rejects every prohibited sync path and a custom OneDrive root
 [+] rejects an engagement record outside OutputRoot and alternate data streams
 [+] refuses a concurrent run or sweep
 [+] does not traverse a junction during manifest discovery or cleanup
Passed: 9 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
```

The tested source arrived via Git objects (`git pack-objects`, remote
`git unpack-objects`, `git read-tree`, `git checkout-index`). All data was
synthetic, created beneath a unique test directory. No tenant was contacted.
The signed operator record and authorization dates were not accessed or changed.

Each assessment run receives `raw/run-<guid>/manifest.json`, with a UTC
`createdAtUtc` and immutable `deleteBy` seven days later. An expired run blocks
new collection across the entire OutputRoot. `Invoke-FieldKit.ps1 -Sweep
-OutputRoot <private-root>` removes only expired run directories, preserving
the engagement files and other runs. Discovery rejects Git markers and links
before recursion. Malformed manifests stop cleanup. Partial deletion retains
the manifest until data is gone. A shared root lock serializes run creation
and sweep. This is explicit cleanup, not an installed background scheduler.

[UNVERIFIED] Local Pester and commit hooks are not GitHub CI. PR checks must
run on the pushed revision. Full live-assessment gates, lab provisioning,
independent live oracles and teardown evidence remain required.

## B6 transport and CI boundary

[VERIFIED: Windows PowerShell 5.1, 2026-09-14] Executed from the next staged
Git tree, using the same Git transport:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
```

```text
Passed: 17 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 15 tracked PowerShell files; no tracked raw output.
All 75 M365 assertions passed. No tenant contacted.
```

The first scanner run falsely identified a local stream method as a write
scope. The regex was corrected and a regression case added; all three
commands above were then rerun successfully. Negative controls cover write
verbs, module-qualified commands, stored-credential options, probing hosts,
dynamic/non-GET methods and splatting at the sole SDK request site. The
scope allowlist now lives in `FieldKit.M365.psm1`; the existing Entra module
delegates to it. A pagination URL must retain both its origin and resource.

## B7 request ceiling and throttling

[VERIFIED: same three Windows commands above, 2026-09-14]

```text
Passed: 24 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 15 tracked PowerShell files; no tracked raw output.
All 75 M365 assertions passed. No tenant contacted.
```

The new cases exercise 429 delta-seconds Retry-After, 503 fallback delays
of 1/2/4/8/16 seconds, HTTP-date recovery, five-retry exhaustion, retries
consuming the last request, exactly 2,000 successful requests followed by
refusal, non-retryable errors, and a session change during a wait. Network
and sleep are mocked. Initial zero-call assertions counted previous tests
because Pester 3 defaults to Describe scope; specifying It scope corrected
the tests, and the complete suite then passed.

The SDK's own retries are disabled at the sole request site, so its default
retry behavior cannot multiply this counter. The source boundary permits
only that exact local request-context command and tests rejection of a
nonzero retry setting. Findings retain `UNKN throttled` or `UNKN request
ceiling`; partial collections are discarded. [VERIFIED: source and official
documentation checked with `web.run open`, 2026-09-14]
[Graph throttling](https://learn.microsoft.com/en-us/graph/throttling) and
[request context](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/set-mgrequestcontext?view=graph-powershell-1.0).

## B2 lab entry points

[VERIFIED: Windows PowerShell 5.1, 2026-09-14] Executed from the final staged
Git tree containing both lab entry points:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-PrepareEngagement.ps1
```

Relevant stdout:

```text
Describing B2 lab-only and verified-domain preflight
 [+] refuses a client record before any Graph read and disconnects
 [+] refuses a custom domain even alongside the tenant default
 [+] accepts only onmicrosoft domains and preserves record bytes and dates
 [+] rejects missing, empty, malformed and suffix-spoofed domains
 [+] refuses a wrong organization id in the response
 [+] refuses an expired record or mismatched context with zero Graph reads
 [+] refuses a non-interactive or non-first-party session
 [+] fails closed when the domain collection is denied
 [+] Up requires an engagement and has no Force bypass
 [+] Up previews offline and preserves the supplied record
 [+] Up rejects client scope in the actual entry point
 [+] Up applies the custom-domain guard before its pending mutation boundary
 [+] Up reaches the explicit unfinished-operation refusal only after a valid lab preflight
 [+] Down requires an engagement and has no Force bypass
 [+] Down previews offline and preserves the supplied record
 [+] Down rejects client scope in the actual entry point
 [+] Down applies the custom-domain guard before its pending mutation boundary
 [+] Down reaches the explicit unfinished-operation refusal only after a valid lab preflight
Passed: 18 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Passed: 24 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 20 tracked PowerShell files; no tracked raw output.
All 24 preparation assertions passed. No tenant contacted.
```

`Up` and `Down` require an explicit engagement record. Offline WhatIf accepts
the zero-GUID tracked fixture; non-preview calls validate current dates,
record type, connected tenant, scopes, Process context and first-party
interactive session before the domain query. The query uses the shared
GET-only transport and creates a B4 run manifest first. Failure disconnects.
The organization ID and every returned verified domain must pass, including
when a custom domain accompanies an onmicrosoft default. Missing data refuses.

[VERIFIED: `web.run open`, 2026-09-14] The
[organization endpoint](https://learn.microsoft.com/en-us/graph/api/organization-get?view=graph-rest-1.0)
exposes `id` and `verifiedDomains` with delegated `User.Read`; the guard does
not add a broad directory-read grant to the signed assessment's scope list.

[VERIFIED: `python3 ci/validate_coverage.py`, 2026-09-14] 20 registered and
20 tracked projects; coverage matches `ci.yml`. Runtime and source-discovery
floors now require 24 gate tests, 18 lab tests and 20 boundary-scanned files.

[UNVERIFIED / pending] B2 is a tested prerequisite to mutation, not a finished
lab deployment. Idempotent provisioning, the ownership ledger, independent
leftover audit, final assessment entry-point integration, B5 per-run naming,
B8 connection orchestration and live endpoint oracles remain unfinished.
No real tenant, operator record, signature, or authorization date was touched.
Prioritize those integration boundaries next, keeping mutations disabled
until ownership and teardown are proven. Preserve the signed record and
use CI on the pushed revision before any live run.

## PR #42 findings 1, 2 and 5 — 2026-09-15

[VERIFIED: `git fetch origin refs/pull/43/head` followed by
`git show FETCH_HEAD:docs/reviews/pr-42-entra-lab-review.md`, 2026-09-15]
Read the mirrored audit from PR #43 while its file was still absent from
`origin/main`. This section covers the first numbered work-order milestone.

[VERIFIED: Windows PowerShell 5.1, 2026-09-15] Executed from an isolated
Git checkout, transported through `git pack-objects`, `git unpack-objects`,
`git read-tree` and `git checkout-index`, with synthetic data only:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-PrepareEngagement.ps1
```

Relevant stdout:

```text
All 96 M365 assertions passed. No tenant contacted.
Passed: 24 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Passed: 23 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 20 tracked PowerShell files; no tracked raw output.
All 24 preparation assertions passed. No tenant contacted.
```

The initial baseline failed `string false is not coerced to a valid boolean`:
its fixture also contains a confirmed unregistered account, so expecting
the whole summary to become UNKN contradicted finding 5's correction.
The replacement assertions prove both facts: malformed registration is
counted as unknown with its own UNKN detail, while the confirmed gap remains
WARN. With no confirmed gap, the same malformed flag yields summary UNKN.
Missing registration rows and missing dormancy history/licences now have
mixed-population regressions in both account orders.

Lab preflight validates a separate tracked allowlist containing four lab
permissions plus basic sign-in scopes, alongside the shared assessment read
scopes. The latter are needed because tenant-wide read consent also reaches
the lab administrator. The Windows tests prove that this combined lab
session passes, each lab-only grant is rejected by assessment before any
request, unknown/empty grants disconnect, and session changes are rechecked
at the transport boundary. The lab suite count floor is now 23.

[VERIFIED: review record command above, 2026-09-15; operator-attested]
The dedicated reader and tenant-wide consent for the six assessment read
scopes are already in place. The README reflects those facts, requires
explicit tenant selection and Process-scoped device-code sign-in as the
reader, and prohibits tenant-wide write consent on the shared application.
Role membership and consent isolation are human prerequisites; these fixture
tests do not independently verify them in the tenant.

[VERIFIED: `python3 ci/validate_coverage.py`, 2026-09-15]
20 projects registered, 20 tracked; coverage matches the workflow.

[UNVERIFIED / next work-order milestone] The specific premium-licence error
mapping and Up-Lab's P1 precondition come next, followed by findings 3, 4,
6, 7 and 8. Assessment integration, live mutations, ownership and teardown
remain unfinished. No tenant was contacted, and no live oracle or GitHub CI
result is claimed for this revision.

## Work-order item 2 — premium licensing

[VERIFIED: operator report, 2026-09-15; no independent API read] Claude
verified findings 1, 2 and 5 against ff638ff, and all 16 CI checks passed.

[VERIFIED: operator-provided review record, 2026-09-15] The reader's MFA
registration request returned 403 with code
`Authentication_RequestFromNonPremiumTenantOrB2CTenant`. The transport now
recognizes that exact structured code and propagates the fixed detail
`tenant has no Entra ID P1 licence` to MFA and dormancy UNKN findings.
An unrelated 403 or a matching string only in the error message is not
diagnosed as missing premium. No response text or request metadata is emitted.

[VERIFIED: Windows commands below, 2026-09-15]

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
```

```text
All 106 M365 assertions passed. No tenant contacted.
Passed: 24 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Passed: 27 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 20 tracked PowerShell files; no tracked raw output.
```

Up requires premium licensing before reaching its planting boundary.
Tests exercise no premium, disabled/pending plans, zero seats, missing
permission, malformed/partial inventory, bundled P1 and P2. The licence
read scope is lab-only; assessment still rejects it.

[VERIFIED: `web.run open/search_query`, 2026-09-15] Sources:
[subscribedSkus permissions and shape](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0),
[service-plan status](https://learn.microsoft.com/en-us/graph/api/resources/serviceplaninfo?view=graph-rest-1.0),
[P1/P2 plan identifiers](https://learn.microsoft.com/en-us/entra/identity/users/licensing-service-plan-reference),
[Conditional Access licensing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview).
The gate establishes tenant inventory, not user-level licence compliance.
[UNVERIFIED] No live Graph run or subscription change occurred in this item.

## Work-order item 3 — remaining audit findings

[VERIFIED: Windows PowerShell commands below, 2026-09-15]

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-PrepareEngagement.ps1
```

```text
Passed: 26 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Passed: 29 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 20 tracked PowerShell files; no tracked raw output.
All 106 M365 assertions passed. No tenant contacted.
All 24 preparation assertions passed. No tenant contacted.
```

Finding 3: direct Get-Mg commands, including GET-named POST actions and
module-qualified calls, are refused even in Up/Down. Get-MgContext is the
explicit local-session exception. Existing exact GET transport exception
and retry configuration rules remain in force.

Finding 4: preflight performs storage/expiry validation without creating a
raw run. Successful and refused Up/Down preflights leave no manifest. There
is no new directory to remove on throw; actual persisted output creates its
manifest at the point of use.

Findings 6/7: shared B1 validation accepts lab or client records and reads
the tracked pack-version allowlist. B2's lab-only check remains in the lab
wrapper. Unknown versions refuse without altering the signed record. The
allowlist contains only the already-supported revision, not future guesses.

Finding 8: cloud names match folder segments (including OneDrive business
folder names). Sandbox, Toolbox and Xbox pass. Existing environment-root,
Git and link checks still pass their negative controls.

[UNVERIFIED] These are synthetic Windows tests, not new live-tenant evidence.


## Work-order item 4 — assessment entry point

[VERIFIED: Windows PowerShell 5.1 commands below, 2026-09-15]
`Invoke-FieldKit.ps1 -M365 -Engagement <record> -OutputRoot <root>` now wires
shared B1 validation to `Get-EntraSnapshot`, `ConvertTo-EntraFindings`, and
`Export-EntraReport`. The record supplies the explicit device-code `-TenantId`;
the first-party reader session uses Process context and the read allowlist.
Authorization, record integrity and session consent are rechecked before each
request and after the last response. Disconnect runs on completion/refusal.

[VERIFIED: same commands and date] Output is a private raw snapshot plus HTML
and Markdown, all beneath one B4 seven-day manifest. Manifest creation follows
collection and final authorization validation. Pre-persistence refusals leave
no manifest; any partially written output remains retained for sweeping.
B5 uses fresh per-run aliases; names require both the record permission and
`-NameAccounts`. Raw SDK errors are suppressed; refusals identify a fixed stage.

[VERIFIED: synthetic regression output, same commands and date] The ten new
assessment cases exercise the actual CLI success path, CLI refusal exit 2,
GET-only collection, device-code/tenant parameters, naming combinations,
expired authorization/retention, wrong tenant, extra consent, wrong app/flow,
missing tooling, record changes between requests and after the last response.
The first run exposed Pester 3 moving transport stubs into module scope;
the test discovery doubles cover only those two transport commands, with a
separate missing-tooling negative control. No production gate was relaxed.

Executed in a temporary Windows copy containing the same source bytes:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-PrepareEngagement.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0
$files = @(git ls-files '*.ps1' '*.psm1' '*.psd1')
$findings = @($files | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Severity Error })
if ($findings.Count) { $findings | Format-Table -AutoSize; exit 1 }
```

```text
Passed: 36 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
All 106 M365 assertions passed. No tenant contacted.
Passed: 29 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
All 24 preparation assertions passed. No tenant contacted.
B3/B6 boundary passed: 22 tracked PowerShell files; no tracked raw output.
PSScriptAnalyzer 1.25.0: zero Error findings across 24 PowerShell files.
```

[UNVERIFIED] No live tenant authentication or independent oracle was run for
this item. The operator selects the dedicated reader at sign-in; fixture
success does not establish that account's live role or licensing. Lab mutation
and teardown remain outside this item.


## Work-order item 5 — owned, idempotent lab provisioning

[VERIFIED: Windows PowerShell 5.1 commands below, 2026-09-15]
The default Up path plants the non-P1 member, guest and privileged role.
`-IncludeConditionalAccess` adds report-only CA scoped to the owned member,
after the P1 precondition. The guest uses reserved `example.invalid`, with
`sendInvitationMessage: false`; only its returned user ID enters ownership.
Passwords and invitation redemption URLs are never saved to the ledger.

[VERIFIED: same commands/date] Eight lifecycle cases exercise durable intents,
repeat runs without duplicate objects or renewed retention, P1 refusal before
writes, report-only CA scope, uncertain-write refusal, pre-existing collisions,
missing objects, MFA drift, protected hand-made users and concurrent/corrupt
ledgers. A Windows file-replacement failure was corrected before this result.
POSTs are never automatically retried; an uncertain outcome stays Pending.

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-EntraLabScaffold.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Gates.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File fieldkit/tests/Test-M365Posture.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File labs/entra-identity/tests/Test-PrepareEngagement.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ci/Test-M365Boundary.ps1
Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0
git ls-files '*.ps1' '*.psm1' '*.psd1' | ForEach-Object { Invoke-ScriptAnalyzer -Path $_ -Severity Error }
```

```text
Passed: 37 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Passed: 36 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
All 106 M365 assertions passed. No tenant contacted.
All 24 preparation assertions passed. No tenant contacted.
B3/B6 boundary passed: 24 tracked PowerShell files; no tracked raw output.
PSScriptAnalyzer 1.25.0: zero Error findings across 26 PowerShell files.
```

[VERIFIED: `web.run open`, 2026-09-15] API contracts checked against Microsoft:
[user creation](https://learn.microsoft.com/en-us/graph/api/user-post-users?view=graph-rest-1.0),
[invitations](https://learn.microsoft.com/en-us/graph/api/invitation-post?view=graph-rest-1.0),
[role assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleassignments?view=graph-rest-1.0),
[CA policy creation](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-post-policies?view=graph-rest-1.0).

[UNVERIFIED: live execution pending] No tenant was contacted. Historical
dormancy is unachievable by construction for **any planted object**. Once P1
is available, the live dormancy check is expected to report this unredeemed
guest as **UNKN (null history)**. That is the correct result, not a gap.
The new member's live role/MFA state still needs its independent oracle.
Teardown and leftover auditing are item 6; do not run live provisioning first.

## Audit 6 follow-up — shared SDK context and safe diagnostics, 2026-09-20

[VERIFIED: commands below, 2026-09-20] Extended the existing Windows
lifecycle fixture before changing implementation. Against `8b49a91`, three
Up POSTs and five Down DELETEs completed with **9** context configurations;
the new assertion requires exactly **1**, before any request. The baseline
failed that assertion (47 passed, 1 failed). After sharing the module's
guard through `Initialize-FieldKitGraphContext`, the same case passes,
including the request-order assertion. No SDK, sign-in or tenant is involved
in these fixtures; the real SDK behavior remains audit 6's live evidence.

The boundary scanner permits only literal `Set-MgRequestContext -MaxRetry 0
-ErrorAction Stop` inside that initializer in the central module. Its sole
read request caller is still literal GET in `Invoke-FieldKitGraph`. Negative
controls reject context setup in the former location, nonzero SDK retries,
and a POST hidden in the initializer.

[VERIFIED: same Windows commands/date] `-Diagnose` is forwarded through both
assessment entry points. Integration tests exercise URI-format errors and
HTTP 403, retain the original exception type and numeric status, and reject
synthetic message/header/body text in every output file. Without the switch,
there is no diagnostics file. The sibling `diagnostics.json` stays beneath
the existing raw-run manifest; no new retention clock is created.

Executed from operator using the existing index-to-Windows Git object bridge:

```bash
# Baseline: only the lifecycle regression staged on 8b49a91.
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py labs/entra-identity/tests/Test-EntraLabScaffold.ps1
# Fixed code and new diagnostic tests staged.
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py fieldkit/tests/Test-M365Gates.ps1 labs/entra-identity/tests/Test-EntraLabScaffold.ps1 fieldkit/tests/Test-M365Posture.ps1 labs/entra-identity/tests/Test-PrepareEngagement.ps1 ci/Test-M365Boundary.ps1
```

The bridge executes each file on Windows as:
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <path>`.

```text
Baseline index tree: 92b0cee510fa9e9aa4b69b4044fa75dc875c58c5
[-] L2 initializes SDK context once before reads across multi-step Up and Down
Expected: {1}; But was: {9}
Passed: 47 Failed: 1 Skipped: 0 Pending: 0 Inconclusive: 0

Fixed index tree: e1bc2298b5146c2dda2dd5742b0cbf31e0f579c8
M365 gates: Passed: 41 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
Lab fixtures: Passed: 48 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
All 106 M365 assertions passed. No tenant contacted.
All 24 preparation assertions passed. No tenant contacted.
B3/B6 boundary passed: 27 tracked PowerShell files; no tracked raw output.
```

Local transcripts: `/tmp/codex-audit6-red.log` and
`/tmp/codex-audit6-green.log`. The result excerpts above are durable; temporary
Windows checkouts and local logs are disposable.

[UNVERIFIED] Live Up/Down and SDK token-cache persistence are not established
by these fixtures. One Graph session per process remains required; a reconnect
can restore SDK retries without reapplying the guard. No live Graph calls,
tenant writes or engagement-date edits were made for this follow-up. The
operator relays CI and renews/signs authorization before further live work.

## Audit 8 follow-up — deleted UPNs, scoped Azure coverage and teardown diagnostics

[VERIFIED: `git show origin/main:docs/reviews/pr-42-entra-lab-review.md`,
2026-09-20] Audit 8 records live Up planting all three default objects under
a newly signed lab engagement. Down removed the role and guest but refused
the member's recycle-bin row because Entra had prefixed its original UPN
with the compact object ID. That live row remains for operator acceptance;
no tenant request was made by this follow-up.

[VERIFIED: Windows commands below, 2026-09-20] Corrected A4-b first, changing
only its deleted member UPN on baseline `9da4c4d`. It failed with incomplete
teardown (47 passed, 1 failed). The fix explicitly distinguishes live rows
from deletedItems rows both in the initial ownership validation and before
purge. Only deleted members may use original UPN or exact compact owned ID
plus original UPN, case-insensitively. ID, display name and member type still
must match. Tests reject wrong prefixes, prefixed live members, changed type,
changed name and wrong ID; the live-member refusal issues zero DELETEs.
The ordinary soft-delete fixture now rewrites UPNs too, so same-run purge,
A4-b recovery and repeat Down all exercise the observed service shape.

**L4 choice: option (b).** With a validated Graph-only ledger and no Azure
context/module, Azure coverage is INFO with an explicit "Azure not assessed"
caveat. The raw snapshot records `Assessed: false` and `Ok: false`; it does
not fabricate a successful inventory. Clean is scoped to the lab lifecycle.
Missing ownership, mismatched contexts and failed attempted ARM reads remain
unknown. A simulated future Azure ownership entry also requires Azure
coverage; the exception cannot silently extend to new object kinds.

`-Diagnose` is available on Down, `Invoke-LabLeftoverAudit` and its reader
entry point. Audit failures go into `diagnostics.json`; Down's failure goes
into `down-diagnostics.json` under the same retained raw run. Each entry has
exactly `ExceptionType` and `HttpStatus` (numeric or null). Tests cover
ownership refusal, Graph URI failure, ARM HTTP failure, DELETE and permanent
purge failure. Synthetic exception-message/header/body strings are absent
from every retained file. No diagnostics files are created by default.
Authorization/preflight refusals still do not create a raw run.

Commands, using the existing Git object bridge and Windows PowerShell 5.1:

```bash
# Baseline with corrected A4-b only:
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py labs/entra-identity/tests/Test-EntraLabScaffold.ps1
# Full regression run:
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py labs/entra-identity/tests/Test-EntraLabScaffold.ps1 fieldkit/tests/Test-M365Gates.ps1 fieldkit/tests/Test-M365Posture.ps1 ci/Test-M365Boundary.ps1
# Final targeted run, including ownership and permanent-purge diagnostics:
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py ci/Test-M365Boundary.ps1 labs/entra-identity/tests/Test-EntraLabScaffold.ps1
```

The bridge runs each file as
`powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <path>`.
Baseline tree: `02b9a76f84f7bf625bba477eef7fcde2c176dc02`.
Full regression tree: `95eff1919fc1b429f07ef8c263db5aef79a59a36`.
Final targeted tree: `b1e8f77835a2e77a547b1eb41bf3c84832ec0083`.

```text
Baseline A4-b: Passed: 47 Failed: 1 Skipped: 0 Pending: 0 Inconclusive: 0
Full regression: lab 55/0; M365 gates 41/0; all 106 M365 assertions passed.
Final lab fixtures: Passed: 56 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 27 tracked PowerShell files; no tracked raw output.
```

Logs remain outside Git: `/tmp/codex-audit8-red.log`,
`/tmp/codex-audit8-green2.log` and `/tmp/codex-audit8-final2.log`.

[UNVERIFIED] Successful live purge, final ledger state and clean independent
audit remain the operator's acceptance run after review and green CI. These
fixtures do not prove SDK behavior or service-side deletion. No engagement
dates were edited; no manual purge is substituted for the acceptance run.

## L5 standalone leftover audit — 2026-09-20

[UNVERIFIED independently; reviewer-attested, 2026-09-20] The operator's
live Down run on `4665a8a` purged the retained member and returned
`Clean: True`. This supersedes the pending-purge acceptance statement above.
The subsequent standalone reader audit failed before sign-in because its
entry point did not import `FieldKit.M365` into script scope. The reviewer's
live import fix identified L5; the independent audit still needs acceptance.

[VERIFIED: Windows commands below, 2026-09-20] Added four tests that launch
`powershell -NoProfile -NonInteractive` and invoke the actual
`fieldkit/checks/Test-LabLeftovers.ps1`. The child imports no FieldKit modules
before invoking the entry point. Only SDK functions are replaced with local
stubs; authorization, storage gates, inventory, reporting and exit handling
run as shipped. All four tests fail on `4665a8a` with the generic refusal.
Adding the explicit `FieldKit.M365.psm1` import makes them pass.

The cases cover clean inventory (exit 0), a leftover candidate (exit 1),
unreadable inventory (exit 2), and expired synthetic authorization (exit 2
before sign-in or a retained run). Successful preflight cases verify sign-in,
disconnect, a retained manifest, HTML report and diagnostics. The inventory
failure retains its exception type without the synthetic private message.
All Graph and ARM calls are stubbed; no live tenant is contacted.

```bash
# Before the import fix, with the new entry-point tests staged:
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py labs/entra-identity/tests/Test-EntraLabScaffold.ps1
# After the fix:
python3 /home/operator/.cache/fieldkit-git-validation/test-gates.py labs/entra-identity/tests/Test-EntraLabScaffold.ps1 fieldkit/tests/Test-M365Gates.ps1 ci/Test-M365Boundary.ps1
```

```text
Baseline tree: 60b9031d56d1c2d30649551fb982de95afa33477
Passed: 56 Failed: 4 Skipped: 0 Pending: 0 Inconclusive: 0
Fixed tree: 554289c3bb0bc70067b5880092f5c17f56a7430e
Lab fixtures: Passed: 60 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
M365 gates: Passed: 41 Failed: 0 Skipped: 0 Pending: 0 Inconclusive: 0
B3/B6 boundary passed: 27 tracked PowerShell files; no tracked raw output.
```

Disposable logs: `/tmp/codex-l5-red.log`, `/tmp/codex-l5-green.log`.
[UNVERIFIED] CI and the standalone reader audit after this fix remain pending.
Fixture success does not prove live SDK authentication or consent. Use the
documented fresh-process reader command; the operator handles any additional
audit-scope consent. No live authorization dates or tenant state were changed.
