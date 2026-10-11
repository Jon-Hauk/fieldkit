# Microsoft 365 / Entra posture prototype

Windows PowerShell 5.1, explicitly invoked from the operator workstation.
The host-local sweep does not automatically contact a tenant. No Linux port.
This milestone adds read-only collection, conservative findings and stable
HTML/Markdown reports. It does not provision, remediate or tear down a lab.

## Run an assessment

[VERIFIED: Windows fixture commands and date in the
[execution evidence](../evidence/m365-gates.md#work-order-item-4--assessment-entry-point)]
The assessment entry point validates the B1 record, signs the reader in by
device code with its explicit tenant ID, collects a snapshot, converts findings,
and exports HTML and Markdown under a B4 seven-day manifest.

1. Complete and sign the [engagement page](../ENGAGEMENT-PACK.md) privately.
   Keep the `fieldkit-engagement/1` JSON record beneath an existing local
   OutputRoot, outside Git and cloud sync. The script checks the schema,
   dates and accepted pack revision; the operator verifies the signature.
2. Use Windows PowerShell 5.1 with `Microsoft.Graph.Authentication` already
   installed. The script does not install modules. Sign in as the dedicated
   reader in the device-code browser prompt; keep credentials out of logs.
3. From the repository root, run:

```powershell
& .\fieldkit\Invoke-FieldKit.ps1 -M365 `
    -Engagement 'C:\fieldkit-engagements\lab-review\engagement.json' `
    -OutputRoot 'C:\fieldkit-engagements'
```

The record supplies `-TenantId` to `Connect-MgGraph`; there is no tenant
selection default. The command requests the six allowlisted read scopes with
`-UseDeviceCode -ContextScope Process` and the first-party Graph PowerShell
application. The operator selects the reader account. Tenant, dates, record
integrity, session type and consent are checked before each request and once
more before saving output. The Graph session is disconnected on completion
or refusal. These parameters are documented by
[Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0)
[VERIFIED: `web.run open`, 2026-09-15].

Use one Graph session per PowerShell process. Start a fresh process for a new
assessment or a reconnect: the SDK retry configuration is initialized once
before the first request, shared with lab reads and writes. Reconnecting in
the same process is not supported and may restore uncounted SDK retries.

Each collection writes `snapshot.json` and `manifest.json` into a new
`raw/run-<guid>` directory beside the record. Raw files have seven-day
retention. HTML and Markdown reports live separately under
`reports/<UTC>-<id>/`; raw sweep does not delete them or the lab's sibling
ownership ledger. Authorization or session refusal before persistence creates
no manifest. Expired raw runs block collection before sign-in.

```powershell
& .\fieldkit\Invoke-FieldKit.ps1 -Sweep -OutputRoot 'C:\fieldkit-engagements'
```

Account names appear only with both `-NameAccounts` and
`allowNamedAccounts: true` in the signed record. Otherwise aliases are stable
within one report and change between runs. Raw snapshots can contain names
regardless of this reporting option and must remain private.

Exit 0 means no `FAIL` finding, 1 means at least one `FAIL`, and 2 means the
assessment could not complete. Inspect every `UNKN`; exit 0 does not prove
complete visibility. Refusals name a fixed processing stage without exposing
SDK error payloads. `-M365` cannot be combined with host or sweep options.
`checks/Test-M365Posture.ps1` forwards the same Engagement/OutputRoot options
to this entry point.

[VERIFIED: live lab run, 2026-09-20; write-up in
[LAB-2026-09-20](https://github.com/Jon-Hauk/engineering-records/blob/main/labs/LAB-2026-09-20-entra-identity.md)]
After the device-code display and SDK request-context fixes (L1/L2 in that
write-up), device-code sign-in and all seven resource reads succeeded as the
dedicated reader with SDK 2.39.0. The operator's separate direct Graph reads
matched the reported counts/settings.
MFA registration returned zero rows: four enabled accounts remain unknown
pending report backfill. This is not evidence of missing MFA. Legacy
authentication and external sharing remain UNKN by design.

The operator reports an active Entra ID P2 trial since 2026-09-19, with one
seat on the reader. This supersedes the earlier licence-blocked status;
it does not prove billing settings or MFA backfill. [VERIFIED: the same
command, 2026-09-20, audit 8] The operator subsequently signed a new lab
engagement and ran Up successfully; Down failed on a rewritten deleted UPN.
Successful complete teardown remains unverified pending operator acceptance.

## Endpoint and permission contract

[VERIFIED: documentation] Checked with `web.run open` on 2026-09-13.
All requests use Microsoft Graph v1.0 and HTTP GET. These delegated scopes
do not replace the signed-in person's required directory reader role or
licensing. A test user with no assigned role is not automatically an assessor.

| Data | GET path | Read scope | Interpretation boundary |
|---|---|---|---|
| Users | `/users?$select=id,userType,accountEnabled,assignedLicenses,displayName,userPrincipalName` | `User.Read.All` | Directory inventory; names retained privately and reported only with both naming permissions |
| MFA registration | `/reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` | Per-user registration, not enforcement; disabled users excluded by the service; external identity protection and reporting latency unresolved |
| Active roles | `/roleManagement/directory/roleAssignments?$expand=principal` | `RoleManagement.Read.Directory` | Counts assignment records and unique GA principals; does not count effective human admins, expand groups, or inventory PIM eligibility |
| Security defaults | `/policies/identitySecurityDefaultsEnforcementPolicy` | `Policy.Read.All` | Reads `isEnabled`; compares available CA states without asserting a sign-in challenge |
| Conditional Access | `/identity/conditionalAccess/policies?$select=id,state` | `Policy.Read.All` | Inventory and individual states; no evaluation of exclusions, grants or effective coverage |
| Guest defaults | `/policies/authorizationPolicy` | `Policy.Read.All` | Default directory role only; no effective guest-session enumeration or file-sharing claim |
| Dormancy | `/users?$select=id,accountEnabled,assignedLicenses,signInActivity&$top=500` | `User.Read.All`, `AuditLog.Read.All` | Uses successful sign-ins; missing, malformed or future history stays unknown |

Sources: [users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0),
[MFA registration](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0),
[active assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0),
[security defaults](https://learn.microsoft.com/en-us/graph/api/identitysecuritydefaultsenforcementpolicy-get?view=graph-rest-1.0),
[CA](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0),
[guest-role values](https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy?view=graph-rest-1.0),
[successful history](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity?view=graph-rest-1.0),
[process context](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0).

[VERIFIED: documentation] Microsoft requires P1/P2 for
[authentication registration reports](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity)
and [programmatic successful sign-in history](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts).
Free-tier access failures are unknown visibility, not failing security.
Do not upgrade or start a trial merely to turn a result green.

## Data and failure handling

[VERIFIED: fixture commands in the execution evidence, 2026-09-15]
Raw responses are persisted only beneath the run manifest. Report aliases use
an in-memory HMAC key generated for each run. The key is not persisted.
Reports and raw snapshots remain private engagement data. Authentication uses
the SDK's Process context; no credential parameter or disk cache is created
by FieldKit. [UNVERIFIED] SDK behavior in the actual operator environment
still needs live validation before claiming zero credential persistence.

Pagination follows only HTTPS links on the same Graph resource and origin.
Cycles, more than 100 pages, malformed collections, duplicates and denied
later pages discard that resource's partial inventory. Other independently
readable resources can still contribute findings. A changed session tenant
stops the whole assessment before another request. Raw exceptions are not
echoed because they can contain private service payloads.

[VERIFIED: offline commands in the execution evidence, 2026-09-20]
Add `-Diagnose` to `Invoke-FieldKit.ps1 -M365` or
`checks/Test-M365Posture.ps1` to write `diagnostics.json` under the raw run's
manifest. It maps failed resource names to `ExceptionType` and numeric
`HttpStatus` only. Unknown status, or failure without an exception, is null.
Messages, headers, URIs and payloads are excluded; the file is absent by
default and swept with the raw run. Findings and their UNKN meanings do not
change. Tests check that synthetic private error text is absent from every
retained file. SDK token-cache persistence remains separately unverified.

[UNVERIFIED] Each newly generated result still requires an independent oracle
for that run; the dated oracle evidence below does not validate future data.
Legacy authentication and SharePoint/OneDrive external sharing remain explicit
`UNKN` findings; no effective service-level collector is implemented yet.
Privileged MFA correlation, PIM, effective group membership, complete method
types and role-holder staleness/licenses remain work to complete. Lab
provisioning, teardown and the independent leftover audit live with the lab,
not in this kit; all three ran live on 2026-09-20 and teardown reported clean
(see LAB-2026-09-20 above). Posture reports cannot establish safe teardown.

## Offline verification

From the fieldkit directory:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tests\Test-M365Posture.ps1
```

No tenant, Graph module, sign-in or package install is needed for fixtures.
See [execution evidence](../evidence/m365-gates.md#work-order-item-4--assessment-entry-point) for results and limits.
