<# Read-only Graph assessment. Windows PowerShell 5.1.
   Device-code sign-in uses a Process-scoped session; credentials are never
   accepted as parameters. See ../docs/m365-posture.md. #>
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot 'FieldKit.M365.psm1')

function Get-EntraField {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return ,($Object[$Name]) }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) { return ,($property.Value) }
    return $null
}

function Get-EntraReadScopes {
    Get-FieldKitReadScopes
}

function Assert-EntraContext {
    param([Parameter(Mandatory)][guid]$TenantId, $Context)
    if ($TenantId -eq [guid]::Empty) { throw 'A nonzero tenant ID is required.' }
    if ($null -eq $Context) { throw 'No Graph session. The operator must sign in interactively.' }
    $actual = [guid]::Empty
    if (-not [guid]::TryParse([string](Get-EntraField $Context 'TenantId'), [ref]$actual) -or $actual -ne $TenantId) {
        throw 'Graph session tenant does not match the requested tenant.'
    }
    if ((Get-EntraField $Context 'AuthType') -ne 'Delegated' -or
        (Get-EntraField $Context 'ContextScope') -ne 'Process' -or
        (Get-EntraField $Context 'Environment') -ne 'Global') {
        throw 'Use a delegated, Process-scoped Graph session in the Global environment.'
    }
    # Refuse unknown/additional grants, including write grants. Missing read
    # grants remain per-endpoint UNKN findings so partial assessments work.
    $allowed = @(Get-EntraReadScopes) + @('openid', 'profile', 'email', 'offline_access', 'User.Read')
    $scopes = Get-EntraField $Context 'Scopes'
    if ($null -eq $scopes -or @($scopes).Count -eq 0 -or @($scopes | Where-Object { $_ -notin $allowed }).Count) {
        throw 'Graph session has absent or unapproved scopes. Use the documented read-only scope list.'
    }
}

function Get-EntraResources {
    @(
        @{ Key = 'Users'; Path = '/v1.0/users?$select=id,userType,accountEnabled,assignedLicenses,displayName,userPrincipalName'; Scope = @('User.Read.All'); Collection = $true }
        @{ Key = 'Mfa'; Path = '/v1.0/reports/authenticationMethods/userRegistrationDetails'; Scope = @('AuditLog.Read.All'); Collection = $true }
        @{ Key = 'Roles'; Path = '/v1.0/roleManagement/directory/roleAssignments?$expand=principal'; Scope = @('RoleManagement.Read.Directory'); Collection = $true }
        @{ Key = 'Defaults'; Path = '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy'; Scope = @('Policy.Read.All'); Collection = $false }
        @{ Key = 'Ca'; Path = '/v1.0/identity/conditionalAccess/policies?$select=id,state'; Scope = @('Policy.Read.All'); Collection = $true }
        @{ Key = 'Guests'; Path = '/v1.0/policies/authorizationPolicy'; Scope = @('Policy.Read.All'); Collection = $false }
        @{ Key = 'Activity'; Path = '/v1.0/users?$select=id,accountEnabled,assignedLicenses,signInActivity&$top=500'; Scope = @('User.Read.All', 'AuditLog.Read.All'); Collection = $true }
    )
}

function Read-EntraResource {
    param($Resource, [scriptblock]$Transport, [int]$MaxPages = 100)
    $uri = 'https://graph.microsoft.com' + $Resource.Path
    $initial = [uri]$uri
    $seen = @{}
    $items = [System.Collections.Generic.List[object]]::new()
    $ids = @{}
    do {
        # A server-provided nextLink must stay on this resource and origin.
        # Never forward a Graph-authenticated request to an arbitrary URL.
        $parsed = $null
        if (-not [uri]::TryCreate($uri, [UriKind]::Absolute, [ref]$parsed) -or
            $parsed.Scheme -ne 'https' -or $parsed.Host -ne 'graph.microsoft.com' -or
            $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Fragment -or
            $parsed.AbsolutePath -cne $initial.AbsolutePath) { throw 'Unsafe Graph pagination link.' }
        if ($seen.ContainsKey($uri) -or $seen.Count -ge $MaxPages) { throw 'Graph pagination cycle or page limit.' }
        $seen[$uri] = $true
        $page = & $Transport $uri
        if ($null -eq $page) { throw 'Graph returned no response.' }
        if (-not $Resource.Collection) { return $page }
        $values = Get-EntraField $page 'value'
        if ($null -eq $values -or $values -is [string] -or
            $values -is [System.Collections.IDictionary] -or $values -isnot [System.Collections.IEnumerable]) {
            throw 'Graph collection value is missing or malformed.'
        }
        foreach ($item in $values) {
            $id = Get-EntraField $item 'id'
            if ($id -isnot [string] -or [string]::IsNullOrWhiteSpace($id) -or $ids.ContainsKey($id)) {
                throw 'Graph collection has a missing or duplicate object ID.'
            }
            $ids[$id] = $true
            $items.Add($item)
        }
        $next = Get-EntraField $page '@odata.nextLink'
        if ($null -ne $next -and ($next -isnot [string] -or [string]::IsNullOrWhiteSpace($next))) {
            throw 'Graph pagination link is malformed.'
        }
        $uri = $next
    } while ($uri)
    return ,($items.ToArray())
}

function Get-EntraSnapshot {
    param([Parameter(Mandatory)][guid]$TenantId, [Parameter(Mandatory)][scriptblock]$ContextProvider,
        [scriptblock]$Request, [scriptblock]$BeforeRequest = {}, [hashtable]$Diagnostics)
    & $BeforeRequest
    $authorizationGuard = $BeforeRequest
    $context = & $ContextProvider
    Assert-EntraContext $TenantId $context
    $snapshot = @{}
    $budget = @{ Requests = 0 }
    foreach ($resource in (Get-EntraResources)) {
        $failure = $null
        if ($null -ne $Diagnostics) { $failure = @{} }
        if ($budget.Requests -ge 2000) {
            $snapshot[$resource.Key] = @{ Ok = $false; Reason = 'request ceiling' }
            continue
        }
        $missing = @($resource.Scope | Where-Object { $_ -notin (Get-EntraField $context 'Scopes') })
        if ($missing.Count) {
            $snapshot[$resource.Key] = @{ Ok = $false; Reason = 'Missing delegated read scope: ' + ($missing -join ', ') }
            continue
        }
        # Revalidate the actual session before EVERY page; a tenant switch is
        # fatal, never a partial finding that permits requests to keep running.
        $guardedRequest = {
            param($Uri)
            Invoke-FieldKitGraph -Uri $Uri -Budget $budget -Request $Request -Failure $failure -BeforeRequest {
                & $authorizationGuard
                Assert-EntraContext $TenantId (& $ContextProvider)
            }
        }
        try {
            $data = Read-EntraResource $resource $guardedRequest
            $snapshot[$resource.Key] = @{ Ok = $true; Data = $data }
        } catch {
            if ($null -ne $Diagnostics) {
                if (-not $failure.Count) { $failure = Get-FieldKitGraphFailure $_ }
                $Diagnostics[$resource.Key] = $failure
            }
            & $BeforeRequest
            Assert-EntraContext $TenantId (& $ContextProvider)
            # Do not print raw SDK exceptions: they can include identities,
            # request headers or service payloads. Partial pages are discarded.
            $reason = 'Collection incomplete: access, licensing, connectivity, throttling, or response validation failed.'
            if ($_.Exception.Message -eq 'UNKN request ceiling') { $reason = 'request ceiling' }
            elseif ($_.Exception.Message -eq 'UNKN throttled') { $reason = 'throttled' }
            elseif ($_.Exception.Message -eq 'UNKN tenant has no Entra ID P1 licence') { $reason = 'tenant has no Entra ID P1 licence' }
            $snapshot[$resource.Key] = @{ Ok = $false; Reason = $reason }
        }
    }
    if ($null -ne $Diagnostics) {
        foreach ($key in @($snapshot.Keys)) {
            if (-not $snapshot[$key].Ok -and -not $Diagnostics.ContainsKey($key)) {
                $Diagnostics[$key] = @{ ExceptionType = $null; HttpStatus = $null }
            }
        }
    }
    return $snapshot
}

function New-EntraFinding {
    param([string]$Name, [ValidateSet('PASS','FAIL','WARN','UNKN','INFO')][string]$Status,
        [string]$Detail, [string]$Remediation = '')
    [pscustomobject]@{ Section = 'Microsoft 365 / Entra'; Name = $Name; Status = $Status
        Detail = '[UNVERIFIED: independent live oracle pending] ' + $Detail; Remediation = $Remediation }
}

function Get-EntraAlias {
    param([string]$Id, [hashtable]$Aliases)
    if ($Aliases.ContainsKey($Id)) { return $Aliases[$Id] }
    return 'object-unknown'
}

function Get-EntraData {
    param($Snapshot, [string]$Key)
    $entry = $Snapshot[$Key]
    if ($null -eq $entry -or -not $entry.Ok) {
        if ($null -ne $entry -and $entry.Reason -in @('throttled', 'request ceiling', 'tenant has no Entra ID P1 licence')) { throw $entry.Reason }
        throw 'Required collection unavailable or incomplete.'
    }
    return $entry.Data
}

function ConvertTo-EntraFindings {
    param([Parameter(Mandatory)][hashtable]$Snapshot, [ValidateRange(1,3650)][int]$DormantDays = 90,
        [datetimeoffset]$AsOf = [datetimeoffset]::UtcNow,
        [switch]$NameAccounts, [bool]$AllowNamedAccounts = $false)
    # A fresh secret HMAC key makes aliases stable within this report only.
    # The key is never persisted; saved raw data stays under the B4 manifest.
    $aliases = @{}
    $hash = [Security.Cryptography.HMACSHA256]::new()
    try {
        foreach ($entry in $Snapshot.Values) {
            if (-not $entry.Ok) { continue }
            foreach ($row in @($entry.Data)) {
                $id = Get-EntraField $row 'id'
                if ($id -is [string] -and $id -and -not $aliases.ContainsKey($id)) {
                    $aliases[$id] = 'object-' + ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($id))).Replace('-', '').Substring(0, 16).ToLowerInvariant())
                }
            }
        }
        if ($NameAccounts -and $AllowNamedAccounts -and $Snapshot.Users.Ok) {
            foreach ($user in $Snapshot.Users.Data) {
                $name = Get-EntraField $user 'userPrincipalName'
                if ($name -is [string] -and $name) { $aliases[(Get-EntraField $user 'id')] = $name }
            }
        }
    } finally { $hash.Dispose() }
    $checks = [ordered]@{
        'MFA registration' = {
            $users = @(Get-EntraData $Snapshot 'Users')
            $rows = @(Get-EntraData $Snapshot 'Mfa')
            $byId = @{}
            foreach ($row in $rows) { $byId[(Get-EntraField $row 'id')] = $row }
            $enabled = @($users | Where-Object { (Get-EntraField $_ 'accountEnabled') -eq $true })
            if (@($users | Where-Object { (Get-EntraField $_ 'accountEnabled') -isnot [bool] }).Count) { throw 'Missing enabled state.' }
            $absent = 0; $unknown = 0; $registered = 0
            $details = [System.Collections.Generic.List[object]]::new()
            foreach ($user in $enabled) {
                $id = Get-EntraField $user 'id'
                $row = $byId[$id]
                $mfa = Get-EntraField $row 'isMfaRegistered'
                $methods = Get-EntraField $row 'methodsRegistered'
                if ($mfa -isnot [bool] -or $null -eq $methods -or $methods -is [string] -or
                    $methods -isnot [System.Collections.IEnumerable]) {
                    $unknown++
                    $details.Add((New-EntraFinding ('MFA ' + (Get-EntraAlias $id $aliases)) UNKN 'Registration data missing. Disabled users are outside the registration report.'))
                } elseif (-not $mfa) {
                    $absent++
                    $details.Add((New-EntraFinding ('MFA ' + (Get-EntraAlias $id $aliases)) WARN 'Report says MFA is not registered. External/home-tenant protection and exceptions are not evaluated.' 'Review this account and its authentication context.'))
                } else {
                    $registered++
                    $details.Add((New-EntraFinding ('MFA ' + (Get-EntraAlias $id $aliases)) INFO ('MFA registered; method count: {0}. Registration does not establish enforcement.' -f @($methods).Count)))
                }
            }
            $status = 'INFO'
            if ($absent) { $status = 'WARN' }
            elseif ($unknown -or -not $enabled.Count) { $status = 'UNKN' }
            New-EntraFinding 'MFA registration' $status ("Enabled accounts: $($enabled.Count); registered: $registered; not registered: $absent; unknown: $unknown. Report latency and external identity protection are not resolved.") 'Review missing registration and privileged identities first.'
            $details | Sort-Object Name
        }
        'Privileged roles' = {
            $roles = @(Get-EntraData $Snapshot 'Roles')
            $ga = @{}; $other = 0; $nonUser = 0
            foreach ($role in $roles) {
                $definition = Get-EntraField $role 'roleDefinitionId'
                $principal = Get-EntraField $role 'principalId'
                if (-not $definition -or -not $principal) { throw 'Missing role fields.' }
                if ($definition -eq '62e90394-69f5-4237-9190-012177145e10') { $ga[$principal] = $true }
                else { $other++ }
                if ((Get-EntraField (Get-EntraField $role 'principal') '@odata.type') -ne '#microsoft.graph.user') { $nonUser++ }
            }
            New-EntraFinding 'Privileged roles' INFO ("Active assignments: $($roles.Count); unique Global Administrator principals: $($ga.Count); other role assignments: $other; non-user or unresolved principals: $nonUser. This is not a count of effective human admins: group expansion, PIM eligibility, staleness, licenses and emergency-access context remain unassessed.")
        }
        'Conditional Access' = {
            $policies = @(Get-EntraData $Snapshot 'Ca')
            $states = @{ enabled = 0; disabled = 0; enabledForReportingButNotEnforced = 0 }
            $details = [System.Collections.Generic.List[object]]::new()
            foreach ($policy in $policies) {
                $state = Get-EntraField $policy 'state'
                if ($null -eq $state -or -not $states.ContainsKey($state)) { throw 'Unknown policy state.' }
                $states[$state]++
                $details.Add((New-EntraFinding ('CA ' + (Get-EntraAlias (Get-EntraField $policy 'id') $aliases)) INFO ("State: $state. Policy coverage and exclusions are not evaluated.")))
            }
            $status = 'INFO'
            if ($states.disabled -or $states.enabledForReportingButNotEnforced) { $status = 'WARN' }
            New-EntraFinding 'Conditional Access' $status ("Policies: $($policies.Count); enabled: $($states.enabled); report-only: $($states.enabledForReportingButNotEnforced); disabled: $($states.disabled). Zero policies does not establish missing protection; coverage and licensing remain separate.") 'Review intended enforcement before changing any policy.'
            $details | Sort-Object Name
        }
        'Security defaults' = {
            $defaults = Get-EntraData $Snapshot 'Defaults'
            $enabled = Get-EntraField $defaults 'isEnabled'
            if ($enabled -isnot [bool]) { throw 'Missing security-defaults flag.' }
            $status = 'INFO'; $overlap = 'Conditional Access overlap could not be established.'
            if ($Snapshot.Ca.Ok) {
                $states = @($Snapshot.Ca.Data | ForEach-Object { Get-EntraField $_ 'state' })
                if (@($states | Where-Object { $_ -notin @('enabled','disabled','enabledForReportingButNotEnforced') }).Count) { throw 'Missing CA state.' }
                $overlap = 'No enabled CA policy observed.'
                if ($states -contains 'enabled') {
                    $overlap = 'Enabled CA policies observed.'
                    if ($enabled) { $status = 'WARN'; $overlap += ' Review apparent overlap with security defaults.' }
                }
            }
            New-EntraFinding 'Security defaults' $status ("isEnabled: $enabled. $overlap This setting does not prove an individual sign-in was challenged.") 'Verify the policy settings and intended protection in the portal.'
        }
        'Legacy authentication' = {
            New-EntraFinding 'Legacy authentication' UNKN 'Effective protocol access is not established. Security-defaults and CA inventory alone cannot identify every Exchange/service-level path; no service configuration or sign-in oracle was collected.'
        }
        'External sharing' = {
            New-EntraFinding 'External sharing' UNKN 'SharePoint and OneDrive tenant/site sharing defaults are not collected in this milestone. Guest-directory settings do not establish file-sharing policy.'
        }
        'Guest access' = {
            $users = @(Get-EntraData $Snapshot 'Users')
            if (@($users | Where-Object { (Get-EntraField $_ 'userType') -notin @('Member','Guest') }).Count) { throw 'Missing user type.' }
            $policy = Get-EntraData $Snapshot 'Guests'
            $restriction = Get-EntraField $policy 'guestUserRoleId'
            $known = @{
                'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'same directory access as members'
                '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'limited directory access (default guest role)'
                '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'restricted to own directory objects'
            }
            if ($null -eq $restriction -or -not $known.ContainsKey($restriction)) { throw 'Unknown guest restriction role.' }
            $count = @($users | Where-Object { (Get-EntraField $_ 'userType') -eq 'Guest' }).Count
            $status = 'INFO'; if ($restriction -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') { $status = 'WARN' }
            New-EntraFinding 'Guest access' $status ("Guests: $count; configured default: $($known[$restriction]). Effective enumeration with additional roles or app grants has not been tested.") 'Review whether guest directory visibility matches the engagement requirements.'
        }
        'Dormant accounts' = {
            $users = @(Get-EntraData $Snapshot 'Activity')
            $stale = 0; $licensed = 0; $unknown = 0; $enabled = 0
            $details = [System.Collections.Generic.List[object]]::new()
            foreach ($user in $users) {
                $active = Get-EntraField $user 'accountEnabled'
                if ($active -isnot [bool]) { throw 'Missing enabled state.' }
                if (-not $active) { continue }
                $enabled++
                $last = Get-EntraField (Get-EntraField $user 'signInActivity') 'lastSuccessfulSignInDateTime'
                $licenses = Get-EntraField $user 'assignedLicenses'
                $date = [datetimeoffset]::MinValue
                if (-not $last -or $null -eq $licenses -or $licenses -is [string] -or
                    $licenses -isnot [System.Collections.IEnumerable] -or
                    -not [datetimeoffset]::TryParse([string]$last, [ref]$date) -or $date -gt $AsOf) {
                    $unknown++
                    $details.Add((New-EntraFinding ('Dormancy ' + (Get-EntraAlias (Get-EntraField $user 'id') $aliases)) UNKN 'Successful sign-in history or licence data is missing or malformed; dormancy is not established.'))
                    continue
                }
                if ($date -lt $AsOf.AddDays(-$DormantDays)) {
                    $stale++
                    if (@($licenses).Count) { $licensed++ }
                }
            }
            $status = 'INFO'
            if ($stale) { $status = 'WARN' }
            elseif ($unknown -or -not $enabled) { $status = 'UNKN' }
            New-EntraFinding 'Dormant accounts' $status ("Enabled accounts: $enabled; successful sign-in older than $DormantDays days: $stale; of those licensed: $licensed; unknown history/licenses: $unknown. Null history is not evidence of dormancy; successful history is not backfilled and requires P1/P2 access.") 'Review stale licensed accounts and ownership before any offboarding decision.'
            $details | Sort-Object Name
        }
    }
    foreach ($name in $checks.Keys) {
        try { & $checks[$name] }
        catch {
            if ($_.Exception.Message -in @('throttled', 'request ceiling', 'tenant has no Entra ID P1 licence')) { New-EntraFinding $name UNKN $_.Exception.Message }
            else { New-EntraFinding $name UNKN 'Required data unavailable, incomplete, or malformed. Check read scopes, delegated reader role, licensing and connectivity; no negative conclusion can be drawn.' }
        }
    }
}

function Export-EntraReport {
    param([Parameter(Mandatory)][object[]]$Findings, [Parameter(Mandatory)][string]$ReportPath)
    $null = New-Item -ItemType Directory -Path $ReportPath -Force -ErrorAction Stop
    $md = [Text.StringBuilder]::new()
    $html = [Text.StringBuilder]::new()
    $null = $md.AppendLine('# Microsoft 365 / Entra posture snapshot').AppendLine()
    $null = $md.AppendLine('Read-only prototype; independent live validation pending. Account names require both engagement permission and -NameAccounts; otherwise aliases are stable only within this run.').AppendLine()
    $null = $md.AppendLine('| Status | Check | Detail |').AppendLine('|---|---|---|')
    $null = $html.AppendLine('<!doctype html><html lang="en"><meta charset="utf-8"><title>Entra posture snapshot</title><body><h1>Microsoft 365 / Entra posture snapshot</h1><p>Read-only prototype; independent live validation pending. Names require both engagement permission and -NameAccounts. Per-run pseudonyms are not anonymization.</p><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>')
    foreach ($finding in ($Findings | Sort-Object Section, Name)) {
        $detail = $finding.Detail
        if ($finding.Status -in @('WARN','FAIL') -and $finding.Remediation) { $detail += ' Action: ' + $finding.Remediation }
        $cells = @($finding.Status, $finding.Name, $detail)
        $escaped = @($cells | ForEach-Object { [Net.WebUtility]::HtmlEncode([string]$_) })
        $null = $html.AppendLine('<tr><td>' + ($escaped -join '</td><td>') + '</td></tr>')
        $mdCells = @($escaped | ForEach-Object { $_ -replace '\|','&#124;' -replace '[\r\n]+',' ' })
        $null = $md.AppendLine('| ' + ($mdCells -join ' | ') + ' |')
    }
    $null = $html.AppendLine('</table><p>Snapshot only, not assurance. No tenant settings were changed.</p></body></html>')
    $markdownPath = Join-Path $ReportPath 'entra-posture.md'
    $htmlPath = Join-Path $ReportPath 'entra-posture.html'
    $encoding = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($markdownPath, $md.ToString(), $encoding)
    [IO.File]::WriteAllText($htmlPath, $html.ToString(), $encoding)
    [pscustomobject]@{ Markdown = $markdownPath; Html = $htmlPath }
}

function Invoke-EntraAssessment {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Engagement, [Parameter(Mandatory)][string]$OutputRoot,
        [switch]$NameAccounts, [ValidateRange(1,3650)][int]$DormantDays = 90, [switch]$Diagnose)
    $stage = 'engagement validation'
    try {
        # Anchor integrity before parsing so a concurrent edit cannot replace
        # the record between validation and the initial hash.
        if (-not (Test-Path -LiteralPath $Engagement -PathType Leaf)) { throw 'B1 cannot read engagement record.' }
        $recordHash = (Get-FileHash -LiteralPath $Engagement -Algorithm SHA256).Hash
        $record = Assert-FieldKitEngagement -Engagement $Engagement
        $stage = 'local output and retention validation'
        $null = Assert-FieldKitOutputReady -OutputRoot $OutputRoot -Engagement $Engagement
        $tenant = [guid]$record.tenantId
        $stage = 'Graph Authentication tooling check'
        foreach ($command in @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest', 'Set-MgRequestContext')) {
            if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw 'Required Graph Authentication tooling is missing.' }
        }
        $stage = 'reader device-code sign-in'
        if (Get-MgContext) { $null = Disconnect-MgGraph -ErrorAction Stop }
        # The operator selects the dedicated reader in the device-code browser.
        Connect-MgGraph -TenantId $tenant.ToString('D') -ClientId '14d82eec-204b-4c2f-b7e8-296a70dab67e' -UseDeviceCode -ContextScope Process -Scopes (Get-EntraReadScopes) -NoWelcome -ErrorAction Stop | Write-Host
        $guard = {
            $null = Assert-FieldKitEngagement -TenantId $tenant -Engagement $Engagement
            if ((Get-FileHash -LiteralPath $Engagement -Algorithm SHA256).Hash -ne $recordHash) { throw 'Engagement record changed during assessment.' }
            $context = Get-MgContext
            Assert-EntraContext $tenant $context
            if ($context.ClientId -ne '14d82eec-204b-4c2f-b7e8-296a70dab67e' -or $context.TokenCredentialType -ne 'DeviceCode') {
                throw 'B8 requires the first-party device-code session.'
            }
        }
        $stage = 'reader session and authorization validation'
        & $guard
        $diagnostics = $null
        if ($Diagnose) { $diagnostics = @{} }
        $snapshot = Get-EntraSnapshot -TenantId $tenant -ContextProvider { Get-MgContext } -BeforeRequest $guard -Diagnostics $diagnostics
        # Recheck even after the final response; the record/session may have changed.
        & $guard
        $stage = 'retained report creation'
        $run = New-FieldKitRawRun -OutputRoot $OutputRoot -Engagement $Engagement
        $null = Assert-FieldKitLocalPath $run.RawPath
        $encoding = New-Object Text.UTF8Encoding($false)
        [IO.File]::WriteAllText((Join-Path $run.RawPath 'snapshot.json'), ($snapshot | ConvertTo-Json -Depth 30), $encoding)
        if ($Diagnose) {
            [IO.File]::WriteAllText((Join-Path $run.RawPath 'diagnostics.json'), ($diagnostics | ConvertTo-Json -Depth 4), $encoding)
        }
        $findings = @(ConvertTo-EntraFindings $snapshot -DormantDays $DormantDays -NameAccounts:$NameAccounts -AllowNamedAccounts $record.allowNamedAccounts)
        $reportDir = New-FieldKitReportDir -OutputRoot $OutputRoot -Engagement $Engagement
        $report = Export-EntraReport -Findings $findings -ReportPath $reportDir
        [pscustomobject]@{ Findings = $findings; Report = $report; RawPath = $run.RawPath; DeleteBy = $run.DeleteBy }
    } catch {
        throw (Get-FieldKitRefusalMessage $_ ('M365 assessment stopped during ' + $stage + '. Check the engagement record, dates, local output root, Graph tooling and the dedicated reader session.'))
    } finally {
        if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) { $null = Disconnect-MgGraph -ErrorAction SilentlyContinue }
    }
}

Export-ModuleMember -Function Get-EntraReadScopes, Assert-EntraContext, Get-EntraSnapshot, ConvertTo-EntraFindings, Export-EntraReport, Invoke-EntraAssessment
