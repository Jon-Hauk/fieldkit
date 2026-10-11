<# Tenant-free regression and adversarial tests. No Graph module required. #>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Entra.psm1') -Force
$script:Assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Label)
    if (-not $Condition) { throw "FAIL: $Label" }
    $script:Assertions++
    Write-Output "PASS: $Label"
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Label)
    $threw = $false
    try { & $Action | Out-Null } catch { $threw = $true }
    Assert-True $threw $Label
}
function New-TestContext {
    @{ TenantId = '11111111-1111-4111-8111-111111111111'; AuthType = 'Delegated';
        ContextScope = 'Process'; Environment = 'Global'; Scopes = @(Get-EntraReadScopes) }
}
function New-TestSnapshot {
    @{
        Users = @{ Ok = $true; Data = @(
            @{ id = 'user-a'; userType = 'Member'; accountEnabled = $true; assignedLicenses = @() },
            @{ id = 'user-b'; userType = 'Guest'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'fixture-sku' }) }
        ) }
        Mfa = @{ Ok = $true; Data = @(
            @{ id = 'user-a'; isMfaRegistered = $true; methodsRegistered = @('microsoftAuthenticatorPush') },
            @{ id = 'user-b'; isMfaRegistered = $false; methodsRegistered = @('email') }
        ) }
        Roles = @{ Ok = $true; Data = @(
            @{ id = 'role-a'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'group-a'; principal = @{ '@odata.type' = '#microsoft.graph.group' } },
            @{ id = 'role-b'; roleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; principalId = 'group-a'; principal = @{ '@odata.type' = '#microsoft.graph.group' } }
        ) }
        Ca = @{ Ok = $true; Data = @(@{ id = 'ca-a'; state = 'enabledForReportingButNotEnforced' }) }
        Defaults = @{ Ok = $true; Data = @{ isEnabled = $true } }
        Guests = @{ Ok = $true; Data = @{ guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b' } }
        Activity = @{ Ok = $true; Data = @(
            @{ id = 'user-a'; accountEnabled = $true; assignedLicenses = @(); signInActivity = @{ lastSuccessfulSignInDateTime = '2026-09-12T00:00:00Z' } },
            @{ id = 'user-b'; accountEnabled = $true; assignedLicenses = @(@{ skuId = 'fixture-sku' }); signInActivity = @{ lastSuccessfulSignInDateTime = '2025-01-01T00:00:00Z'; lastSignInDateTime = '2026-09-13T00:00:00Z' } }
        ) }
    }
}
function Get-TestFinding {
    param($Snapshot, [string]$Name)
    @(ConvertTo-EntraFindings $Snapshot -AsOf ([datetimeoffset]'2026-09-13T00:00:00Z')) | Where-Object Name -eq $Name
}

$tenant = [guid]'11111111-1111-4111-8111-111111111111'
$context = New-TestContext
Assert-EntraContext $tenant $context
Assert-True $true 'matching delegated process session accepted'
foreach ($scope in @('RoleEligibilitySchedule.Read.Directory', 'SharePointTenantSettings.Read.All')) {
    Assert-True ($scope -in @(Get-EntraReadScopes)) ("approved read scope is allowlisted: $scope")
    $specific = New-TestContext
    $specific.Scopes = @($scope)
    Assert-EntraContext $tenant $specific
    Assert-True $true ("context accepts approved read scope: $scope")
}
foreach ($change in @(
    @{ Key = 'TenantId'; Value = '22222222-2222-4222-8222-222222222222' },
    @{ Key = 'TenantId'; Value = 'not-a-guid' },
    @{ Key = 'AuthType'; Value = 'AppOnly' },
    @{ Key = 'ContextScope'; Value = 'CurrentUser' },
    @{ Key = 'Environment'; Value = 'USGov' },
    @{ Key = 'Scopes'; Value = @(('Directory.Read' + 'Write.All')) },
    @{ Key = 'Scopes'; Value = @('Mail.Read') },
    @{ Key = 'Scopes'; Value = @() }
)) {
    $bad = New-TestContext; $bad[$change.Key] = $change.Value
    Assert-Throws { Assert-EntraContext $tenant $bad } ("session guard rejects $($change.Key): $($change.Value -join ',')")
}
Assert-Throws { Assert-EntraContext ([guid]::Empty) $context } 'zero tenant rejected'
Assert-Throws { Assert-EntraContext $tenant $null } 'missing session rejected'

$script:Calls = [Collections.Generic.List[string]]::new()
$request = {
    param($Uri)
    $script:Calls.Add($Uri)
    if ($Uri -match '/users\?' -and $Uri -notmatch 'signInActivity') {
        if ($Uri -match 'skiptoken') { return @{ value = @(@{ id = 'b' }) } }
        return @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=page2' }
    }
    if ($Uri -match '/policies/identitySecurity') { return @{ isEnabled = $true } }
    if ($Uri -match '/policies/authorization') { return @{ guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b' } }
    return @{ value = @() }
}
$collected = Get-EntraSnapshot $tenant { $context } $request
Assert-True ($collected.Users.Ok -and $collected.Users.Data.Count -eq 2) 'pagination accumulates every page'
Assert-True ($collected.Mfa.Ok -and $collected.Mfa.Data.Count -eq 0) 'empty collection remains a valid empty array'
Assert-True ($script:Calls.Count -eq 8) 'seven resources and second users page requested'

$restricted = New-TestContext; $restricted.Scopes = @('Policy.Read.All')
$script:Calls.Clear()
$partial = Get-EntraSnapshot $tenant { $restricted } $request
Assert-True (-not $partial.Users.Ok -and -not $partial.Mfa.Ok -and $partial.Defaults.Ok) 'missing scopes permit only independently readable endpoints'
Assert-True ($script:Calls.Count -eq 3) 'missing-scope endpoints never contacted'
foreach ($message in @('403 denied private-fixture-string', '401 expired', '429 throttled', '503 unreachable')) {
    $failed = Get-EntraSnapshot $tenant { $context } { param($Uri) throw $message }
    Assert-True (@($failed.Values | Where-Object { $_.Ok }).Count -eq 0) ("request failure remains incomplete: $message")
    Assert-True (($failed | ConvertTo-Json -Depth 6) -notmatch 'private-fixture-string') 'raw exception content is not disclosed'
}

# Adversarial transports differ from the normal fixture's representation.
foreach ($shape in @('ErrorDetails', 'ResponseBody', 'Error')) {
    $premium = Get-EntraSnapshot $tenant { $context } {
        $e = New-Object Exception 'private payload'
        $e | Add-Member NoteProperty ResponseStatusCode 403
        $body = '{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant","message":"private payload"}}'
        $record = New-Object Management.Automation.ErrorRecord($e, 'fixture', 'PermissionDenied', $null)
        if ($shape -eq 'ErrorDetails') { $record.ErrorDetails = New-Object Management.Automation.ErrorDetails($body) }
        elseif ($shape -eq 'ResponseBody') { $e | Add-Member NoteProperty ResponseBody $body }
        else { $e | Add-Member NoteProperty Error @{ Code = 'Authentication_RequestFromNonPremiumTenantOrB2CTenant' } }
        throw $record
    }
    foreach ($name in @('MFA registration', 'Dormant accounts')) {
        $f = Get-TestFinding $premium $name
        Assert-True ($f.Status -eq 'UNKN' -and $f.Detail -match 'tenant has no Entra ID P1 licence') ("premium code maps to specific unknown: $shape / $name")
    }
    Assert-True (($premium | ConvertTo-Json -Depth 6) -notmatch 'private payload') 'premium error does not disclose response text'
}
$denied = Get-EntraSnapshot $tenant { $context } {
    $e = New-Object Exception 'Authentication_RequestFromNonPremiumTenantOrB2CTenant'
    $e | Add-Member NoteProperty ResponseStatusCode 403
    $e | Add-Member NoteProperty ResponseBody '{"error":{"code":"Authorization_RequestDenied"}}'
    throw $e
}
Assert-True ((Get-TestFinding $denied 'MFA registration').Detail -notmatch 'tenant has no Entra ID P1 licence') 'unrelated 403 and error text are not diagnosed as missing premium'
foreach ($link in @(
    'https://example.invalid/v1.0/users',
    'http://graph.microsoft.com/v1.0/users',
    'https://graph.microsoft.com:444/v1.0/users',
    'https://graph.microsoft.com/v1.0/groups',
    'https://graph.microsoft.com/v1.0/users#fragment',
    'https://someone@graph.microsoft.com/v1.0/users',
    '/v1.0/users?$skiptoken=relative',
    'https://graph.microsoft.com/v1.0/users?$select=id,userType,accountEnabled,assignedLicenses'
)) {
    $badPage = Get-EntraSnapshot $tenant { $context } { param($Uri) @{ value = @(@{ id = 'a' }); '@odata.nextLink' = $link } }
    Assert-True (-not $badPage.Users.Ok) ("unsafe or repeating pagination rejected: $link")
}
foreach ($page in @(@{}, @{ value = $null }, @{ value = 'wrong' }, @{ value = @{} },
    @{ value = @(@{ noId = 'x' }) }, @{ value = @(@{ id = 'same' }, @{ id = 'same' }) },
    @{ value = @(); '@odata.nextLink' = 2 })) {
    $invalid = Get-EntraSnapshot $tenant { $context } { param($Uri) $page }
    Assert-True (-not $invalid.Users.Ok) 'malformed collection cannot become a clean inventory'
}
$secondPageFailure = Get-EntraSnapshot $tenant { $context } {
    param($Uri)
    if ($Uri -match 'skiptoken') { throw 'second page denied' }
    @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=two' }
}
Assert-True (-not $secondPageFailure.Users.Ok -and -not $secondPageFailure.Users.ContainsKey('Data')) 'partial results discarded after a later page fails'
$script:ContextReads = 0; $script:TransportCalls = 0
Assert-Throws {
    Get-EntraSnapshot $tenant {
        $script:ContextReads++
        $c = New-TestContext
        if ($script:ContextReads -gt 2) { $c.TenantId = '22222222-2222-4222-8222-222222222222' }
        $c
    } { param($Uri) $script:TransportCalls++; @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users?$skiptoken=two' } }
} 'tenant switch between pages aborts assessment'
Assert-True ($script:TransportCalls -eq 1) 'no request sent after session tenant switch'

$snapshot = New-TestSnapshot
$all = @(ConvertTo-EntraFindings $snapshot -AsOf ([datetimeoffset]'2026-09-13T00:00:00Z'))
Assert-True ($all.Count -eq 11) 'eight summary checks plus per-user and per-policy details'
Assert-True (@($all | Where-Object { $_.Detail -notmatch '^\[UNVERIFIED' }).Count -eq 0) 'every finding declares the pending live oracle'
Assert-True ((Get-TestFinding $snapshot 'MFA registration').Status -eq 'WARN') 'email-only registration does not imply MFA'
Assert-True ((Get-TestFinding $snapshot 'Privileged roles').Detail -match 'unique Global Administrator principals: 1;') 'duplicate assignments counted as one principal'
Assert-True ((Get-TestFinding $snapshot 'Privileged roles').Detail -match 'non-user or unresolved principals: 2') 'group assignments are not mislabeled as human admins'
Assert-True ((Get-TestFinding $snapshot 'Conditional Access').Status -eq 'WARN') 'report-only policy is not enforced'
Assert-True ((Get-TestFinding $snapshot 'Dormant accounts').Detail -match 'older than 90 days: 1; of those licensed: 1') 'recent failed attempt does not reset successful-sign-in dormancy'
Assert-True ((Get-TestFinding $snapshot 'Legacy authentication').Status -eq 'UNKN') 'legacy auth has no unsupported inferred verdict'
Assert-True ((Get-TestFinding $snapshot 'External sharing').Status -eq 'UNKN') 'external sharing gap stays explicit'
foreach ($mutation in @(
    @{ Key = 'Mfa'; Name = 'MFA registration' }, @{ Key = 'Roles'; Name = 'Privileged roles' },
    @{ Key = 'Ca'; Name = 'Conditional Access' }, @{ Key = 'Defaults'; Name = 'Security defaults' },
    @{ Key = 'Guests'; Name = 'Guest access' }, @{ Key = 'Activity'; Name = 'Dormant accounts' }
)) {
    $s = New-TestSnapshot; $s[$mutation.Key] = @{ Ok = $false; Reason = 'fixture denied' }
    Assert-True ((Get-TestFinding $s $mutation.Name).Status -eq 'UNKN') ("denied collection: $($mutation.Name)")
}
$s = New-TestSnapshot; $s.Mfa.Data[0].isMfaRegistered = 'false'
$mixed = @(ConvertTo-EntraFindings $s)
Assert-True ((Get-TestFinding $s 'MFA registration').Status -eq 'WARN') 'known missing MFA stays WARN alongside a malformed registration flag'
Assert-True ((Get-TestFinding $s 'MFA registration').Detail -match 'registered: 0; not registered: 1; unknown: 1') 'string false is counted as unknown, not as a boolean'
Assert-True (@($mixed | Where-Object { $_.Name -like 'MFA object-*' -and $_.Status -eq 'UNKN' }).Count -eq 1) 'malformed registration retains its per-account UNKN finding'
$s.Mfa.Data[1].isMfaRegistered = $true
Assert-True ((Get-TestFinding $s 'MFA registration').Status -eq 'UNKN') 'malformed registration without a known warning leaves the summary UNKN'
$s = New-TestSnapshot; $s.Mfa.Data = @()
Assert-True ((Get-TestFinding $s 'MFA registration').Detail -match 'unknown: 2') 'missing enabled-user report rows stay unknown'
foreach ($reverse in @($false, $true)) {
    $s = New-TestSnapshot
    $s.Mfa.Data = @($s.Mfa.Data[1])
    if ($reverse) { $s.Users.Data = @($s.Users.Data[1], $s.Users.Data[0]) }
    $mixed = @(ConvertTo-EntraFindings $s)
    Assert-True ((Get-TestFinding $s 'MFA registration').Status -eq 'WARN') 'missing MFA row cannot mask a confirmed unregistered account in either order'
    Assert-True ((Get-TestFinding $s 'MFA registration').Detail -match 'not registered: 1; unknown: 1') 'mixed MFA summary discloses both populations'
    Assert-True (@($mixed | Where-Object { $_.Name -like 'MFA object-*' -and $_.Status -eq 'UNKN' }).Count -eq 1) 'missing MFA row retains one per-account UNKN'
}
$s = New-TestSnapshot; $s.Defaults.Data = @{}
Assert-True ((Get-TestFinding $s 'Security defaults').Status -eq 'UNKN') 'absent security-defaults flag is unknown'
$s = New-TestSnapshot; $s.Ca.Data[0].state = 'newFutureState'
Assert-True ((Get-TestFinding $s 'Conditional Access').Status -eq 'UNKN') 'future policy state is unknown'
$s = New-TestSnapshot; $s.Ca.Data[0].state = 'enabled'
Assert-True ((Get-TestFinding $s 'Security defaults').Status -eq 'WARN') 'apparent CA and defaults overlap is surfaced'
$s = New-TestSnapshot; $s.Guests.Data.guestUserRoleId = 'unknown-role'
Assert-True ((Get-TestFinding $s 'Guest access').Status -eq 'UNKN') 'unknown guest role is not assumed restricted'
foreach ($time in @($null, 'invalid', '2030-01-01T00:00:00Z')) {
    $s = New-TestSnapshot; $s.Activity.Data[1].signInActivity.lastSuccessfulSignInDateTime = $time
    Assert-True ((Get-TestFinding $s 'Dormant accounts').Status -eq 'UNKN') 'null, invalid or future activity is not proof of dormancy'
}
foreach ($reverse in @($false, $true)) {
    foreach ($missing in @('history', 'licenses')) {
        $s = New-TestSnapshot
        if ($missing -eq 'history') { $s.Activity.Data[0].signInActivity.lastSuccessfulSignInDateTime = $null }
        else { $s.Activity.Data[0].assignedLicenses = $null }
        if ($reverse) { $s.Activity.Data = @($s.Activity.Data[1], $s.Activity.Data[0]) }
        $mixed = @(ConvertTo-EntraFindings $s -AsOf ([datetimeoffset]'2026-09-13T00:00:00Z'))
        Assert-True ((Get-TestFinding $s 'Dormant accounts').Status -eq 'WARN') 'unknown history or licenses cannot mask confirmed dormancy in either order'
        Assert-True ((Get-TestFinding $s 'Dormant accounts').Detail -match 'older than 90 days: 1; of those licensed: 1; unknown history/licenses: 1') 'mixed dormancy summary discloses both populations'
        Assert-True (@($mixed | Where-Object { $_.Name -like 'Dormancy object-*' -and $_.Status -eq 'UNKN' }).Count -eq 1) 'unknown dormancy retains one per-account UNKN'
    }
}
# JSON object conversion catches hashtable-only implementations.
$s = New-TestSnapshot
foreach ($key in @($s.Keys)) { $s[$key].Data = $s[$key].Data | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json }
Assert-True ((Get-TestFinding $s 'Guest access').Detail -match 'Guests: 1;') 'PSCustomObject responses supported'

$out = Join-Path ([IO.Path]::GetTempPath()) ('codex-m365-tests-' + [guid]::NewGuid().ToString('N'))
$report = Export-EntraReport $all $out
$before = (Get-FileHash $report.Markdown).Hash
$null = Export-EntraReport @($all | Sort-Object Name -Descending) $out
Assert-True ((Get-FileHash $report.Markdown).Hash -eq $before) 'Markdown deterministic across input order and repeat export'
$text = [IO.File]::ReadAllText($report.Markdown)
Assert-True ($text -notmatch 'user-a|user-b|group-a|ca-a|fixture-sku') 'reports omit raw object identifiers and license IDs'
$unsafe = @([pscustomobject]@{ Section = 'Test'; Name = '<script>|'; Status = 'WARN'; Detail = '<img src=x onerror=bad>|'; Remediation = '<b>fix</b>' })
$r = Export-EntraReport $unsafe (Join-Path $out 'encoding')
Assert-True ([IO.File]::ReadAllText($r.Html) -notmatch '<script>|<img|<b>fix') 'HTML encodes untrusted fields'
Assert-True ([IO.File]::ReadAllText($r.Markdown) -match '&#124;') 'Markdown escapes table separators'
Write-Output ("All {0} M365 assertions passed. No tenant contacted. Reports: {1}" -f $script:Assertions, $out)
