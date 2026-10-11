Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.M365.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Entra.psm1') -Force
function global:Get-MgContext { throw 'Unmocked context' }
function global:Connect-MgGraph {
    [CmdletBinding()] param($TenantId, $ClientId, [switch]$UseDeviceCode, $ContextScope, $Scopes, [switch]$NoWelcome)
    throw 'Unmocked connect'
}
function global:Disconnect-MgGraph { [CmdletBinding()] param() throw 'Unmocked disconnect' }
function global:Set-MgRequestContext { [CmdletBinding()] param($MaxRetry) throw 'Unmocked retry context' }
function global:Invoke-MgGraphRequest { [CmdletBinding()] param($Method, $Uri, $OutputType) throw 'Unmocked request' }

Describe 'M365 assessment integration' {
    BeforeEach {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('fieldkit-assessment-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $root 'engagement')
        $recordPath = Join-Path $root 'engagement\engagement.json'
        $record = @{ schema = 'fieldkit-engagement/1'; type = 'client'; tenantId = '11111111-1111-4111-8111-111111111111';
            authorisedBy = 'Synthetic owner'; authorisedOn = (Get-Date).ToString('yyyy-MM-dd'); expiresOn = (Get-Date).AddDays(7).ToString('yyyy-MM-dd');
            allowNamedAccounts = $false; packVersion = '5f1b166' }
        $record | ConvertTo-Json | Set-Content $recordPath
        $global:AssessmentFixture = @{ Connected = $false; Calls = 0; MutateRecord = $false; MutateAt = 0; Path = $recordPath;
            Context = @{ TenantId = $record.tenantId; ClientId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; AuthType = 'Delegated';
                TokenCredentialType = 'DeviceCode'; ContextScope = 'Process'; Environment = 'Global'; Scopes = @(Get-EntraReadScopes) } }
        Mock Get-MgContext { if ($global:AssessmentFixture.Connected) { $global:AssessmentFixture.Context } } -ModuleName FieldKit.Entra
        Mock Connect-MgGraph { $global:AssessmentFixture.Connected = $true } -ModuleName FieldKit.Entra
        Mock Disconnect-MgGraph { $global:AssessmentFixture.Connected = $false } -ModuleName FieldKit.Entra
        # Pester 3 moves transport stubs into M365's module scope, so Entra's
        # tooling probe needs discovery doubles for those two commands only.
        Mock Get-Command { [pscustomobject]@{ Name = $Name } } -ModuleName FieldKit.Entra -ParameterFilter {
            $Name -in @('Invoke-MgGraphRequest', 'Set-MgRequestContext')
        }
        Mock Set-MgRequestContext {} -ModuleName FieldKit.M365
        Mock Invoke-MgGraphRequest {
            $global:AssessmentFixture.Calls++
            if ($global:AssessmentFixture.MutateRecord -or $global:AssessmentFixture.Calls -eq $global:AssessmentFixture.MutateAt) { [IO.File]::AppendAllText($global:AssessmentFixture.Path, ' ') }
            if ($Uri -match '/users\?') { return @{ value = @(@{ id = 'fixture-user'; userPrincipalName = 'synthetic@example.invalid';
                userType = 'Member'; accountEnabled = $true; assignedLicenses = @(); signInActivity = @{ lastSuccessfulSignInDateTime = '2025-01-01T00:00:00Z' } }) } }
            if ($Uri -match '/userRegistrationDetails') { return @{ value = @(@{ id = 'fixture-user'; isMfaRegistered = $false; methodsRegistered = @() }) } }
            if ($Uri -match '/identitySecurityDefaults') { return @{ isEnabled = $false } }
            if ($Uri -match '/authorizationPolicy') { return @{ guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b' } }
            return @{ value = @() }
        } -ModuleName FieldKit.M365
    }
    AfterEach {
        Remove-Item $root -Recurse -Force
        Remove-Variable AssessmentFixture -Scope Global
    }
    It 'connects with explicit tenant and device code, collects through GET and writes a retained report' {
        $hash = (Get-FileHash $recordPath).Hash
        $result = Invoke-EntraAssessment $recordPath $root
        $global:AssessmentFixture.Calls | Should Be 7
        (Test-Path $result.Report.Markdown) | Should Be $true
        $result.Report.Markdown | Should Match '\\reports\\'
        $result.Report.Markdown.StartsWith($result.RawPath) | Should Be $false
        (Test-Path (Join-Path $result.RawPath 'manifest.json')) | Should Be $true
        (Test-Path (Join-Path $result.RawPath 'snapshot.json')) | Should Be $true
        (Test-Path (Join-Path $result.RawPath 'entra-posture.md')) | Should Be $false
        (Get-Content (Join-Path $result.RawPath 'snapshot.json') -Raw) | Should Match 'synthetic@example.invalid'
        (Get-Content $result.Report.Markdown -Raw) | Should Not Match 'synthetic@example.invalid|fixture-user'
        (Get-FileHash $recordPath).Hash | Should Be $hash
        $global:AssessmentFixture.Connected | Should Be $false
        Assert-MockCalled Connect-MgGraph -ModuleName FieldKit.Entra -Scope It -Times 1 -Exactly -ParameterFilter {
            $TenantId -eq '11111111-1111-4111-8111-111111111111' -and $UseDeviceCode -and $ContextScope -eq 'Process' -and $Scopes.Count -eq 6
        }
        Assert-MockCalled Invoke-MgGraphRequest -ModuleName FieldKit.M365 -Scope It -Times 7 -Exactly -ParameterFilter { $Method -eq 'GET' }
    }
    It 'requires both naming permissions and gives each run different pseudonyms' {
        $a = Invoke-EntraAssessment $recordPath $root
        $b = Invoke-EntraAssessment $recordPath $root -NameAccounts
        (Get-Content $b.Report.Markdown -Raw) | Should Not Match 'synthetic@example.invalid'
        @($a.Findings | Where-Object Name -like 'MFA object-*')[0].Name | Should Not Be @($b.Findings | Where-Object Name -like 'MFA object-*')[0].Name
        $record.allowNamedAccounts = $true; $record | ConvertTo-Json | Set-Content $recordPath
        $c = Invoke-EntraAssessment $recordPath $root
        (Get-Content $c.Report.Markdown -Raw) | Should Not Match 'synthetic@example.invalid'
        $d = Invoke-EntraAssessment $recordPath $root -NameAccounts
        (Get-Content $d.Report.Markdown -Raw) | Should Match 'synthetic@example.invalid'
    }
    It 'diagnoses SDK URI failures without persisting exception messages or payloads' {
        Mock Invoke-MgGraphRequest {
            throw [UriFormatException]::new('SYNTHETIC-PRIVATE-MESSAGE synthetic-person@example.invalid')
        } -ModuleName FieldKit.M365
        $result = Invoke-EntraAssessment $recordPath $root -Diagnose
        $path = Join-Path $result.RawPath 'diagnostics.json'
        $diagnostics = Get-Content $path -Raw | ConvertFrom-Json
        @($diagnostics.PSObject.Properties).Count | Should Be 7
        foreach ($entry in $diagnostics.PSObject.Properties) {
            $entry.Value.ExceptionType | Should Be 'System.UriFormatException'
            ($null -eq $entry.Value.HttpStatus) | Should Be $true
            @($entry.Value.PSObject.Properties).Count | Should Be 2
        }
        foreach ($file in Get-ChildItem $root -File -Recurse) {
            (Get-Content $file.FullName -Raw) | Should Not Match 'SYNTHETIC-PRIVATE-MESSAGE|synthetic-person@example.invalid'
        }
    }
    It 'forwards Diagnose through the check CLI and retains numeric HTTP status without headers or body' {
        Mock Invoke-MgGraphRequest {
            if ($Uri -match '/userRegistrationDetails') {
                $errorObject = [InvalidOperationException]::new('SYNTHETIC-PRIVATE-MESSAGE')
                $errorObject | Add-Member -NotePropertyName Response -NotePropertyValue @{
                    StatusCode = [Net.HttpStatusCode]::Forbidden
                    Headers = @{ Private = 'SYNTHETIC-PRIVATE-HEADER' }; Content = 'SYNTHETIC-PRIVATE-BODY'
                }
                throw $errorObject
            }
            return @{ value = @() }
        } -ModuleName FieldKit.M365
        $null = & (Join-Path $PSScriptRoot '..\checks\Test-M365Posture.ps1') -Engagement $recordPath -OutputRoot $root -Diagnose
        $path = @(Get-ChildItem $root -Filter diagnostics.json -Recurse)[0].FullName
        $diagnostics = Get-Content $path -Raw | ConvertFrom-Json
        @($diagnostics.PSObject.Properties).Count | Should Be 1
        $diagnostics.Mfa.ExceptionType | Should Be 'System.InvalidOperationException'
        $diagnostics.Mfa.HttpStatus | Should Be 403
        foreach ($file in Get-ChildItem $root -File -Recurse) {
            (Get-Content $file.FullName -Raw) | Should Not Match 'SYNTHETIC-PRIVATE-(MESSAGE|HEADER|BODY)'
        }
    }
    It 'does not retain diagnostics unless explicitly requested' {
        Mock Invoke-MgGraphRequest { throw [UriFormatException]::new('SYNTHETIC-PRIVATE-MESSAGE') } -ModuleName FieldKit.M365
        $result = Invoke-EntraAssessment $recordPath $root
        (Test-Path (Join-Path $result.RawPath 'diagnostics.json')) | Should Be $false
        (Get-Content (Join-Path $result.RawPath 'snapshot.json') -Raw) | Should Not Match 'SYNTHETIC-PRIVATE-MESSAGE|ExceptionType|HttpStatus'
    }
    It 'refuses expired authorization and expired retention before device-code sign-in' {
        $record.authorisedOn = (Get-Date).AddDays(-8).ToString('yyyy-MM-dd'); $record.expiresOn = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
        $record | ConvertTo-Json | Set-Content $recordPath
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'B1 authorization is expired'
        $record.expiresOn = (Get-Date).AddDays(1).ToString('yyyy-MM-dd'); $record | ConvertTo-Json | Set-Content $recordPath
        $run = New-FieldKitRawRun $root $recordPath
        $m = Get-Content $run.ManifestPath -Raw | ConvertFrom-Json
        $m.createdAtUtc = [datetimeoffset]::UtcNow.AddDays(-8).ToString('o'); $m.deleteBy = ([datetimeoffset]$m.createdAtUtc).AddDays(7).ToString('o')
        $m | ConvertTo-Json | Set-Content $run.ManifestPath
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'B4 expired raw output'
        Assert-MockCalled Connect-MgGraph -ModuleName FieldKit.Entra -Scope It -Times 0 -Exactly
        $global:AssessmentFixture.Calls | Should Be 0
    }
    It 'rejects wrong tenants and additional consent before any request or raw run' {
        $global:AssessmentFixture.Context.TenantId = '22222222-2222-4222-8222-222222222222'
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'assessment stopped'
        $global:AssessmentFixture.Context.TenantId = $record.tenantId
        $global:AssessmentFixture.Context.Scopes += ('Directory.Read' + 'Write.All')
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'assessment stopped'
        $global:AssessmentFixture.Calls | Should Be 0
        @(Get-ChildItem $root -Filter manifest.json -Recurse).Count | Should Be 0
    }
    It 'stops if the signed record changes between requests without creating a raw run' {
        $global:AssessmentFixture.MutateRecord = $true
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'assessment stopped'
        $global:AssessmentFixture.Calls | Should Be 1
        @(Get-ChildItem $root -Filter manifest.json -Recurse).Count | Should Be 0
        $global:AssessmentFixture.Connected | Should Be $false
    }
    It 'revalidates authorization after the last response before persisting output' {
        $global:AssessmentFixture.MutateAt = 7
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'assessment stopped'
        $global:AssessmentFixture.Calls | Should Be 7
        @(Get-ChildItem $root -Filter manifest.json -Recurse).Count | Should Be 0
        $global:AssessmentFixture.Connected | Should Be $false
    }
    It 'runs the actual M365 CLI through collection and both reports' {
        $cli = Join-Path $PSScriptRoot '..\Invoke-FieldKit.ps1'
        $output = & $cli -M365 -Engagement $recordPath -OutputRoot $root
        ($output | Out-String) | Should Match 'Reports:'
        $global:AssessmentFixture.Calls | Should Be 7
        @(Get-ChildItem $root -Filter entra-posture.md -Recurse).Count | Should Be 1
        @(Get-ChildItem $root -Filter entra-posture.html -Recurse).Count | Should Be 1
        $global:AssessmentFixture.Connected | Should Be $false
    }
    It 'refuses a non-device-code or non-first-party context before collection' {
        $global:AssessmentFixture.Context.TokenCredentialType = 'InteractiveBrowser'
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'B8 requires the first-party device-code session'
        $global:AssessmentFixture.Context.TokenCredentialType = 'DeviceCode'
        $global:AssessmentFixture.Context.ClientId = '22222222-2222-4222-8222-222222222222'
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'B8 requires the first-party device-code session'
        $global:AssessmentFixture.Calls | Should Be 0
        @(Get-ChildItem $root -Filter manifest.json -Recurse).Count | Should Be 0
    }
    It 'refuses missing transport tooling before reader sign-in' {
        Mock Get-Command { $null } -ModuleName FieldKit.Entra -ParameterFilter { $Name -eq 'Invoke-MgGraphRequest' }
        { Invoke-EntraAssessment $recordPath $root } | Should Throw 'tooling check'
        Assert-MockCalled Connect-MgGraph -ModuleName FieldKit.Entra -Scope It -Times 0 -Exactly
        $global:AssessmentFixture.Calls | Should Be 0
    }
    It 'returns exit two from the real CLI on an invalid engagement before authenticating' {
        $cli = Join-Path $PSScriptRoot '..\Invoke-FieldKit.ps1'
        $output = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cli -M365 -Engagement (Join-Path $root 'missing.json') -OutputRoot $root
        $LASTEXITCODE | Should Be 2
        ($output -join ' ') | Should Match 'B1 cannot read engagement record'
        $global:AssessmentFixture.Calls | Should Be 0
    }
}
Remove-Item Function:\Get-MgContext, Function:\Connect-MgGraph, Function:\Disconnect-MgGraph, Function:\Set-MgRequestContext, Function:\Invoke-MgGraphRequest -ErrorAction SilentlyContinue
