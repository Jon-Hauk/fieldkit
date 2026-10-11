Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.M365.psm1') -Force
Describe 'B6 GET-only Graph transport' {
    BeforeEach { $budget = @{ Requests = 0 } }
    It 'rejects non-GET before executing transport' {
        foreach ($method in @('POST', 'PATCH', 'PUT', 'DELETE', 'HEAD')) {
            { Invoke-FieldKitGraph -Uri 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Method $method -Request { throw 'transport must not execute' } } | Should Throw 'Method'
        }
    }
    It 'rejects foreign origins, credentials in URLs, fragments and unsupported versions' {
        foreach ($uri in @('http://graph.microsoft.com/v1.0/users', 'https://example.invalid/v1.0/users',
            'https://graph.microsoft.com:444/v1.0/users', 'https://user@graph.microsoft.com/v1.0/users',
            'https://graph.microsoft.com/v1.0/users#fragment', 'https://graph.microsoft.com/beta/users')) {
            { Invoke-FieldKitGraph $uri -Budget $budget -Request { throw 'transport must not execute' } } | Should Throw 'B6 requires'
        }
    }
    It 'passes the exact validated GET URL to the transport once' {
        $result = Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users?$top=1' -Budget $budget -Request { param($Uri) @{ seen = $Uri } }
        $result.seen | Should Be 'https://graph.microsoft.com/v1.0/users?$top=1'
    }
}

Describe 'B7 bounded sequential requests' {
    BeforeEach {
        $budget = @{ Requests = 0 }
        Mock Start-Sleep {} -ModuleName FieldKit.M365
    }
    It 'honors Retry-After on 429 and stops after five retries' {
        $request = {
            $e = New-Object Exception 'private payload must not be echoed'
            $e | Add-Member NoteProperty Response ([pscustomobject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = '3' } })
            throw $e
        }
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request $request } | Should Throw 'UNKN throttled'
        $budget.Requests | Should Be 6
        Assert-MockCalled Start-Sleep -ModuleName FieldKit.M365 -Scope It -Times 5 -Exactly -ParameterFilter { $Seconds -eq 3 }
    }
    It 'uses exponential backoff on 503 when Retry-After is absent' {
        $request = {
            $e = New-Object Exception 'fixture'
            $e | Add-Member NoteProperty Response ([pscustomobject]@{ StatusCode = 503; Headers = @{} })
            throw $e
        }
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request $request } | Should Throw 'UNKN throttled'
        foreach ($delay in @(1, 2, 4, 8, 16)) {
            Assert-MockCalled Start-Sleep -ModuleName FieldKit.M365 -Scope It -Times 1 -Exactly -ParameterFilter { $Seconds -eq $delay }
        }
    }
    It 'supports HTTP-date Retry-After and recovers on the following attempt' {
        $request = {
            if ($budget.Requests -eq 1) {
                $e = New-Object Exception 'fixture'
                $e | Add-Member NoteProperty ResponseStatusCode 503
                $e | Add-Member NoteProperty ResponseHeaders @{ 'Retry-After' = [datetimeoffset]::UtcNow.AddSeconds(10).ToString('r') }
                throw $e
            }
            @{ recovered = $true }
        }
        $result = Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request $request
        $result.recovered | Should Be $true
        $budget.Requests | Should Be 2
        Assert-MockCalled Start-Sleep -ModuleName FieldKit.M365 -Scope It -Times 1 -Exactly -ParameterFilter { $Seconds -ge 9 -and $Seconds -le 10 }
    }
    It 'counts retries against the shared 2000-request ceiling and makes no further call' {
        $budget.Requests = 1999
        $request = {
            $e = New-Object Exception 'fixture'
            $e | Add-Member NoteProperty Response ([pscustomobject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = '1' } })
            throw $e
        }
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request $request } | Should Throw 'UNKN request ceiling'
        $budget.Requests | Should Be 2000
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/groups' -Budget $budget -Request { throw 'must not execute' } } | Should Throw 'UNKN request ceiling'
        Assert-MockCalled Start-Sleep -ModuleName FieldKit.M365 -Scope It -Times 0 -Exactly
    }
    It 'permits exactly 2000 successful calls across resources then refuses the next' {
        for ($i = 0; $i -lt 2000; $i++) {
            $null = Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request { @{ value = @() } }
        }
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/groups' -Budget $budget -Request { throw 'must not execute' } } | Should Throw 'UNKN request ceiling'
        $budget.Requests | Should Be 2000
    }
    It 'does not retry an access denial or expose service error text' {
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -Request { throw 'private identity payload' } } | Should Throw 'UNKN Graph read unavailable'
        $budget.Requests | Should Be 1
        Assert-MockCalled Start-Sleep -ModuleName FieldKit.M365 -Scope It -Times 0 -Exactly
    }
    It 'rechecks the session after a wait and prevents a retry if it changed' {
        $guard = { if ($budget.Requests -eq 1) { throw 'session changed' } }
        $request = {
            $e = New-Object Exception 'fixture'
            $e | Add-Member NoteProperty Response ([pscustomobject]@{ StatusCode = 429; Headers = @{ 'Retry-After' = '1' } })
            throw $e
        }
        { Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget -BeforeRequest $guard -Request $request } | Should Throw 'session changed'
        $budget.Requests | Should Be 1
    }
}

Describe 'B7 SDK request context is applied once per process' {
    # Graph SDK 2.39.0: Set-MgRequestContext after any request has been sent
    # makes every later Invoke-MgGraphRequest throw UriFormatException, so the
    # per-request call left only the first resource readable (live 2026-09-20).
    BeforeEach {
        Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.M365.psm1') -Force
        $budget = @{ Requests = 0 }
        function global:Set-MgRequestContext { [CmdletBinding()] param($MaxRetry) }
        function global:Invoke-MgGraphRequest { [CmdletBinding()] param($Method, $Uri, $OutputType) }
        $global:TransportFixture = @{ ContextCalls = 0; Requests = 0 }
        Mock Set-MgRequestContext { $global:TransportFixture.ContextCalls++ } -ModuleName FieldKit.M365
        Mock Invoke-MgGraphRequest { $global:TransportFixture.Requests++; @{ value = @() } } -ModuleName FieldKit.M365
    }
    AfterEach { Remove-Item Function:\Set-MgRequestContext, Function:\Invoke-MgGraphRequest, Variable:\TransportFixture -ErrorAction SilentlyContinue }
    It 'configures the SDK before the first request and never again' {
        foreach ($i in 1..3) { $null = Invoke-FieldKitGraph 'https://graph.microsoft.com/v1.0/users' -Budget $budget }
        $global:TransportFixture.Requests | Should Be 3
        $global:TransportFixture.ContextCalls | Should Be 1
    }
}
