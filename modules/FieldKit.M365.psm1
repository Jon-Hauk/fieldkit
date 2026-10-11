# Windows PowerShell 5.1. Shared M365 authorization, storage and transport gates.
Set-StrictMode -Version 2.0
# Shared by reads and lab writes; one Graph session per process.
$script:FieldKitRequestContextSet = $false

function Get-FieldKitPackVersions {
    $list = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\engagement-pack-versions.json') -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($list.schema -cne 'fieldkit-pack-versions/1' -or $list.versions -isnot [array] -or -not $list.versions.Count -or
        @($list.versions | Where-Object { $_ -isnot [string] -or $_ -cnotmatch '^[a-f0-9]{7,40}$' }).Count) {
        throw 'B1 invalid tracked pack-version list.'
    }
    $list.versions
}

function Assert-FieldKitEngagement {
    [CmdletBinding()]
    param(
        [guid]$TenantId,
        [Parameter(Mandatory)][string]$Engagement,
        [switch]$Preview
    )
    try { $record = Get-Content -LiteralPath $Engagement -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw 'B1 cannot read engagement record.' }
    if ($null -eq $record -or $record -is [array]) { throw 'B1 invalid engagement record.' }
    foreach ($field in @('schema', 'type', 'tenantId', 'authorisedBy', 'authorisedOn', 'expiresOn', 'allowNamedAccounts', 'packVersion')) {
        if ($null -eq $record.PSObject.Properties[$field]) { throw ('B1 missing engagement field: ' + $field) }
    }
    if ($record.schema -cne 'fieldkit-engagement/1' -or $record.allowNamedAccounts -isnot [bool] -or
        $record.authorisedBy -isnot [string] -or [string]::IsNullOrWhiteSpace($record.authorisedBy) -or
        $record.packVersion -notin @(Get-FieldKitPackVersions)) { throw 'B1 unsupported engagement schema or pack version.' }
    if ($record.type -cnotin @('lab', 'client')) { throw 'B1 invalid engagement type.' }
    $configured = [guid]::Empty
    if ($record.tenantId -isnot [string] -or -not [guid]::TryParseExact($record.tenantId, 'D', [ref]$configured)) {
        throw 'B1 tenantId must be a GUID.'
    }
    if ($PSBoundParameters.ContainsKey('TenantId') -and $configured -ne $TenantId) { throw 'B1 TenantId does not match engagement record.' }
    try {
        $start = [datetime]::ParseExact($record.authorisedOn, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $end = [datetime]::ParseExact($record.expiresOn, 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    } catch { throw 'B1 invalid authorization dates.' }
    if ($end -lt $start) { throw 'B1 inverted authorization dates.' }
    if (-not $Preview) {
        if ($configured -eq [guid]::Empty) { throw 'B1 zero tenant is for offline preview only.' }
        if ((Get-Date).Date -lt $start -or (Get-Date).Date -gt $end) { throw 'B1 authorization is expired or not yet valid.' }
    }
    return $record
}

function Get-FieldKitProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [Collections.IDictionary]) { return ,($Object[$Name]) }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return ,($p.Value) }
}

function Assert-FieldKitLocalPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$File)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2) -match '[:*?]') {
        throw 'B4 requires an absolute local Windows path without streams or wildcards.'
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -match '(?i)(^|\\)(OneDrive(?: - [^\\]+)?|Dropbox|Google Drive|iCloudDrive|Box)(\\|$)') { throw 'B4 cloud-path rejection.' }
    foreach ($name in @('OneDrive', 'OneDriveCommercial')) {
        foreach ($scope in @('Process', 'User', 'Machine')) {
            $value = [Environment]::GetEnvironmentVariable($name, $scope)
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $cloud = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($value)).TrimEnd('\')
                if ($full.Equals($cloud, [StringComparison]::OrdinalIgnoreCase) -or
                    $full.StartsWith($cloud + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'B4 environment-root rejection.' }
            }
        }
    }
    $cursor = $full
    $leaf = $true
    while ($cursor) {
        $item = $null
        try { $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop }
        catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
        if ($null -ne $item) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'B4 linked path rejected.' }
            if (-not $item.PSIsContainer -and -not ($leaf -and $File)) { throw 'B4 expected a directory.' }
            if ($item.PSIsContainer) {
                $marker = $null
                try { $marker = Get-Item -LiteralPath (Join-Path $cursor '.git') -Force -ErrorAction Stop }
                catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw } }
                if ($null -ne $marker) { throw 'B4 git-ancestor rejection.' }
            }
        }
        $parent = [IO.Directory]::GetParent($cursor)
        if ($null -eq $parent) { break }
        $cursor = $parent.FullName
        $leaf = $false
    }
    return $full.TrimEnd('\')
}

function Assert-FieldKitChildPath {
    param([string]$Root, [string]$Path)
    if (-not $Path.StartsWith($Root.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'B4 path must be beneath OutputRoot.'
    }
}

function Get-FieldKitTree {
    param([string]$Path)
    # Enumerate one level at a time: never follow a junction during discovery.
    foreach ($item in @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'B4 linked descendant rejected.' }
        if ($item.Name -eq '.git') { throw 'B4 nested git directory rejected.' }
        $null = Assert-FieldKitLocalPath $item.FullName -File:(-not $item.PSIsContainer)
        $item
        if ($item.PSIsContainer) { Get-FieldKitTree $item.FullName }
    }
}

function Get-FieldKitRawManifests {
    param([string]$OutputRoot)
    foreach ($file in @(Get-FieldKitTree $OutputRoot | Where-Object { -not $_.PSIsContainer -and $_.Name -eq 'manifest.json' })) {
        try {
            $m = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ((Get-FieldKitProperty $m 'schema') -cne 'fieldkit-raw/1') { throw 'schema' }
            $id = [guid]::Empty
            if (-not [guid]::TryParseExact([string](Get-FieldKitProperty $m 'runId'), 'D', [ref]$id) -or $id -eq [guid]::Empty) { throw 'runId' }
            $created = [datetimeoffset]::ParseExact([string](Get-FieldKitProperty $m 'createdAtUtc'), 'o', [Globalization.CultureInfo]::InvariantCulture)
            $delete = [datetimeoffset]::ParseExact([string](Get-FieldKitProperty $m 'deleteBy'), 'o', [Globalization.CultureInfo]::InvariantCulture)
            if ($created.Offset -ne [timespan]::Zero -or $delete -ne $created.AddDays(7)) { throw 'deadline' }
            $dir = $file.Directory
            if ($dir.Name -cne ('run-' + $id.ToString('D')) -or $dir.Parent.Name -ne 'raw') { throw 'ownership' }
            Assert-FieldKitChildPath $OutputRoot $dir.FullName
            [pscustomobject]@{ Path = $file.FullName; Directory = $dir.FullName; DeleteBy = $delete }
        } catch { throw ('B4 invalid retention manifest; review without deleting: ' + $file.FullName) }
    }
}

function Get-FieldKitRefusalMessage {
    param([Parameter(Mandatory)]$ErrorRecord, [Parameter(Mandatory)][string]$Fallback)
    $msg = [string]$ErrorRecord.Exception.Message
    if ($msg -match '^(B[1-8]\b|UNKN\b|P1 precondition)') { return $msg }
    return $Fallback
}

function New-FieldKitReportDir {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputRoot, [Parameter(Mandatory)][string]$Engagement)
    $root = Assert-FieldKitLocalPath $OutputRoot
    $record = Assert-FieldKitLocalPath $Engagement -File
    Assert-FieldKitChildPath $root $record
    $stamp = [datetimeoffset]::UtcNow.UtcDateTime.ToString('yyyyMMddTHHmmss', [Globalization.CultureInfo]::InvariantCulture)
    $dir = Join-Path (Split-Path $record -Parent) ('reports\' + $stamp + 'Z-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = Assert-FieldKitLocalPath $dir
    $null = New-Item -ItemType Directory -Path $dir -ErrorAction Stop
    return $dir
}

function Open-FieldKitOutputLock {
    param([string]$OutputRoot)
    $lockPath = Join-Path $OutputRoot '.fieldkit.lock'
    $null = Assert-FieldKitLocalPath $lockPath -File
    try { return [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None) }
    catch { throw 'B4 OutputRoot is locked or inaccessible; no run or sweep started.' }
}

function New-FieldKitRawRun {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$OutputRoot, [Parameter(Mandatory)][string]$Engagement)
    $root = Assert-FieldKitLocalPath $OutputRoot
    $record = Assert-FieldKitLocalPath $Engagement -File
    Assert-FieldKitChildPath $root $record
    if (-not (Test-Path -LiteralPath $record -PathType Leaf)) { throw 'B4 engagement record is missing.' }
    $lock = Open-FieldKitOutputLock $root
    try {
        foreach ($manifest in @(Get-FieldKitRawManifests $root)) {
            if ($manifest.DeleteBy -le [datetimeoffset]::UtcNow) {
                throw ('B4 expired raw output; run -Sweep before collecting: ' + $manifest.Directory)
            }
        }
        $id = [guid]::NewGuid().ToString('D')
        $raw = Join-Path (Split-Path $record -Parent) ('raw\run-' + $id)
        $null = Assert-FieldKitLocalPath $raw
        $null = New-Item -ItemType Directory -Path $raw -ErrorAction Stop
        $created = [datetimeoffset]::UtcNow
        $manifest = [ordered]@{ schema = 'fieldkit-raw/1'; runId = $id; createdAtUtc = $created.ToString('o'); deleteBy = $created.AddDays(7).ToString('o') }
        $path = Join-Path $raw 'manifest.json'
        $bytes = [Text.Encoding]::UTF8.GetBytes(($manifest | ConvertTo-Json))
        $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
        [pscustomobject]@{ RawPath = $raw; ManifestPath = $path; DeleteBy = $manifest.deleteBy }
    } finally { $lock.Dispose() }
}

function Assert-FieldKitOutputReady {
    param([Parameter(Mandatory)][string]$OutputRoot, [Parameter(Mandatory)][string]$Engagement)
    $root = Assert-FieldKitLocalPath $OutputRoot
    $record = Assert-FieldKitLocalPath $Engagement -File
    Assert-FieldKitChildPath $root $record
    if (-not (Test-Path -LiteralPath $record -PathType Leaf)) { throw 'B4 engagement record is missing.' }
    $lock = Open-FieldKitOutputLock $root
    try {
        foreach ($manifest in @(Get-FieldKitRawManifests $root)) {
            if ($manifest.DeleteBy -le [datetimeoffset]::UtcNow) { throw 'B4 expired raw output; run -Sweep before collecting.' }
        }
    } finally { $lock.Dispose() }
    return $root
}

function Remove-FieldKitExpiredRaw {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$OutputRoot)
    $root = Assert-FieldKitLocalPath $OutputRoot
    $lock = Open-FieldKitOutputLock $root
    try {
        # Validate the entire tree and every manifest before deleting anything.
        $expired = @(Get-FieldKitRawManifests $root | Where-Object { $_.DeleteBy -le [datetimeoffset]::UtcNow })
        foreach ($manifest in $expired) {
            if ($PSCmdlet.ShouldProcess($manifest.Directory, 'Delete expired FieldKit raw output')) {
                $null = Assert-FieldKitLocalPath $manifest.Directory
                $null = @(Get-FieldKitTree $manifest.Directory)
                # Keep the manifest until all data has been removed. A partial
                # deletion must continue to block collection on the next run.
                foreach ($child in @(Get-ChildItem -LiteralPath $manifest.Directory -Force -ErrorAction Stop)) {
                    if ($child.FullName -ne $manifest.Path) { Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction Stop }
                }
                Remove-Item -LiteralPath $manifest.Path -Force -ErrorAction Stop
                [IO.Directory]::Delete($manifest.Directory)
                [pscustomobject]@{ Status = 'INFO'; Detail = 'Expired raw output deleted'; Path = $manifest.Directory }
            }
        }
    } finally { $lock.Dispose() }
}

function Get-FieldKitReadScopes {
    @('User.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Policy.Read.All',
        'RoleEligibilitySchedule.Read.Directory', 'SharePointTenantSettings.Read.All')
}

function Get-FieldKitGraphErrorCode {
    param([Management.Automation.ErrorRecord]$Record)
    # Inspect structured fields only; never echo or substring-match service text.
    $errorObject = Get-FieldKitProperty $Record.Exception 'Error'
    $code = Get-FieldKitProperty $errorObject 'Code'
    if ($code -is [string]) { return $code }
    $bodies = @((Get-FieldKitProperty $Record.ErrorDetails 'Message'),
        (Get-FieldKitProperty $Record.Exception 'ResponseBody'))
    $response = Get-FieldKitProperty $Record.Exception 'Response'
    $content = Get-FieldKitProperty $response 'Content'
    if ($content -is [string]) { $bodies += $content }
    elseif ($null -ne $content -and $null -ne $content.PSObject.Methods['ReadAsStringAsync']) {
        try { $bodies += $content.ReadAsStringAsync().GetAwaiter().GetResult() } catch { }
    }
    foreach ($body in $bodies) {
        if ($body -isnot [string] -or [string]::IsNullOrWhiteSpace($body)) { continue }
        try {
            $parsed = $body | ConvertFrom-Json -ErrorAction Stop
            $code = Get-FieldKitProperty (Get-FieldKitProperty $parsed 'error') 'code'
            if ($code -is [string]) { return $code }
        } catch { }
    }
}

function Initialize-FieldKitGraphContext {
    # SDK 2.39.0 breaks subsequent requests if context is set after any request.
    # Keep this flag initialized at module load for StrictMode, and do not
    # force-reload the module or reconnect Graph within a production process.
    if (-not $script:FieldKitRequestContextSet) {
        $null = Set-MgRequestContext -MaxRetry 0 -ErrorAction Stop
        $script:FieldKitRequestContextSet = $true
    }
}

function Get-FieldKitGraphFailure {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord]$Record)
    # Deliberately exclude Message, ErrorDetails, headers, URI and payload.
    $response = Get-FieldKitProperty $Record.Exception 'Response'
    $status = Get-FieldKitProperty $response 'StatusCode'
    if ($null -eq $status) { $status = Get-FieldKitProperty $Record.Exception 'ResponseStatusCode' }
    $number = 0
    $httpStatus = $null
    if ($status -is [System.Enum]) { $status = [int]$status }
    if ([int]::TryParse([string]$status, [ref]$number) -and $number -ge 100 -and $number -le 599) { $httpStatus = $number }
    @{ ExceptionType = $Record.Exception.GetType().FullName; HttpStatus = $httpStatus }
}

function Invoke-FieldKitGraph {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET')][string]$Method = 'GET',
        [Parameter(Mandatory)][hashtable]$Budget,
        [scriptblock]$BeforeRequest = {},
        [scriptblock]$Request,
        [hashtable]$Failure
    )
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed) -or
        $parsed.Scheme -ne 'https' -or $parsed.Host -ne 'graph.microsoft.com' -or
        $parsed.Port -ne 443 -or $parsed.UserInfo -or $parsed.Fragment -or
        $parsed.AbsolutePath -notmatch '^/v1\.0/' -or $Uri -match '[\\\r\n]') {
        throw 'B6 requires a Microsoft Graph v1.0 HTTPS GET URL.'
    }
    for ($retry = 0; $retry -le 5; $retry++) {
        if ($null -ne $Failure) { $Failure.Clear() }
        if ($Budget.Requests -ge 2000) { throw 'UNKN request ceiling' }
        # Recheck authorization after every wait, before any retried request.
        & $BeforeRequest
        $Budget.Requests++
        try {
            if ($Request) { return & $Request $Uri }
            Initialize-FieldKitGraphContext
            # Sole SDK request call site. B6 CI verifies the literal method here.
            return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        } catch {
            if ($null -ne $Failure) {
                $safeFailure = Get-FieldKitGraphFailure $_
                $Failure.ExceptionType = $safeFailure.ExceptionType
                $Failure.HttpStatus = $safeFailure.HttpStatus
            }
            if ((Get-FieldKitGraphErrorCode $_) -ceq 'Authentication_RequestFromNonPremiumTenantOrB2CTenant') {
                throw 'UNKN tenant has no Entra ID P1 licence'
            }
            $response = Get-FieldKitProperty $_.Exception 'Response'
            $status = Get-FieldKitProperty $response 'StatusCode'
            if ($null -eq $status) { $status = Get-FieldKitProperty $_.Exception 'ResponseStatusCode' }
            if ($null -eq $status -or [int]$status -notin @(429, 503)) { throw 'UNKN Graph read unavailable' }
            if ($retry -eq 5) { throw 'UNKN throttled' }
            if ($Budget.Requests -ge 2000) { throw 'UNKN request ceiling' }
            $headers = Get-FieldKitProperty $response 'Headers'
            if ($null -eq $headers) { $headers = Get-FieldKitProperty $_.Exception 'ResponseHeaders' }
            $header = Get-FieldKitProperty $headers 'Retry-After'
            $seconds = [Math]::Pow(2, $retry)
            # Both dictionary headers and HttpResponseMessage.Headers occur in
            # SDK exception shapes. Support delta seconds and HTTP-date values.
            $typed = Get-FieldKitProperty $headers 'RetryAfter'
            if ($null -ne $typed) {
                if ($null -ne $typed.Delta) { $header = [string]$typed.Delta.TotalSeconds }
                elseif ($null -ne $typed.Date) { $header = $typed.Date.ToString('r') }
            }
            if ($header -is [array]) { $header = $header[0] }
            if ($null -ne $header) {
                $delta = 0
                $date = [datetimeoffset]::MinValue
                if ([int]::TryParse([string]$header, [ref]$delta) -and $delta -ge 0) { $seconds = $delta }
                elseif ([datetimeoffset]::TryParse([string]$header, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
                    $seconds = [Math]::Max(0, [Math]::Ceiling(($date - [datetimeoffset]::UtcNow).TotalSeconds))
                }
            }
            # Long Retry-After values are honored without a single uninterruptible wait.
            while ($seconds -gt 0) {
                $chunk = [int][Math]::Min(60, $seconds)
                Start-Sleep -Seconds $chunk
                $seconds -= $chunk
            }
        }
    }
}

Export-ModuleMember -Function Get-FieldKitProperty, Get-FieldKitPackVersions, Assert-FieldKitEngagement, Assert-FieldKitOutputReady, Assert-FieldKitLocalPath, New-FieldKitRawRun, New-FieldKitReportDir, Remove-FieldKitExpiredRaw, Get-FieldKitReadScopes, Get-FieldKitRefusalMessage, Initialize-FieldKitGraphContext, Get-FieldKitGraphFailure, Invoke-FieldKitGraph
