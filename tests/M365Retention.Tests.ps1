# Pester fixtures only: every path belongs to this test's fresh private root.
$modulePath = Join-Path $PSScriptRoot '..\modules\FieldKit.M365.psm1'
Import-Module $modulePath -Force

Describe 'B4 local storage and seven-day retention' {
    BeforeEach {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('fieldkit-retention-' + [guid]::NewGuid().ToString('N'))
        $engagementDir = Join-Path $root 'engagement'
        $null = New-Item -ItemType Directory -Path $engagementDir
        $record = Join-Path $engagementDir 'engagement.json'
        $pack = Join-Path $engagementDir 'engagement.md'
        [IO.File]::WriteAllText($record, '{"fixture":true}')
        [IO.File]::WriteAllText($pack, 'fixture signed pack; preserve byte for byte')
    }
    AfterEach {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    }
    It 'sets a UTC deadline seven days after this run and never renews an old run' {
        $first = New-FieldKitRawRun -OutputRoot $root -Engagement $record
        $m = Get-Content $first.ManifestPath -Raw | ConvertFrom-Json
        (([datetimeoffset]$m.deleteBy) - ([datetimeoffset]$m.createdAtUtc)).TotalDays | Should Be 7
        ([datetimeoffset]$m.createdAtUtc).Offset.TotalSeconds | Should Be 0
        $hash = (Get-FileHash $first.ManifestPath).Hash
        $next = New-FieldKitRawRun -OutputRoot $root -Engagement $record
        $next.RawPath | Should Not Be $first.RawPath
        (Get-FileHash $first.ManifestPath).Hash | Should Be $hash
    }
    It 'blocks collection until expired data is swept and preserves signatures and unexpired data' {
        $signedHash = (Get-FileHash $pack).Hash
        $recordHash = (Get-FileHash $record).Hash
        $old = New-FieldKitRawRun $root $record
        $live = New-FieldKitRawRun $root $record
        [IO.File]::WriteAllText((Join-Path $old.RawPath 'response.json'), 'private fixture')
        [IO.File]::WriteAllText((Join-Path $live.RawPath 'response.json'), 'keep fixture')
        $m = Get-Content $old.ManifestPath -Raw | ConvertFrom-Json
        $m.createdAtUtc = [datetimeoffset]::UtcNow.AddDays(-8).ToString('o')
        $m.deleteBy = ([datetimeoffset]$m.createdAtUtc).AddDays(7).ToString('o')
        $m | ConvertTo-Json | Set-Content $old.ManifestPath
        { New-FieldKitRawRun $root $record } | Should Throw 'expired raw output'
        $null = Remove-FieldKitExpiredRaw $root -WhatIf
        (Test-Path $old.ManifestPath) | Should Be $true
        $null = Remove-FieldKitExpiredRaw $root -Confirm:$false
        (Test-Path $old.RawPath) | Should Be $false
        (Test-Path (Join-Path $live.RawPath 'response.json')) | Should Be $true
        (Get-FileHash $pack).Hash | Should Be $signedHash
        (Get-FileHash $record).Hash | Should Be $recordHash
        $null = New-FieldKitRawRun $root $record
    }
    It 'does not delete a sibling lab ledger when sweeping expired raw output' {
        $ledger = Join-Path $engagementDir 'lab-ledger.json'
        [IO.File]::WriteAllText($ledger, '{"schema":"fieldkit-lab-ledger/1","note":"ownership"}')
        $old = New-FieldKitRawRun $root $record
        [IO.File]::WriteAllText((Join-Path $old.RawPath 'snapshot.json'), 'raw fixture')
        $m = Get-Content $old.ManifestPath -Raw | ConvertFrom-Json
        $m.createdAtUtc = [datetimeoffset]::UtcNow.AddDays(-8).ToString('o')
        $m.deleteBy = ([datetimeoffset]$m.createdAtUtc).AddDays(7).ToString('o')
        $m | ConvertTo-Json | Set-Content $old.ManifestPath
        $null = Remove-FieldKitExpiredRaw $root -Confirm:$false
        (Test-Path $old.RawPath) | Should Be $false
        (Test-Path $ledger) | Should Be $true
        (Get-Content $ledger -Raw) | Should Match 'ownership'
    }
    It 'refuses malformed and extended deadlines without deleting data' {
        $run = New-FieldKitRawRun $root $record
        $m = Get-Content $run.ManifestPath -Raw | ConvertFrom-Json
        $m.deleteBy = ([datetimeoffset]$m.createdAtUtc).AddDays(8).ToString('o')
        $m | ConvertTo-Json | Set-Content $run.ManifestPath
        { New-FieldKitRawRun $root $record } | Should Throw 'invalid retention manifest'
        { Remove-FieldKitExpiredRaw $root -Confirm:$false } | Should Throw 'invalid retention manifest'
        (Test-Path $run.ManifestPath) | Should Be $true
    }
    It 'does not trust a manifest planted beside the signed pack' {
        $run = New-FieldKitRawRun $root $record
        Copy-Item $run.ManifestPath (Join-Path $engagementDir 'manifest.json')
        { Remove-FieldKitExpiredRaw $root -Confirm:$false } | Should Throw 'invalid retention manifest'
        (Test-Path $pack) | Should Be $true
    }
    It 'rejects git ancestry including a worktree marker file' {
        [IO.File]::WriteAllText((Join-Path $root '.git'), 'gitdir: fixture')
        { New-FieldKitRawRun $root $record } | Should Throw 'git-ancestor'
    }
    It 'rejects every prohibited sync path and a custom OneDrive root' {
        foreach ($name in @('OneDrive', 'Dropbox', 'Google Drive', 'iCloudDrive', 'Box')) {
            { Assert-FieldKitLocalPath (Join-Path $root $name) } | Should Throw 'cloud-path'
        }
        $before = $env:OneDrive
        try {
            $env:OneDrive = $root
            { New-FieldKitRawRun $root $record } | Should Throw 'environment-root'
        } finally { $env:OneDrive = $before }
    }
    It 'matches cloud folders as segments while allowing Sandbox Toolbox and Xbox' {
        foreach ($name in @('Sandbox', 'Toolbox', 'Xbox')) {
            { Assert-FieldKitLocalPath (Join-Path $root ($name + '\reports')) } | Should Not Throw
        }
        foreach ($name in @('Box', 'OneDrive - Example', 'Dropbox')) {
            { Assert-FieldKitLocalPath (Join-Path $root ($name + '\reports')) } | Should Throw 'cloud-path'
        }
    }
    It 'rejects an engagement record outside OutputRoot and alternate data streams' {
        { New-FieldKitRawRun (Join-Path $root 'different-root') $record } | Should Throw 'beneath OutputRoot'
        { Assert-FieldKitLocalPath ($record + ':stream') -File } | Should Throw 'absolute local'
    }
    It 'refuses a concurrent run or sweep' {
        $lock = [IO.File]::Open((Join-Path $root '.fieldkit.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        try {
            { New-FieldKitRawRun $root $record } | Should Throw 'locked or inaccessible'
            { Remove-FieldKitExpiredRaw $root } | Should Throw 'locked or inaccessible'
        } finally { $lock.Dispose() }
    }
    It 'does not traverse a junction during manifest discovery or cleanup' {
        $target = Join-Path $root 'outside'
        $null = New-Item -ItemType Directory -Path $target
        $link = Join-Path $engagementDir 'link'
        $null = New-Item -ItemType Junction -Path $link -Target $target
        try {
            { New-FieldKitRawRun $root $record } | Should Throw 'linked descendant'
            { Remove-FieldKitExpiredRaw $root } | Should Throw 'linked descendant'
        } finally { [IO.Directory]::Delete($link) }
    }
}
