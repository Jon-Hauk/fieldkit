<#
.SYNOPSIS
    Check a Windows host against a small-business security baseline.

.DESCRIPTION
    The findings here are the ones that actually come up on SMB endpoints,
    chosen because each is both common and cheap to fix. This is deliberately
    NOT a CIS benchmark: a 400-item report gets skimmed and filed, a 20-item
    report gets acted on.

    Read-only. Reports what is true; changes nothing. Several controls need
    administrator rights to read and will report UNKN unelevated - that is a
    visibility limit, not a finding.

.EXAMPLE
    .\Test-SecurityBaseline.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-SecurityBaseline.ps1

.NOTES
    ASCII only, Windows PowerShell 5.1 compatible. See ..\README.md.
    Exit code 0 = no FAIL findings, 1 = at least one FAIL.
#>
[CmdletBinding()]
param(
    [switch]$NoReport,
    # Set by Invoke-FieldKit.ps1, which owns the findings collection, the
    # report and the exit code when several checks run as one engagement.
    [switch]$Chained,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Common.psm1')
if (-not $Chained) { Clear-FieldKitFindings }

$isAdmin = Get-FieldKitElevation

Write-Host ""
Write-Host "Security baseline - $env:COMPUTERNAME" -ForegroundColor Cyan
if (-not $isAdmin) {
    Write-Host "running unelevated - some controls will report UNKN" -ForegroundColor DarkYellow
}

# -------------------------------------------------------------------------
Set-FieldKitSection 'Malware defence'

Test-Control 'Defender real-time protection' {
    $m = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $m) { return Unknown 'Defender status unavailable (third-party AV?)' }
    Verdict $m.RealTimeProtectionEnabled ("real-time={0}" -f $m.RealTimeProtectionEnabled)
} 'Set-MpPreference -DisableRealtimeMonitoring $false'

Test-Control 'Antivirus signature age' {
    $m = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $m) { return Unknown 'Defender status unavailable' }
    $age = (New-TimeSpan -Start $m.AntivirusSignatureLastUpdated -End (Get-Date)).Days
    # Signatures update daily. Anything past a few days means the machine is
    # not talking to update infrastructure, which is the real finding.
    if ($age -gt 7) { Fail "$age days old" }
    elseif ($age -gt 3) { Warn "$age days old" }
    else { Pass "$age day(s) old" }
} 'Update-MpSignature, then investigate why updates stopped'

Test-Control 'Tamper protection' {
    $m = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if (-not $m) { return Unknown 'Defender status unavailable' }
    if ($null -eq $m.IsTamperProtected) { return Unknown 'not reported on this build' }
    Verdict $m.IsTamperProtected ("enabled={0}" -f $m.IsTamperProtected)
} 'Enable Tamper Protection in Windows Security > Virus & threat protection'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Host hardening'

Test-Control 'Firewall on (all profiles)' {
    $off = @(Get-NetFirewallProfile -ErrorAction Stop |
             Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name)
    if ($off.Count -gt 0) { Fail ("disabled: " + ($off -join ', ')) }
    else { Pass 'Domain, Private, Public' }
} 'Set-NetFirewallProfile -All -Enabled True'

Test-Control 'BitLocker on system drive' {
    if (-not $isAdmin) { return Unknown 'needs admin to read' }
    $v = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if (-not $v) { return Fail 'no BitLocker volume - system drive unencrypted' }
    Verdict ($v.ProtectionStatus -eq 'On') ("{0}, {1}% encrypted" -f $v.ProtectionStatus, $v.EncryptionPercentage)
} 'manage-bde -on C:  (a stolen unencrypted laptop is a reportable breach)'

Test-Control 'Secure Boot' {
    if (-not $isAdmin) { return Unknown 'needs admin to read UEFI state' }
    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
    Verdict $sb ("enabled={0}" -f $sb)
} 'Enable Secure Boot in UEFI firmware settings'

Test-Control 'UAC enabled' {
    $v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
          -Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA
    Verdict ($v -eq 1) ("EnableLUA={0}" -f $v)
} 'Set EnableLUA to 1 and reboot'

Test-Control 'SMBv1 not installed' {
    # SMBv1 is how ransomware moved laterally in every major SMB incident of
    # the last decade. It is off by default on current Windows, but upgraded
    # machines carry it forward.
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if (-not $f) { return Unknown 'feature state unreadable (needs admin)' }
    Verdict ($f.State -ne 'Enabled') ("state={0}" -f $f.State)
} 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'

Test-Control 'PowerShell v2 engine absent' {
    # PSv2 bypasses script block logging and AMSI. Attackers downgrade to it
    # deliberately.
    $f = Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -ErrorAction SilentlyContinue
    if (-not $f) { return Unknown 'feature state unreadable (needs admin)' }
    Verdict ($f.State -ne 'Enabled') ("state={0}" -f $f.State)
} 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Accounts'

Test-Control 'Local administrators' {
    # Everyday accounts holding local admin is the single most common finding
    # on an SMB endpoint, and the one clients push back on hardest.
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
                     Select-Object -ExpandProperty Name)
    } catch {
        return Unknown 'cannot enumerate (needs admin)'
    }
    $txt = ($members -join ', ')
    if ($members.Count -gt 3) { Warn ("{0} members: {1}" -f $members.Count, $txt) }
    else { Info $txt }
} 'Remove day-to-day accounts from Administrators; use a separate admin login'

Test-Control 'Guest account disabled' {
    $g = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    if (-not $g) { return Pass 'no Guest account' }
    Verdict (-not $g.Enabled) ("enabled={0}" -f $g.Enabled)
} 'Disable-LocalUser -Name Guest'

Test-Control 'Accounts with non-expiring passwords' {
    $u = @(Get-LocalUser -ErrorAction SilentlyContinue |
           Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
    if ($u.Count -eq 0) { return Pass 'none' }
    Warn (($u | Select-Object -ExpandProperty Name) -join ', ')
} 'Review these accounts; service accounts should be documented, not implicit'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Remote access and exposure'

Test-Control 'RDP disabled' {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
             -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($deny -eq 1) { Pass 'RDP disabled' } else { Warn 'RDP enabled' }
} 'If RDP is needed, reach it over a VPN or overlay network - never port-forward 3389'

Test-Control 'RDP network level authentication' {
    $deny = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' `
             -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($deny -eq 1) { return Pass 'n/a - RDP disabled' }
    $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
            -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    Verdict ($nla -eq 1) ("NLA={0}" -f $nla)
} 'Require Network Level Authentication for RDP'

Test-Control 'Services listening on all interfaces' {
    $risky = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -eq '0.0.0.0' -and $_.LocalPort -in 22,23,135,139,445,1433,3306,3389,5432,5900 })
    if ($risky.Count -eq 0) { return Pass 'none of the usual suspects' }
    $ports = (($risky | Select-Object -ExpandProperty LocalPort -Unique | Sort-Object) -join ', ')
    Warn "listening wide: $ports"
} 'Bind to 127.0.0.1 or a VPN interface, or firewall these to trusted sources'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Patching'

Test-Control 'Last successful update' {
    $h = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending |
         Select-Object -First 1
    if (-not $h -or -not $h.InstalledOn) { return Unknown 'no dated hotfix history' }
    $age = (New-TimeSpan -Start $h.InstalledOn -End (Get-Date)).Days
    $txt = "{0} ({1} days ago)" -f $h.InstalledOn.ToString('yyyy-MM-dd'), $age
    # Patch Tuesday is monthly, so 35+ days means at least one cycle missed.
    if ($age -gt 60) { Fail $txt }
    elseif ($age -gt 35) { Warn $txt }
    else { Pass $txt }
} 'Run Windows Update and confirm it completes; check for a stuck update service'

Test-Control 'Windows Update service' {
    $s = Get-Service wuauserv -ErrorAction SilentlyContinue
    if (-not $s) { return Unknown 'service not found' }
    # Disabled here is a deliberate act, and worth surfacing as a finding
    # rather than a curiosity.
    if ($s.StartType -eq 'Disabled') { Fail 'wuauserv is Disabled' }
    else { Pass ("start={0}, status={1}" -f $s.StartType, $s.Status) }
} 'Set-Service wuauserv -StartupType Manual'

# -------------------------------------------------------------------------
if ($Chained) { return }

$summary = Write-FieldKitSummary

if (-not $NoReport) {
    if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot '..\reports' }
    $r = Export-FieldKitReport -Path $ReportPath -Title 'Security baseline' -Target $env:COMPUTERNAME
    Write-Host ""
    Write-Host "report: $($r.Html)" -ForegroundColor Cyan
}

if ($summary.Fail -gt 0) { exit 1 } else { exit 0 }
