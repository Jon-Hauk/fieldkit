<#
.SYNOPSIS
    Check how a Windows host is managed, hardened, and who can get into it.

.DESCRIPTION
    Test-SecurityBaseline.ps1 answers "is this machine defended". This one
    answers the four questions an MSP or an endpoint-management engagement
    actually gets asked:

        1. Is this device under management at all, and by whom?
        2. What hardening is on beyond the antivirus defaults?
        3. Can data walk out of it - removable media, unescrowed disk keys?
        4. Who can sign in, how strong is that, and did anyone leave?

    Deliberately vendor-neutral. It reads the state Intune, ManageEngine
    Endpoint Central, Kandji or a GPO would all be setting, rather than
    looking for one console's agent. A finding here is true whichever tool
    the client bought, which is also what makes the report portable between
    them.

    Read-only. Reports what is true; changes nothing. Controls that need
    administrator rights report UNKN unelevated - that is a visibility
    limit, not a finding.

.EXAMPLE
    .\Test-EndpointManagement.ps1

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-EndpointManagement.ps1

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
    [string]$ReportPath,
    # Days without a logon before an enabled account is called dormant. 90 is
    # the usual offboarding SLA; shorten it for a site with contractors.
    [int]$DormantDays = 90
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Common.psm1')
if (-not $Chained) { Clear-FieldKitFindings }

$isAdmin = Get-FieldKitElevation

Write-Host ""
Write-Host "Endpoint management - $env:COMPUTERNAME" -ForegroundColor Cyan
if (-not $isAdmin) {
    Write-Host "running unelevated - some controls will report UNKN" -ForegroundColor DarkYellow
}

# Read a registry value without turning a missing key into an exception. Most
# policy here is absent rather than set, and absent is the common answer.
function Get-PolicyValue {
    param([string]$Path, [string]$Name)
    try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

# dsregcmd is the only supported view of the join state and it prints a
# report, not objects. Parse it once; the controls below read the result.
$joinState = @{}
try {
    foreach ($line in (dsregcmd /status 2>$null)) {
        if ($line -match '^\s*([A-Za-z][A-Za-z ]+?)\s*:\s*(.+?)\s*$') {
            $joinState[$matches[1].Trim()] = $matches[2].Trim()
        }
    }
} catch { }

# -------------------------------------------------------------------------
Set-FieldKitSection 'Device management'

Test-Control 'Directory join state' {
    if ($joinState.Count -eq 0) { return Unknown 'dsregcmd produced no output' }
    $joined = @()
    foreach ($k in 'AzureAdJoined', 'DomainJoined', 'EnterpriseJoined', 'WorkplaceJoined') {
        if ($joinState[$k] -eq 'YES') { $joined += $k }
    }
    if ($joined.Count -eq 0) {
        # Not a failure by itself. A sole trader's laptop is correctly
        # standalone; a staff device that is standalone has no policy path.
        return Warn 'standalone - no directory, so no central policy path'
    }
    Info ($joined -join ', ')
} 'If this device holds company data, join it to Entra ID or the domain so policy can reach it'

Test-Control 'MDM enrolment' {
    # HKLM\...\Enrollments always has entries; only ones carrying a provider
    # name and a discovery URL are a real MDM channel. The rest are the
    # per-user placeholders Windows creates on its own.
    $real = @()
    try {
        foreach ($e in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop) {
            $p = Get-ItemProperty $e.PSPath -ErrorAction SilentlyContinue
            if ($p.ProviderID -and $p.DiscoveryServiceFullURL) {
                $real += ('{0} ({1})' -f $p.ProviderID, ([uri]$p.DiscoveryServiceFullURL).Host)
            }
        }
    } catch { return Unknown 'enrolment key unreadable' }
    if ($real.Count -eq 0) { return Warn 'no MDM provider enrolled' }
    Info (($real | Select-Object -Unique) -join '; ')
} 'Enrol in the tenant MDM (Intune, Endpoint Central, or the client''s own) so configuration is enforced rather than asked for'

Test-Control 'Management agents present' {
    # Name-matched deliberately: this is the one control that is allowed to
    # know vendors, because "which console owns this box" is a question the
    # generic state cannot answer.
    $patterns = 'ManageEngine|Endpoint Central|DesktopCentral|Intune|IntuneManagementExtension|Teramind|NinjaRMM|Datto|ConnectWise|Kaseya|SentinelOne|CrowdStrike|Sophos|JumpCloud|Automate'
    $svc = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $patterns -or $_.Name -match $patterns })
    if ($svc.Count -eq 0) { return Info 'none detected' }
    Info (($svc | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join '; ')
}

Test-Control 'Remote-access tooling' {
    # An unmanaged remote-access tool is how most small offices actually get
    # supported, and also how most of them get breached. Report, do not judge.
    $patterns = 'TeamViewer|AnyDesk|ScreenConnect|LogMeIn|Splashtop|RustDesk|VNC|Chrome Remote'
    $svc = @(Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $patterns -or $_.Name -match $patterns })
    if ($svc.Count -eq 0) { return Pass 'no third-party remote-access service' }
    Warn (($svc | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join '; ')
} 'Confirm each remote-access tool is sanctioned, MFA-protected and inventoried; remove the rest'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Device hardening'

Test-Control 'Virtualisation-based security' {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if (-not $dg) { return Unknown 'DeviceGuard class unavailable' }
    # 2 = running. 1 = configured but not running, which reads as on and is not.
    Verdict ($dg.VirtualizationBasedSecurityStatus -eq 2) `
        ("VBS status={0}" -f $dg.VirtualizationBasedSecurityStatus)
} 'Enable VBS and memory integrity in Windows Security > Device security > Core isolation'

Test-Control 'Credential Guard' {
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if (-not $dg) { return Unknown 'DeviceGuard class unavailable' }
    $running = @($dg.SecurityServicesRunning)
    # 1 = Credential Guard, 2 = HVCI / memory integrity.
    $hasCg = $running -contains 1
    $hasCi = $running -contains 2
    if ($hasCg) { return Pass 'Credential Guard running' }
    if ($hasCi) { return Warn 'memory integrity on, Credential Guard off' }
    Warn 'no VBS security services running'
} 'Turn on Credential Guard so LSASS secrets cannot be dumped from an admin session'

Test-Control 'LSA protection (RunAsPPL)' {
    $v = Get-PolicyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    if ($null -eq $v) { return Warn 'not configured' }
    Verdict ($v -ge 1) ("RunAsPPL={0}" -f $v)
} 'Set HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1 and reboot'

Test-Control 'Attack surface reduction rules' {
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $p) { return Unknown 'Defender preferences unavailable' }
    $ids = @($p.AttackSurfaceReductionRules_Ids)
    if ($ids.Count -eq 0) { return Fail 'no ASR rules configured' }
    $act = @($p.AttackSurfaceReductionRules_Actions)
    # 1 = block, 2 = audit, 6 = warn. Audit-only is the trap: the console is
    # green, the rule stops nothing.
    $block = @($act | Where-Object { $_ -eq 1 }).Count
    $audit = @($act | Where-Object { $_ -eq 2 }).Count
    $detail = "{0} configured: {1} blocking, {2} audit-only" -f $ids.Count, $block, $audit
    if ($block -eq 0) { return Fail $detail }
    if ($audit -gt 0) { return Warn $detail }
    Pass $detail
} 'Move audit-only ASR rules to block once the audit log is clean'

Test-Control 'Network protection' {
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $p) { return Unknown 'Defender preferences unavailable' }
    # 0 = off, 1 = block, 2 = audit.
    switch ([int]$p.EnableNetworkProtection) {
        1 { Pass 'blocking' }
        2 { Warn 'audit only - logs, does not block' }
        default { Fail 'off' }
    }
} 'Set-MpPreference -EnableNetworkProtection Enabled'

Test-Control 'Application control' {
    # AppLocker and WDAC are alternatives, not a pair; either one satisfies
    # the control, so report whichever is actually enforcing.
    $dg = Get-CimInstance -ClassName Win32_DeviceGuard `
        -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    # 1 = audit, 2 = enforced.
    if ($dg -and $dg.CodeIntegrityPolicyEnforcementStatus -eq 2) {
        return Pass 'WDAC code integrity enforced'
    }
    $al = $null
    try { $al = Get-AppLockerPolicy -Effective -ErrorAction Stop } catch { }
    $enforced = @()
    if ($al) {
        foreach ($rc in $al.RuleCollections) {
            if ($rc.Count -gt 0 -and $rc.EnforcementMode -ne 'NotConfigured') {
                $enforced += ('{0}={1}' -f $rc.RuleCollectionType, $rc.EnforcementMode)
            }
        }
    }
    if ($enforced.Count -gt 0) { return Pass ('AppLocker: ' + ($enforced -join ', ')) }
    if ($dg -and $dg.CodeIntegrityPolicyEnforcementStatus -eq 1) {
        return Warn 'WDAC in audit mode only'
    }
    Warn 'no application control - any signed or unsigned binary runs'
} 'Start WDAC or AppLocker in audit mode, review a fortnight of logs, then enforce'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Data loss prevention'

Test-Control 'Removable storage policy' {
    # Two independent paths block USB mass storage. Check both before
    # concluding it is open, or the report contradicts the client's console.
    $deny = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices' 'Deny_All'
    if ($deny -eq 1) { return Pass 'all removable storage denied by policy' }
    $start = Get-PolicyValue 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' 'Start'
    if ($start -eq 4) { return Pass 'USBSTOR driver disabled' }
    Warn ("unrestricted (USBSTOR Start={0})" -f $start)
} 'Set a removable-storage policy, or at minimum require BitLocker To Go for write access'

Test-Control 'Controlled folder access' {
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    if (-not $p) { return Unknown 'Defender preferences unavailable' }
    switch ([int]$p.EnableControlledFolderAccess) {
        1 { Pass 'enabled' }
        2 { Warn 'audit only' }
        default { Warn 'off - ransomware can rewrite user documents' }
    }
} 'Set-MpPreference -EnableControlledFolderAccess Enabled after auditing for false positives'

Test-Control 'BitLocker key escrow' {
    # The disk being encrypted is Test-SecurityBaseline's control. This is the
    # different question: if the user leaves or the board dies, who has the key.
    $ad  = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'OSActiveDirectoryBackup'
    $req = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' 'OSRequireActiveDirectoryBackup'
    if ($ad -eq 1) {
        return Verdict ($req -eq 1) ("escrow on, mandatory={0}" -f ($req -eq 1))
    }
    if (-not $isAdmin) { return Unknown 'needs admin to read protectors' }
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if (-not $vol -or $vol.ProtectionStatus -ne 'On') { return Info 'volume not protected - escrow moot' }
    $hasRecovery = @($vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }).Count
    Verdict ($hasRecovery -gt 0) ("recovery passwords on volume: {0}, no directory escrow policy" -f $hasRecovery)
} 'Enable and require recovery-key backup to Entra ID or AD before encrypting any staff device'

Test-Control 'Cloud sync redirection' {
    # Known-folder move is the difference between "the laptop was stolen" and
    # "the laptop was stolen and the work is gone."
    $kfm = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive' 'KFMSilentOptIn'
    if ($kfm) { return Pass ("known-folder move to tenant {0}" -f $kfm) }
    Info 'no OneDrive known-folder policy - confirm where user data actually lives'
}

# -------------------------------------------------------------------------
Set-FieldKitSection 'Identity and access'

Test-Control 'Password policy' {
    # net accounts is the local SAM policy. On a joined machine the directory
    # overrides it, which is why the join state is reported above this.
    $out = net accounts 2>$null
    if (-not $out) { return Unknown 'net accounts produced no output' }
    $minLen  = ($out | Select-String 'Minimum password length')      -replace '.*:\s*', ''
    $history = ($out | Select-String 'Length of password history')   -replace '.*:\s*', ''
    $lockout = ($out | Select-String 'Lockout threshold')            -replace '.*:\s*', ''
    $detail = "min length={0}, history={1}, lockout={2}" -f $minLen, $history, $lockout
    $weak = ($minLen -match '^\d+$' -and [int]$minLen -lt 12) -or $lockout -match 'Never'
    if ($weak) { return Warn $detail }
    Pass $detail
} 'Set a minimum length of 12+, a lockout threshold, and password history in the directory or local policy'

Test-Control 'Passwordless / Hello for Business' {
    $pol = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' 'Enabled'
    if ($pol -eq 1) { return Pass 'Hello for Business enforced by policy' }
    if ($pol -eq 0) { return Warn 'Hello for Business explicitly disabled' }
    # Absent policy is the default, which is "user's choice" - worth naming
    # because it is the cheapest MFA a small office can actually deploy.
    Info 'no Hello for Business policy - sign-in strength is per user'
} 'Deploy Hello for Business so the second factor is the device, not a code the user retypes'

Test-Control 'Named local administrators' {
    # Baseline counts them. This asks the follow-up: is each one a person.
    try { $m = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop) }
    catch { return Unknown 'needs admin to enumerate' }
    $local = @($m | Where-Object { $_.PrincipalSource -eq 'Local' -and $_.ObjectClass -eq 'User' })
    $detail = "{0} members, {1} local user accounts" -f $m.Count, $local.Count
    if ($local.Count -gt 1) { return Warn $detail }
    Pass $detail
} 'Give each admin a named account and remove shared or leftover ones; deploy LAPS for the built-in account'

Test-Control 'LAPS for the local admin password' {
    $mod = Get-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' 'BackupDirectory'
    if ($mod) { return Pass ("Windows LAPS backing up to directory type {0}" -f $mod) }
    $legacy = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' 'AdmPwdEnabled'
    if ($legacy -eq 1) { return Warn 'legacy AdmPwd LAPS - migrate to Windows LAPS' }
    Warn 'no LAPS - local admin password is likely shared across the fleet'
} 'Enable Windows LAPS so every machine has a different, rotated local admin password'

Test-Control 'Screen lock' {
    $secs = Get-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
    if ($secs -and $secs -gt 0) {
        return Verdict ($secs -le 900) ("machine policy: {0}s" -f $secs)
    }
    $active = Get-PolicyValue 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'
    $secure = Get-PolicyValue 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'
    # Blank ScreenSaverIsSecure means the saver runs without demanding a
    # password, which is a screen saver and not a lock.
    if ($active -eq '1' -and $secure -eq '1') { return Warn 'user setting only, not enforced by policy' }
    Warn 'no enforced inactivity lock'
} 'Set an enforced machine inactivity limit of 900 seconds or less'

Test-Control 'Dormant enabled accounts' {
    # The offboarding control. An account that still works months after its
    # owner left is the finding; the leaving is not visible from here.
    try { $users = @(Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled }) }
    catch { return Unknown 'cannot enumerate local users' }
    $cut = (Get-Date).AddDays(-$DormantDays)
    $stale = @($users | Where-Object { $_.LastLogon -and $_.LastLogon -lt $cut })
    $never = @($users | Where-Object { -not $_.LastLogon })
    if ($stale.Count -eq 0 -and $never.Count -eq 0) {
        return Pass ("{0} enabled accounts, none dormant at the {1}-day threshold" -f $users.Count, $DormantDays)
    }
    $names = @()
    $names += ($stale | ForEach-Object { '{0} ({1:yyyy-MM-dd})' -f $_.Name, $_.LastLogon })
    $names += ($never | ForEach-Object { '{0} (never)' -f $_.Name })
    Warn ($names -join ', ')
} 'Disable each account whose owner has left, then delete it once its data is reassigned'

# -------------------------------------------------------------------------
if (-not $Chained) {
    $summary = Write-FieldKitSummary
    if (-not $NoReport) {
        if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot '..\reports' }
        $r = Export-FieldKitReport -Path $ReportPath `
            -Title 'Endpoint management review' -Target $env:COMPUTERNAME
        Write-Host ""
        Write-Host "  report (client) : $($r.Html)"     -ForegroundColor Cyan
        Write-Host "  report (keep)   : $($r.Markdown)" -ForegroundColor Cyan
    }
    if ($summary.Fail -gt 0) { exit 1 } else { exit 0 }
}
