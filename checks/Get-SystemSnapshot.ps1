<#
.SYNOPSIS
    Inventory and health snapshot of a Windows host.

.DESCRIPTION
    The "what am I even looking at" pass. Run this first on an unfamiliar
    machine: it answers the questions you would otherwise ask the client and
    get a wrong answer to, because most people do not know their own build
    number or how long the box has been up.

    Read-only. Uses CIM rather than WMI so it does not depend on the legacy
    WMI service being healthy - which on a sick machine it often is not.

.EXAMPLE
    .\Get-SystemSnapshot.ps1

.NOTES
    ASCII only, Windows PowerShell 5.1 compatible. See ..\README.md.
#>
[CmdletBinding()]
param(
    [switch]$NoReport,
    # Set by Invoke-FieldKit.ps1, which owns the findings collection and the
    # report when several checks run as one engagement.
    [switch]$Chained,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Common.psm1')
if (-not $Chained) { Clear-FieldKitFindings }

Write-Host ""
Write-Host "System snapshot - $env:COMPUTERNAME" -ForegroundColor Cyan

# -------------------------------------------------------------------------
Set-FieldKitSection 'Machine'

Test-Control 'Model' {
    $cs = Get-CimInstance Win32_ComputerSystem
    Info ("{0} {1}" -f $cs.Manufacturer, $cs.Model)
}

Test-Control 'Serial / service tag' {
    $b = Get-CimInstance Win32_BIOS
    # The service tag is what the vendor's warranty lookup wants. Getting it
    # without walking the client through BIOS screens saves a support call.
    Info $b.SerialNumber
}

Test-Control 'CPU' {
    $c = @(Get-CimInstance Win32_Processor)[0]
    Info ("{0} ({1}c/{2}t)" -f $c.Name.Trim(), $c.NumberOfCores, $c.NumberOfLogicalProcessors)
}

Test-Control 'Installed RAM' {
    $cs = Get-CimInstance Win32_ComputerSystem
    $gb = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    # Under 8 GB on a modern Windows desktop is a performance complaint
    # waiting to happen, and it is cheap to fix.
    if ($gb -lt 8) { Warn "$gb GB - low for current Windows" } else { Info "$gb GB" }
} 'Quote a RAM upgrade before investigating software causes of slowness'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Operating system'

Test-Control 'Edition and build' {
    $os = Get-CimInstance Win32_OperatingSystem
    $ub = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR
    $build = $os.BuildNumber
    if ($ub) { $build = "$build.$ub" }
    Info ("{0} ({1})" -f $os.Caption.Trim(), $build)
}

Test-Control 'Install date' {
    $os = Get-CimInstance Win32_OperatingSystem
    $age = (New-TimeSpan -Start $os.InstallDate -End (Get-Date)).Days
    Info ("{0} ({1} days ago)" -f $os.InstallDate.ToString('yyyy-MM-dd'), $age)
}

Test-Control 'Uptime' {
    $os = Get-CimInstance Win32_OperatingSystem
    $up = New-TimeSpan -Start $os.LastBootUpTime -End (Get-Date)
    $txt = "{0}d {1}h" -f $up.Days, $up.Hours
    # Very long uptime on Windows usually means updates are not completing,
    # not that the machine is impressively stable.
    if ($up.Days -gt 30) { Warn "$txt - updates likely not finishing" } else { Info $txt }
} 'Reboot, then confirm Windows Update completes cleanly'

Test-Control 'Pending reboot' {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    $pending = @($keys | Where-Object { Test-Path $_ })
    if ($pending.Count -gt 0) { Warn 'reboot required to finish updates' } else { Pass 'none' }
} 'Restart the machine'

Test-Control 'Domain / workgroup' {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) { Info ("domain: {0}" -f $cs.Domain) }
    else { Info ("workgroup: {0}" -f $cs.Workgroup) }
}

Test-Control 'Time synchronisation' {
    # Clock skew breaks Kerberos, TLS and MFA, and presents as a dozen
    # unrelated-looking symptoms. Cheap to check, expensive to overlook.
    $svc = Get-Service W32Time -ErrorAction SilentlyContinue
    if (-not $svc) { return Unknown 'W32Time service not found' }
    if ($svc.Status -ne 'Running') { return Warn 'W32Time not running' }
    Pass 'W32Time running'
} 'Start-Service W32Time; w32tm /resync'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Storage'

foreach ($vol in (Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Sort-Object DeviceID)) {
    $id = $vol.DeviceID
    Test-Control "Free space $id" {
        $total = $vol.Size
        $free  = $vol.FreeSpace
        if (-not $total) { return Unknown 'size unavailable' }
        $pct = [math]::Round(100 * $free / $total, 1)
        $txt = "{0} GB free of {1} GB ({2}%)" -f `
            [math]::Round($free/1GB,1), [math]::Round($total/1GB,1), $pct
        # Windows starts behaving badly well before zero, and 10% is the
        # point where updates and page file growth begin to fail.
        if ($pct -lt 10) { Fail $txt }
        elseif ($pct -lt 20) { Warn $txt }
        else { Pass $txt }
    } 'Free space or expand the volume before troubleshooting anything else'
}

Test-Control 'Physical disk health' {
    $d = Get-PhysicalDisk -ErrorAction SilentlyContinue
    if (-not $d) { return Unknown 'Get-PhysicalDisk unavailable' }
    $bad = @($d | Where-Object { $_.HealthStatus -ne 'Healthy' })
    if ($bad.Count -gt 0) {
        Fail ("unhealthy: " + (($bad | ForEach-Object { "$($_.FriendlyName)=$($_.HealthStatus)" }) -join ', '))
    } else {
        Pass ("{0} disk(s) healthy" -f @($d).Count)
    }
} 'Back up now and replace the failing disk before any other work'

# -------------------------------------------------------------------------
if (-not $Chained) { $null = Write-FieldKitSummary }

if (-not $NoReport) {
    if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot '..\reports' }
    $r = Export-FieldKitReport -Path $ReportPath -Title 'System snapshot' -Target $env:COMPUTERNAME
    Write-Host ""
    Write-Host "report: $($r.Html)" -ForegroundColor Cyan
}
