<#
.SYNOPSIS
    Run the full fieldkit diagnostic sweep and produce one client report.

.DESCRIPTION
    Runs every check in one session so the engagement produces a single
    report rather than three. That matters more than it sounds: a client who
    receives one document reads it, and a client who receives three files
    reads none of them.

    Everything is read-only. Nothing on the target host is modified; the only
    thing written is the report, and -ReportPath controls where that goes.

    Exit codes, for use from a scheduler or RMM:
        0  no FAIL findings
        1  at least one FAIL
        2  the sweep itself could not complete

.PARAMETER NoInternet
    Skip the checks that send traffic off the machine. Use on air-gapped or
    sensitive sites.

.PARAMETER ReportPath
    Where to write the report. Defaults to .\reports next to this script.

.PARAMETER ClientName
    Appears in the report title. Use the client or site name so the file is
    identifiable six months later.

.EXAMPLE
    .\Invoke-FieldKit.ps1

.EXAMPLE
    .\Invoke-FieldKit.ps1 -ClientName 'Northgate Dental' -ReportPath D:\engagements

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Invoke-FieldKit.ps1

.NOTES
    ASCII only, Windows PowerShell 5.1 compatible.
    Run elevated for a complete picture; unelevated works and reports UNKN
    for what it cannot read.
#>
[CmdletBinding()]
param(
    [switch]$NoInternet,
    [string]$ReportPath,
    [string]$ClientName
)

$ErrorActionPreference = 'Stop'

$module = Join-Path $PSScriptRoot 'modules\FieldKit.Common.psm1'
if (-not (Test-Path $module)) {
    Write-Error "FieldKit.Common.psm1 not found next to this script."
    exit 2
}

# -Force here and nowhere else: this is the one place that deliberately
# resets collected findings, because it owns the sweep.
Import-Module $module -Force
Clear-FieldKitFindings

if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot 'reports' }

$title = 'Diagnostic report'
if ($ClientName) { $title = "Diagnostic report - $ClientName" }

$banner = @"

  fieldkit sweep
  host      : $env:COMPUTERNAME
  operator  : $env:USERNAME
  elevated  : $(if (Get-FieldKitElevation) { 'yes' } else { 'no - some controls will report UNKN' })
  started   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
Write-Host $banner -ForegroundColor Cyan

$checks = @(
    @{ Name = 'System snapshot';  Script = 'checks\Get-SystemSnapshot.ps1';    Args = @{} }
    @{ Name = 'Network health';   Script = 'checks\Test-NetworkHealth.ps1';    Args = @{ NoInternet = $NoInternet } }
    @{ Name = 'Security baseline';Script = 'checks\Test-SecurityBaseline.ps1'; Args = @{} }
)

$ran = 0
foreach ($c in $checks) {
    $path = Join-Path $PSScriptRoot $c.Script
    if (-not (Test-Path $path)) {
        Write-Host ("  skipping {0} - {1} not found" -f $c.Name, $c.Script) -ForegroundColor DarkYellow
        continue
    }
    try {
        # -Chained: the check contributes findings but does not print its own
        # summary, write its own report, or exit the process.
        # Splatting binds to a variable, not an expression, hence the copy.
        $extra = $c.Args
        & $path -Chained -NoReport @extra | Out-Null
        $ran++
    } catch {
        # One broken check must not cost the operator the whole visit.
        Write-Host ("  {0} failed to complete: {1}" -f $c.Name,
            ($_.Exception.Message -replace '\s+', ' ').Trim()) -ForegroundColor Red
    }
}

if ($ran -eq 0) {
    Write-Error "No checks ran."
    exit 2
}

$summary = Write-FieldKitSummary

$r = Export-FieldKitReport -Path $ReportPath -Title $title -Target $env:COMPUTERNAME
Write-Host ""
Write-Host "  report (client) : $($r.Html)"     -ForegroundColor Cyan
Write-Host "  report (keep)   : $($r.Markdown)" -ForegroundColor Cyan
Write-Host ""

if ($summary.Fail -gt 0) { exit 1 } else { exit 0 }
