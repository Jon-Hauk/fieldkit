<#
.SYNOPSIS
    Shared harness for the fieldkit diagnostic scripts.

.DESCRIPTION
    Every check script collects findings through this module so that one
    engagement produces one consistent report, whatever mix of scripts was run.

    Design rules, all of which exist because this runs on someone else's
    machine:

      * READ ONLY. Nothing here writes to the target system outside the
        report directory. A diagnostic that changes state cannot be run
        during triage, because you can no longer say what was already broken
        and what you broke.

      * Windows PowerShell 5.1. No ternary, no ??, no &&, no -AsHashtable.
        Client machines are 5.1 far more often than 7.x, and a parser error
        on arrival is not the first impression you want.

      * Unelevated is a first-class mode, not a failure. A control that
        cannot be read reports UNKN, never FAIL. A tool that cries wolf
        gets ignored, and then the real finding gets ignored with it.
#>

$script:Findings = [System.Collections.ArrayList]::new()
$script:Section  = 'General'

function Get-FieldKitElevation {
    <#  True when the current process can read admin-only state.  #>
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-FieldKitSection {
    param([Parameter(Mandatory)][string]$Name)
    $script:Section = $Name
    Write-Host ""
    Write-Host $Name -ForegroundColor White
}

# --- verdict constructors -------------------------------------------------
# Checks return one of these rather than a bare boolean, so a check can say
# "I could not tell" instead of being forced into pass/fail.

function Pass    { param([string]$Detail) [pscustomobject]@{ Status = 'PASS'; Detail = $Detail } }
function Fail    { param([string]$Detail) [pscustomobject]@{ Status = 'FAIL'; Detail = $Detail } }
function Warn    { param([string]$Detail) [pscustomobject]@{ Status = 'WARN'; Detail = $Detail } }
function Unknown { param([string]$Detail) [pscustomobject]@{ Status = 'UNKN'; Detail = $Detail } }
function Info    { param([string]$Detail) [pscustomobject]@{ Status = 'INFO'; Detail = $Detail } }

function Verdict {
    <#  Convenience for the common boolean case: Verdict $ok "detail".  #>
    param([bool]$Condition, [string]$Detail)
    if ($Condition) { Pass $Detail } else { Fail $Detail }
}

$script:StatusColour = @{
    PASS = 'Green'; FAIL = 'Red'; WARN = 'Yellow'; UNKN = 'DarkYellow'; INFO = 'Gray'
}

function Test-Control {
    <#
    .SYNOPSIS
        Run one check, print it, and record it for the report.

    .PARAMETER Check
        Scriptblock returning a verdict object (Pass/Fail/Warn/Unknown/Info).

    .PARAMETER Remediation
        Shown under a FAIL or WARN. Write it as the command or action the
        client should take, not as a restatement of the problem.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Check,
        [string]$Remediation = ''
    )

    try {
        $result = & $Check
    } catch {
        # Access-denied is missing visibility, not a failing control. Anything
        # else is a bug in the check itself and should be loud, because a
        # silently broken check reads exactly like a passing one.
        # Messages arrive with trailing newlines that wreck the aligned output.
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        if ($msg -match 'denied|privilege|elevation|elevated|unauthorized') {
            $result = Unknown 'needs admin to read'
        } else {
            $result = Unknown ("check errored: " + $msg)
        }
    }

    if ($null -eq $result -or -not $result.Status) {
        $result = Unknown 'check returned nothing'
    }

    $null = $script:Findings.Add([pscustomobject]@{
        Section     = $script:Section
        Name        = $Name
        Status      = $result.Status
        Detail      = $result.Detail
        Remediation = $Remediation
    })

    $colour = $script:StatusColour[$result.Status]
    if (-not $colour) { $colour = 'Gray' }
    Write-Host ("  [{0}] {1,-38} {2}" -f $result.Status, $Name, $result.Detail) -ForegroundColor $colour

    if ($Remediation -and $result.Status -in @('FAIL', 'WARN')) {
        Write-Host ("         -> {0}" -f $Remediation) -ForegroundColor DarkYellow
    }
    if ($result.Status -eq 'UNKN' -and $result.Detail -match 'needs admin') {
        Write-Host  "         -> re-run as Administrator to read this" -ForegroundColor DarkYellow
    }
}

function Get-FieldKitFindings {
    return $script:Findings
}

function Clear-FieldKitFindings {
    $script:Findings.Clear()
    $script:Section = 'General'
}

function Get-FieldKitSummary {
    $f = $script:Findings
    [pscustomobject]@{
        Total = $f.Count
        Pass  = @($f | Where-Object { $_.Status -eq 'PASS' }).Count
        Fail  = @($f | Where-Object { $_.Status -eq 'FAIL' }).Count
        Warn  = @($f | Where-Object { $_.Status -eq 'WARN' }).Count
        Unkn  = @($f | Where-Object { $_.Status -eq 'UNKN' }).Count
        Info  = @($f | Where-Object { $_.Status -eq 'INFO' }).Count
    }
}

function Write-FieldKitSummary {
    $s = Get-FieldKitSummary
    Write-Host ""
    Write-Host ("{0} checks: {1} pass, {2} fail, {3} warn, {4} unknown, {5} informational" -f `
        $s.Total, $s.Pass, $s.Fail, $s.Warn, $s.Unkn, $s.Info) -ForegroundColor Cyan
    if ($s.Unkn -gt 0) {
        Write-Host "Some controls could not be read. Re-run elevated for a complete picture." -ForegroundColor DarkYellow
    }
    return $s
}

function ConvertTo-FieldKitHtmlRow {
    param($Finding)
    $cls = $Finding.Status.ToLower()
    $rem = ''
    if ($Finding.Remediation -and $Finding.Status -in @('FAIL', 'WARN')) {
        $rem = '<div class="rem">' + [System.Web.HttpUtility]::HtmlEncode($Finding.Remediation) + '</div>'
    }
    '<tr><td><span class="pill {0}">{1}</span></td><td>{2}</td><td>{3}{4}</td></tr>' -f `
        $cls,
        $Finding.Status,
        [System.Web.HttpUtility]::HtmlEncode($Finding.Name),
        [System.Web.HttpUtility]::HtmlEncode($Finding.Detail),
        $rem
}

function Export-FieldKitReport {
    <#
    .SYNOPSIS
        Write the collected findings to Markdown and self-contained HTML.

    .DESCRIPTION
        The HTML is what you hand a client: one file, no external assets, opens
        anywhere. The Markdown is what you keep, because it diffs cleanly
        between visits and shows what actually changed.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Title = 'Diagnostic report',
        [string]$Target = $env:COMPUTERNAME
    )

    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }

    $stamp    = Get-Date
    $slug     = '{0}-{1}' -f $Target, $stamp.ToString('yyyyMMdd-HHmmss')
    $summary  = Get-FieldKitSummary
    $findings = $script:Findings

    # --- Markdown ---------------------------------------------------------
    $md = New-Object System.Text.StringBuilder
    $null = $md.AppendLine("# $Title")
    $null = $md.AppendLine()
    $null = $md.AppendLine("- Host: ``$Target``")
    $null = $md.AppendLine("- Collected: $($stamp.ToString('yyyy-MM-dd HH:mm:ss K'))")
    $null = $md.AppendLine("- Collected by: $env:USERNAME")
    $null = $md.AppendLine("- Elevated: $(if (Get-FieldKitElevation) { 'yes' } else { 'no' })")
    $null = $md.AppendLine()
    $null = $md.AppendLine("**$($summary.Total) checks - $($summary.Fail) fail, $($summary.Warn) warn, $($summary.Unkn) unknown, $($summary.Pass) pass.**")
    $null = $md.AppendLine()

    foreach ($section in ($findings | Select-Object -ExpandProperty Section -Unique)) {
        $null = $md.AppendLine("## $section")
        $null = $md.AppendLine()
        $null = $md.AppendLine('| | Check | Detail |')
        $null = $md.AppendLine('|---|---|---|')
        foreach ($f in ($findings | Where-Object { $_.Section -eq $section })) {
            $detail = $f.Detail -replace '\|', '\|'
            if ($f.Remediation -and $f.Status -in @('FAIL', 'WARN')) {
                $detail += '<br>-> ' + ($f.Remediation -replace '\|', '\|')
            }
            $null = $md.AppendLine("| $($f.Status) | $($f.Name) | $detail |")
        }
        $null = $md.AppendLine()
    }

    $mdPath = Join-Path $Path "$slug.md"
    [System.IO.File]::WriteAllText($mdPath, $md.ToString(), (New-Object System.Text.UTF8Encoding($false)))

    # --- HTML -------------------------------------------------------------
    $rows = New-Object System.Text.StringBuilder
    foreach ($section in ($findings | Select-Object -ExpandProperty Section -Unique)) {
        $null = $rows.AppendLine('<tr class="sec"><td colspan="3">' + [System.Web.HttpUtility]::HtmlEncode($section) + '</td></tr>')
        foreach ($f in ($findings | Where-Object { $_.Section -eq $section })) {
            $null = $rows.AppendLine((ConvertTo-FieldKitHtmlRow $f))
        }
    }

    $html = @"
<!doctype html>
<html><head><meta charset="utf-8"><title>$([System.Web.HttpUtility]::HtmlEncode($Title)) - $([System.Web.HttpUtility]::HtmlEncode($Target))</title>
<style>
 :root { color-scheme: light dark; --bg:#fff; --fg:#1a1a1a; --mut:#666; --line:#e5e5e5; --head:#fafafa; }
 @media (prefers-color-scheme: dark) { :root { --bg:#161616; --fg:#e8e8e8; --mut:#999; --line:#2c2c2c; --head:#1e1e1e; } }
 body { background:var(--bg); color:var(--fg); font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif; margin:0; padding:2rem; }
 .wrap { max-width:60rem; margin:0 auto; }
 h1 { font-size:1.4rem; margin:0 0 .25rem; }
 .meta { color:var(--mut); font-size:.85rem; margin-bottom:1.5rem; }
 .meta code { background:var(--head); padding:.1rem .3rem; border-radius:3px; }
 .tally { display:flex; gap:.5rem; flex-wrap:wrap; margin-bottom:1.5rem; }
 .tally div { border:1px solid var(--line); border-radius:6px; padding:.5rem .8rem; }
 .tally b { display:block; font-size:1.3rem; }
 table { border-collapse:collapse; width:100%; }
 td { border-bottom:1px solid var(--line); padding:.5rem .6rem; vertical-align:top; }
 tr.sec td { background:var(--head); font-weight:600; padding-top:.9rem; }
 .pill { display:inline-block; min-width:3.2rem; text-align:center; font-size:.72rem;
         font-weight:700; letter-spacing:.04em; padding:.15rem .4rem; border-radius:3px; color:#fff; }
 .pass{background:#2e7d32}.fail{background:#c62828}.warn{background:#ef6c00}
 .unkn{background:#757575}.info{background:#455a64}
 .rem { color:var(--mut); font-size:.85rem; margin-top:.25rem; }
 footer { color:var(--mut); font-size:.8rem; margin-top:2rem; border-top:1px solid var(--line); padding-top:1rem; }
</style></head><body><div class="wrap">
<h1>$([System.Web.HttpUtility]::HtmlEncode($Title))</h1>
<div class="meta">
 Host <code>$([System.Web.HttpUtility]::HtmlEncode($Target))</code> &middot;
 collected $($stamp.ToString('yyyy-MM-dd HH:mm')) by $([System.Web.HttpUtility]::HtmlEncode($env:USERNAME)) &middot;
 elevated: $(if (Get-FieldKitElevation) { 'yes' } else { 'no' })
</div>
<div class="tally">
 <div><b>$($summary.Fail)</b> fail</div>
 <div><b>$($summary.Warn)</b> warn</div>
 <div><b>$($summary.Unkn)</b> unknown</div>
 <div><b>$($summary.Pass)</b> pass</div>
</div>
<table>$($rows.ToString())</table>
<footer>Read-only diagnostic. Nothing on this host was modified during collection.</footer>
</div></body></html>
"@

    $htmlPath = Join-Path $Path "$slug.html"
    [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))

    [pscustomobject]@{ Markdown = $mdPath; Html = $htmlPath; Summary = $summary }
}

Export-ModuleMember -Function `
    Get-FieldKitElevation, Set-FieldKitSection, Test-Control,
    Pass, Fail, Warn, Unknown, Info, Verdict,
    Get-FieldKitFindings, Clear-FieldKitFindings, Get-FieldKitSummary,
    Write-FieldKitSummary, Export-FieldKitReport
