<#
.SYNOPSIS
    Diagnose network connectivity on a Windows host, layer by layer.

.DESCRIPTION
    Works outward in the order faults actually occur: adapter, address,
    gateway, DNS, internet, TLS. Reporting in that order matters, because
    "the internet is down" is nearly always one specific hop, and naming the
    hop is the whole value of the call.

    OUTBOUND TRAFFIC. Unlike the other scripts in this kit, this one sends
    packets off the machine. It contacts, and nothing else:

      * the host's own default gateway            (ICMP)
      * 1.1.1.1                                   (ICMP)
      * the host's own configured DNS servers     (DNS query for a public name)
      * https://www.microsoft.com                 (HTTPS GET, proves TLS egress)
      * http://www.msftconnecttest.com/connecttest.txt  (HTTP GET, captive portal)

    Nothing is uploaded and no client data leaves the machine. Use
    -NoInternet to restrict the run to the local network only, which is the
    right choice on an air-gapped or otherwise sensitive site.

.EXAMPLE
    .\Test-NetworkHealth.ps1

.EXAMPLE
    .\Test-NetworkHealth.ps1 -NoInternet

.NOTES
    ASCII only, Windows PowerShell 5.1 compatible. See ..\README.md.
    Exit code 0 = no FAIL findings, 1 = at least one FAIL.
#>
[CmdletBinding()]
param(
    [switch]$NoInternet,
    [switch]$NoReport,
    # Set by Invoke-FieldKit.ps1, which owns the findings collection, the
    # report and the exit code when several checks run as one engagement.
    [switch]$Chained,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Common.psm1')
if (-not $Chained) { Clear-FieldKitFindings }

function Test-IcmpHost {
    <#  Ping with a real timeout. Test-NetConnection blocks far too long on a
        dead host to be usable during triage.  #>
    param([string]$Address, [int]$TimeoutMs = 1500, [int]$Count = 3)
    $ping    = New-Object System.Net.NetworkInformation.Ping
    $times   = @()
    $lost    = 0
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $r = $ping.Send($Address, $TimeoutMs)
            if ($r.Status -eq 'Success') { $times += $r.RoundtripTime } else { $lost++ }
        } catch { $lost++ }
    }
    [pscustomobject]@{
        Sent    = $Count
        Lost    = $lost
        AvgMs   = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 0) } else { $null }
        Success = ($lost -lt $Count)
    }
}

Write-Host ""
Write-Host "Network health - $env:COMPUTERNAME" -ForegroundColor Cyan
if ($NoInternet) { Write-Host "-NoInternet: local checks only, nothing leaves this machine" -ForegroundColor DarkYellow }

# Pick the interface that actually carries traffic, rather than guessing by
# name. The one with a default route is the one the user means.
$defaultRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Sort-Object RouteMetric | Select-Object -First 1
$primaryIf = $null
if ($defaultRoute) {
    $primaryIf = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
}

# -------------------------------------------------------------------------
Set-FieldKitSection 'Interface'

Test-Control 'Adapters up' {
    $up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
    if ($up.Count -eq 0) { return Fail 'no adapter is up' }
    Info (($up | ForEach-Object { "$($_.Name) ($($_.LinkSpeed))" }) -join ', ')
} 'Check the cable, the switch port, or the wireless association'

Test-Control 'Primary interface' {
    if (-not $primaryIf) { return Fail 'no default route - host cannot leave its subnet' }
    Info ("{0}, {1}" -f $primaryIf.Name, $primaryIf.LinkSpeed)
} 'No default gateway is configured; check DHCP or the static configuration'

Test-Control 'Link errors' {
    if (-not $primaryIf) { return Unknown 'no primary interface' }
    $s = Get-NetAdapterStatistics -Name $primaryIf.Name -ErrorAction SilentlyContinue
    if (-not $s) { return Unknown 'statistics unavailable' }
    $err = $s.ReceivedPacketErrors + $s.OutboundPacketErrors
    # A handful of errors over a long uptime is normal. Sustained errors mean
    # cable, duplex mismatch, or a failing port.
    if ($err -gt 1000) { Warn "$err packet errors - suspect cable or port" }
    else { Pass "$err packet errors" }
} 'Reseat or replace the cable; check switch port duplex'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Addressing'

Test-Control 'IPv4 address' {
    if (-not $primaryIf) { return Unknown 'no primary interface' }
    $ip = Get-NetIPAddress -InterfaceIndex $primaryIf.InterfaceIndex -AddressFamily IPv4 `
          -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ip) { return Fail 'no IPv4 address' }
    # 169.254.x.x means DHCP failed and Windows self-assigned. This single
    # check explains a large fraction of "no internet" calls.
    if ($ip.IPAddress -like '169.254.*') {
        return Fail ("{0} - APIPA, DHCP did not answer" -f $ip.IPAddress)
    }
    Info ("{0}/{1} ({2})" -f $ip.IPAddress, $ip.PrefixLength, $ip.PrefixOrigin)
} 'DHCP is not responding: check the DHCP server, scope exhaustion, or VLAN'

Test-Control 'Default gateway' {
    if (-not $defaultRoute) { return Fail 'none configured' }
    Info $defaultRoute.NextHop
} 'Set a gateway via DHCP or static configuration'

Test-Control 'Gateway reachable' {
    if (-not $defaultRoute) { return Unknown 'no gateway configured' }
    $r = Test-IcmpHost -Address $defaultRoute.NextHop
    if (-not $r.Success) { return Fail ("no reply from {0}" -f $defaultRoute.NextHop) }
    if ($r.Lost -gt 0) { return Warn ("{0}/{1} lost, avg {2} ms" -f $r.Lost, $r.Sent, $r.AvgMs) }
    Pass ("avg {0} ms" -f $r.AvgMs)
} 'The fault is between this host and the router - cable, switch, VLAN, or firewall'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Name resolution'

Test-Control 'DNS servers configured' {
    if (-not $primaryIf) { return Unknown 'no primary interface' }
    $dns = Get-DnsClientServerAddress -InterfaceIndex $primaryIf.InterfaceIndex `
           -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $addrs = @($dns.ServerAddresses)
    if ($addrs.Count -eq 0) { return Fail 'none configured' }
    Info ($addrs -join ', ')
} 'Configure DNS via DHCP or statically'

Test-Control 'DNS resolution works' {
    try {
        $a = Resolve-DnsName -Name 'www.microsoft.com' -Type A -DnsOnly -QuickTimeout -ErrorAction Stop
        Verdict ($a.Count -gt 0) ("resolved to {0}" -f (@($a | Where-Object { $_.IPAddress }) | Select-Object -First 1).IPAddress)
    } catch {
        Fail 'query failed - DNS is the fault'
    }
} 'Gateway is reachable but DNS is not resolving: check the DNS server or try 1.1.1.1'

Test-Control 'Hosts file clean' {
    # A tampered hosts file is both a malware artefact and a leftover from
    # someone's debugging three years ago. Both are worth seeing.
    $p = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (-not (Test-Path $p)) { return Unknown 'hosts file not found' }
    $entries = @(Get-Content $p -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '^\s*[^#\s]' })
    if ($entries.Count -eq 0) { return Pass 'no active entries' }
    Warn ("{0} active entry/entries" -f $entries.Count)
} 'Review the hosts file for stale or malicious overrides'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Internet'

if ($NoInternet) {
    Test-Control 'Internet reachability' { Info 'skipped (-NoInternet)' }
} else {
    Test-Control 'ICMP to 1.1.1.1' {
        $r = Test-IcmpHost -Address '1.1.1.1'
        if (-not $r.Success) { return Fail 'no reply - no route to the internet, or ICMP is filtered' }
        if ($r.Lost -gt 0) { return Warn ("{0}/{1} lost, avg {2} ms" -f $r.Lost, $r.Sent, $r.AvgMs) }
        # Latency well above typical broadband suggests congestion or a
        # saturated uplink rather than an outage.
        if ($r.AvgMs -gt 150) { return Warn ("avg {0} ms - high" -f $r.AvgMs) }
        Pass ("avg {0} ms" -f $r.AvgMs)
    } 'Gateway responds but the internet does not: fault is upstream at the router or ISP'

    Test-Control 'HTTPS egress' {
        # Some networks block ICMP entirely, so a ping failure alone does not
        # prove the internet is down. This is the check that settles it.
        #
        # Deliberately NOT msftconnecttest.com: that is the NCSI endpoint and
        # is served over plain HTTP, so its certificate does not validate.
        # Pointing a TLS check at it produces a confident false failure.
        try {
            $old = [Net.ServicePointManager]::SecurityProtocol
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $resp = Invoke-WebRequest -Uri 'https://www.microsoft.com' `
                    -UseBasicParsing -TimeoutSec 10
            [Net.ServicePointManager]::SecurityProtocol = $old
            Verdict ($resp.StatusCode -eq 200) ("HTTP {0}" -f $resp.StatusCode)
        } catch {
            $m = ($_.Exception.Message -replace '\s+', ' ').Trim()
            # A trust failure here, against a host whose certificate is valid
            # everywhere else, is the signature of TLS interception.
            if ($m -match 'trust relationship|SSL/TLS') {
                Fail "TLS trust failure - suspect interception or a stale root store"
            } else {
                Fail $m
            }
        }
    } 'Check proxy settings, TLS inspection, or an upstream content filter'

    Test-Control 'No captive portal' {
        # NCSI returns this exact body. Anything else means something is
        # intercepting plain HTTP - hotel wifi, a guest VLAN, or a filter.
        try {
            $resp = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' `
                    -UseBasicParsing -TimeoutSec 10
            $body = ($resp.Content | Out-String).Trim()
            Verdict ($body -eq 'Microsoft Connect Test') ("body: '{0}'" -f $body)
        } catch {
            Unknown ("probe failed: " + ($_.Exception.Message -replace '\s+', ' ').Trim())
        }
    } 'Traffic is being intercepted - sign in to the portal or move off the guest network'
}

Test-Control 'System proxy' {
    $p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
         -ErrorAction SilentlyContinue
    if ($p.ProxyEnable -eq 1) { Info ("enabled: {0}" -f $p.ProxyServer) }
    else { Pass 'no proxy configured' }
}

# -------------------------------------------------------------------------
if ($Chained) { return }

$summary = Write-FieldKitSummary

if (-not $NoReport) {
    if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot '..\reports' }
    $r = Export-FieldKitReport -Path $ReportPath -Title 'Network health' -Target $env:COMPUTERNAME
    Write-Host ""
    Write-Host "report: $($r.Html)" -ForegroundColor Cyan
}

if ($summary.Fail -gt 0) { exit 1 } else { exit 0 }
