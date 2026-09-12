<#
.SYNOPSIS
    Diagnose inbound mail delivery for a domain from public DNS alone.

.DESCRIPTION
    Answers one question before you have access to anything: is this domain's
    mail broken in DNS, or is it broken inside the mail tenant?

    That split is the whole point. Outbound mail never consults the sending
    domain's own MX records, so a client who can send but cannot receive has
    a fault on the inbound path only - which is either MX, or it is
    tenant-side configuration this script cannot see. Ruling DNS in or out
    costs one minute and no credentials, and it decides which access you need
    to ask for.

    OUTBOUND TRAFFIC. This sends DNS queries about $Domain to the resolver
    named by -Server (8.8.8.8 by default). It reads public records only,
    changes nothing, and needs no relationship with the domain. Nothing about
    the operator's own machine is collected or transmitted.

    UNLIKE THE OTHER CHECKS IN THIS KIT the target is a domain rather than
    this host, so it is deliberately not part of the Invoke-FieldKit sweep.
    Run it on its own.

.PARAMETER Domain
    The domain to test. A bare domain, a URL or an address all work.

.PARAMETER Server
    Resolver to query. Defaults to 8.8.8.8 rather than the local resolver,
    because a stale cache or a split-horizon DNS server on the operator's own
    network will quietly return the wrong answer, and nothing in the output
    would reveal that it had.

.EXAMPLE
    .\Test-MailDelivery.ps1 -Domain contoso.com

.EXAMPLE
    .\Test-MailDelivery.ps1 -Domain contoso.com -Server 1.1.1.1

.NOTES
    ASCII only, Windows PowerShell 5.1 compatible. See ..\README.md.
    Exit code 0 = no FAIL findings, 1 = at least one FAIL.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Domain,

    [string]$Server = '8.8.8.8',

    [switch]$NoReport,
    # Set by a caller that owns the findings collection and the report.
    [switch]$Chained,
    [string]$ReportPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\modules\FieldKit.Common.psm1')
if (-not $Chained) { Clear-FieldKitFindings }

# Accept what people actually paste: a URL, an address, a trailing dot.
$Domain = $Domain.Trim().ToLower()
$Domain = $Domain -replace '^\s*https?://', ''
$Domain = $Domain -replace '^[^@]*@', ''
$Domain = $Domain -replace '/.*$', ''
$Domain = $Domain.TrimEnd('.')

function Get-Dns {
    <#  Never throws. A missing record and a failed query are different
        findings, so the caller tells them apart by $script:LastDnsError
        rather than by an empty result.  #>
    param([string]$Name, [string]$Type)
    $script:LastDnsError = $null
    try {
        return @(Resolve-DnsName -Name $Name -Type $Type -Server $Server -DnsOnly -ErrorAction Stop)
    } catch {
        $script:LastDnsError = ($_.Exception.Message -replace '\s+', ' ').Trim()
        return @()
    }
}

function Test-GoogleMxTarget {
    param([string]$Target)
    $t = $Target.TrimEnd('.').ToLower()
    # Current Workspace provisions the single smtp.google.com record; older
    # tenants carry the five-record ASPMX set. Both are correct, and
    # "modernising" a working legacy set is a self-inflicted outage.
    return ($t -match '^smtp\.google\.com$') -or ($t -match 'aspmx.*\.google(mail)?\.com$')
}

Write-Host ""
Write-Host "Mail delivery - $Domain" -ForegroundColor Cyan
Write-Host "resolver $Server - public records only, nothing is modified" -ForegroundColor DarkGray

# -------------------------------------------------------------------------
Set-FieldKitSection 'Delegation'

$ns = @(Get-Dns -Name $Domain -Type NS | Where-Object { $_.NameHost })

Test-Control 'Domain resolves' {
    if ($ns.Count -gt 0) { return Pass 'authoritative nameservers found' }
    if ($script:LastDnsError) { return Fail ("query failed: " + $script:LastDnsError) }
    Fail 'no NS records - the domain may be unregistered or expired'
} 'Confirm the domain is registered and not expired before looking at anything else'

Test-Control 'DNS hosted at' {
    if ($ns.Count -eq 0) { return Unknown 'no nameservers to report' }
    # The most useful line here for scoping the job: it names whose console
    # you need a login to, which is the part that actually costs a day of
    # calendar time on a job like this.
    Info (($ns | ForEach-Object { $_.NameHost.TrimEnd('.') } | Sort-Object -Unique) -join ', ')
}

# -------------------------------------------------------------------------
Set-FieldKitSection 'Inbound mail'

$mx       = @(Get-Dns -Name $Domain -Type MX | Where-Object { $_.NameExchange })
$mxSorted = @($mx | Sort-Object Preference)

Test-Control 'MX records present' {
    if ($mx.Count -eq 0) { return Fail 'none published - inbound mail has nowhere to go' }
    Pass ("{0} record(s)" -f $mx.Count)
} 'Publish Google MX at the DNS host: smtp.google.com, priority 1'

Test-Control 'MX targets' {
    if ($mx.Count -eq 0) { return Unknown 'no MX records' }
    Info (($mxSorted | ForEach-Object { "{0} ({1})" -f $_.NameExchange.TrimEnd('.'), $_.Preference }) -join ', ')
}

Test-Control 'MX points to Google Workspace' {
    if ($mx.Count -eq 0) { return Unknown 'no MX records' }
    $google  = @($mxSorted | Where-Object { Test-GoogleMxTarget $_.NameExchange })
    $foreign = @($mxSorted | Where-Object { -not (Test-GoogleMxTarget $_.NameExchange) })

    if ($google.Count -eq 0) {
        return Fail ("mail is delivered to " + $foreign[0].NameExchange.TrimEnd('.') + ", not to Google")
    }
    if ($foreign.Count -eq 0) { return Pass 'all records are Google' }

    # Lowest preference number wins. A leftover record from a previous host
    # sitting below Google swallows every message, and it presents exactly
    # like having no MX at all - which is why it survives so many attempts to
    # fix it by checking that the Google records are present. They are.
    $lowest = $mxSorted[0]
    if (-not (Test-GoogleMxTarget $lowest.NameExchange)) {
        return Fail ("{0} at priority {1} outranks Google and takes all mail" -f
            $lowest.NameExchange.TrimEnd('.'), $lowest.Preference)
    }
    Warn ("{0} non-Google record(s) present below Google" -f $foreign.Count)
} 'Delete the non-Google MX records; Google must hold the lowest priority number'

Test-Control 'MX hostnames resolve' {
    if ($mx.Count -eq 0) { return Unknown 'no MX records' }
    $dead = @()
    foreach ($r in $mxSorted) {
        $addr = @(Get-Dns -Name $r.NameExchange -Type A | Where-Object { $_.IPAddress })
        if ($addr.Count -eq 0) { $dead += $r.NameExchange.TrimEnd('.') }
    }
    if ($dead.Count -gt 0) { return Fail ("no address for " + ($dead -join ', ')) }
    Pass 'all targets resolve'
} 'An MX pointing at a hostname with no address discards mail silently'

# -------------------------------------------------------------------------
# Not the reported fault - outbound works - but this is where the follow-on
# work lives, and it costs three more queries to know whether it exists.
Set-FieldKitSection 'Authentication (informational)'

$txt = @(Get-Dns -Name $Domain -Type TXT | Where-Object { $_.Strings })
$spf = @($txt | Where-Object { (($_.Strings -join '') -match '^v=spf1') })

Test-Control 'SPF' {
    if ($spf.Count -eq 0) { return Warn 'no SPF record published' }
    # Two v=spf1 records is a permerror under RFC 7208: receivers are required
    # to fail the check rather than pick one, so this breaks authentication
    # more thoroughly than publishing nothing at all.
    if ($spf.Count -gt 1) { return Fail ("{0} SPF records - receivers treat this as permerror" -f $spf.Count) }
    $v = ($spf[0].Strings -join '')
    if ($v -match '_spf\.google\.com') { return Pass $v }
    Warn ("does not authorise Google: " + $v)
} 'Publish exactly one SPF record, including _spf.google.com'

Test-Control 'DMARC' {
    $d   = @(Get-Dns -Name ("_dmarc." + $Domain) -Type TXT | Where-Object { $_.Strings })
    $rec = @($d | Where-Object { (($_.Strings -join '') -match '^v=DMARC1') })
    if ($rec.Count -eq 0) { return Warn 'no DMARC record published' }
    $v = ($rec[0].Strings -join '')
    $p = 'none'
    if ($v -match 'p\s*=\s*([a-z]+)') { $p = $Matches[1] }
    Info ("policy p=" + $p)
} 'Publish a DMARC record, starting at p=none while you read the reports'

Test-Control 'DKIM (default selector)' {
    $k = @(Get-Dns -Name ("google._domainkey." + $Domain) -Type TXT | Where-Object { $_.Strings })
    if ($k.Count -gt 0) { return Pass 'google._domainkey present' }
    # Absence here is not absence of DKIM. The selector is chosen by whoever
    # set it up and cannot be enumerated from outside, so a working key on a
    # custom selector is indistinguishable from no key at all. Say that,
    # rather than reporting a failure that may not be one.
    Unknown 'not on the default selector - a custom selector is invisible from outside'
} 'Read the active selector in Admin console, Apps > Google Workspace > Gmail > Authenticate email'

# -------------------------------------------------------------------------
Set-FieldKitSection 'Conclusion'

Test-Control 'Fault localised to' {
    $dnsFail = @(Get-FieldKitFindings | Where-Object {
        $_.Section -in @('Delegation', 'Inbound mail') -and $_.Status -eq 'FAIL'
    })
    if ($dnsFail.Count -gt 0) {
        return Info 'DNS - correct the records above, then retest after the TTL expires'
    }
    # Everything visible from outside is correct, so every remaining cause
    # lives behind an admin login: the domain added as an alias rather than a
    # hosted domain, Gmail switched off for the user's OU, a routing rule, or
    # mail sitting in quarantine.
    Info 'the tenant - DNS is correct, so the cause is inside Workspace Admin'
}

# -------------------------------------------------------------------------
if ($Chained) { return }

$summary = Write-FieldKitSummary

if (-not $NoReport) {
    if (-not $ReportPath) { $ReportPath = Join-Path $PSScriptRoot '..\reports' }
    $r = Export-FieldKitReport -Path $ReportPath -Title "Mail delivery - $Domain" -Target $Domain
    Write-Host ""
    Write-Host "report: $($r.Html)" -ForegroundColor Cyan
}

if ($summary.Fail -gt 0) { exit 1 } else { exit 0 }
