<# Opt-in assessment wrapper; shares all gates with Invoke-FieldKit -M365. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Engagement,
    [Parameter(Mandatory)][string]$OutputRoot, [switch]$NameAccounts, [switch]$Diagnose)
& (Join-Path $PSScriptRoot '..\Invoke-FieldKit.ps1') -M365 -Engagement $Engagement -OutputRoot $OutputRoot -NameAccounts:$NameAccounts -Diagnose:$Diagnose
