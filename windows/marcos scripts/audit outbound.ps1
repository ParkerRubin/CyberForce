<#
.SYNOPSIS
    CyberForce 2026 - Comprehensive Windows Outbound Firewall Audit Script
#>

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "    WINDOWS OUTBOUND FIREWALL COMPREHENSIVE AUDIT REPORT" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Audit Outbound Profile States & Default Actions
Write-Host "`n[+] 1. Firewall Profile Default Outbound Actions & States:" -ForegroundColor Yellow
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction, LogAllowed, LogBlocked | Format-Table -AutoSize

# 2. Audit All Active Outbound Rules (Allow & Block)
Write-Host "`n[+] 2. Active Outbound Rules & Remote Bindings:" -ForegroundColor Yellow
$outboundRules = Get-NetFirewallRule -Direction Outbound -Enabled True

$auditData = foreach ($rule in $outboundRules) {
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $addrFilter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $appFilter  = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        DisplayName   = $rule.DisplayName
        Action        = $rule.Action
        Profile       = $rule.Profile
        Protocol      = $portFilter.Protocol
        RemotePort    = $portFilter.RemotePort
        RemoteAddress = $addrFilter.RemoteAddress
        ProgramPath   = $appFilter.Program
    }
}

$auditData | Format-Table -AutoSize

$totalRules = $auditData.Count
Write-Host "`n[+] Audit Summary: Found $totalRules active outbound rules." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
