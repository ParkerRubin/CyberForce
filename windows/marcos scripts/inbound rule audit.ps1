<#
.SYNOPSIS
    CyberForce 2026 - Comprehensive Windows Firewall Audit Script
#>

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "    WINDOWS FIREWALL COMPREHENSIVE AUDIT REPORT" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Audit Firewall Profiles (State & Logging)
Write-Host "`n[+] 1. Firewall Profile States & Logging Configuration:" -ForegroundColor Yellow
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked, LogFilePath | Format-Table -AutoSize

# 2. Audit All Active Inbound Allow Rules (Ports & Program Paths)
Write-Host "`n[+] 2. Active Inbound Allow Rules & Bindings:" -ForegroundColor Yellow
$inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow

$auditData = foreach ($rule in $inboundRules) {
    $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue
    $appFilter  = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        DisplayName   = $rule.DisplayName
        Profile       = $rule.Profile
        Protocol      = $portFilter.Protocol
        LocalPort     = $portFilter.LocalPort
        ProgramPath   = $appFilter.Program
    }
}

$auditData | Out-Host

# 3. Summary Count of Open Ports / Rules
$totalRules = $auditData.Count
Write-Host "`n[+] Audit Summary: Found $totalRules active inbound allow rules." -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
