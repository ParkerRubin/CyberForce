<#
.SYNOPSIS
    CyberForce 2026 - Comprehensive Mail/File Server Lockdown & Remediation
.DESCRIPTION
    Purges unauthorized local accounts, sweeps non-standard scheduled tasks,
    hardens firewall profiles with logging, opens scored service ports, and enforces core services.
#>

$ErrorActionPreference = "SilentlyContinue"
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "   CYBERFORCE - FULL SYSTEM LOCKDOWN & REMEDIATION" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Audit and Secure Local User Accounts
Write-Host "`n[+] Disabling Unauthorized Local User Accounts..." -ForegroundColor Yellow
$AllowedUsers = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount", "score1", "score2", "patch", "blueteam")
$AllUsers = Get-LocalUser
foreach ($user in $AllUsers) {
    if ($AllowedUsers -notcontains $user.Name) {
        Disable-LocalUser -Name $user.Name -ErrorAction SilentlyContinue
        Write-Host "   - Disabled unauthorized account: $($user.Name)" -ForegroundColor Red
    } else {
        Enable-LocalUser -Name $user.Name -ErrorAction SilentlyContinue
        if ($user.Name -match 'score|patch') {
            Set-LocalUser -Name $user.Name -PasswordNeverExpires $true
        }
        Write-Host "   - Verified required account: $($user.Name)" -ForegroundColor Green
    }
}

# 2. Sweep Suspicious Scheduled Tasks
Write-Host "`n[+] Sweeping Non-Standard Scheduled Tasks..." -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.Author -notmatch "Microsoft" -and $_.TaskPath -eq "\" } | ForEach-Object {
    Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "   - Removed rogue task: $($_.TaskName)" -ForegroundColor Yellow
}

# 3. Enforce Firewall Profiles & Packet Logging
Write-Host "`n[+] Hardening Windows Firewall & Enabling Logging..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True
Set-NetFirewallProfile -Profile Domain, Private, Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32768
Write-Host "   - Firewall profiles active with allowed/blocked packet logging enabled." -ForegroundColor Green

# 4. Open Inbound Ports for Scored Services
Write-Host "`n[+] Opening Inbound Ports for Scored Services..." -ForegroundColor Yellow
$ScoredPorts = @(22, 25, 80, 110, 143, 389, 587, 5222, 9998)
foreach ($port in $ScoredPorts) {
    $ruleName = "CFC_Scored_Port_$port"
    Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $port -Action Allow | Out-Null
    Write-Host "   - Opened TCP Port $port" -ForegroundColor Green
}

# 5. Configure Core Services
Write-Host "`n[+] Ensuring Core Services are Running and Automatic..." -ForegroundColor Yellow
$CriticalServices = @("W3SVC", "MailService", "sshd")
foreach ($svcName in $CriticalServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Set-Service -Name $svcName -StartupType Automatic
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
        Write-Host "   - Service [$svcName] set to Automatic and Started." -ForegroundColor Green
    } else {
        Write-Host "   - Service [$svcName] not found on this image." -ForegroundColor DarkGray
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   LOCKDOWN & REMEDIATION COMPLETE." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
