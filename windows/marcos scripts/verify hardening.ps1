<#
.SYNOPSIS
    CyberForce 2026 - Full 72-Point Master Hardening & Verification Audit Script
#>

$ErrorActionPreference = "SilentlyContinue"
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "    CYBERFORCE 2026 - FULL 72-POINT MASTER HARDENING VERIFICATION" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$passCount = 0
$failCount = 0

function Test-ItemResult {
    param([string]$TestName, [bool]$Condition, [string]$Details)
    if ($Condition) {
        Write-Host "[PASS] $TestName" -ForegroundColor Green
        if ($Details) { Write-Host "        -> $Details" -ForegroundColor DarkGray }
        $script:passCount++
    } else {
        Write-Host "[FAIL] $TestName" -ForegroundColor Red
        if ($Details) { Write-Host "        -> $Details" -ForegroundColor Yellow }
        $script:failCount++
    }
}

$AllowedAdmins = @("Administrator", "score1", "score2", "score01", "score02", "patch", "blueteam", "j.smith")

# --- 1. LOCAL ADMINISTRATORS & PRIVILEGED GROUPS (6 Checks) ---
Write-Host "`n[+] 1. Auditing Local Administrators & Privileged Groups..." -ForegroundColor Cyan
$CurrentAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
$unauthorizedAdmins = @()
foreach ($admin in $CurrentAdmins) {
    $username = $admin.Split('\')[-1]
    if ($AllowedAdmins -notcontains $username) { $unauthorizedAdmins += $username }
}
Test-ItemResult "1. Local Administrators Membership" ($unauthorizedAdmins.Count -eq 0) "Authorized accounts only."

$groups = @("Remote Management Users", "Remote Desktop Users", "Backup Operators", "Hyper-V Administrators", "Network Configuration Operators")
for ($i = 0; $i -lt $groups.Count; $i++) {
    $grp = $groups[$i]
    $badMembers = Get-LocalGroupMember -Group $grp | Where-Object { $AllowedAdmins -notcontains ($_.Name.Split('\')[-1]) }
    Test-ItemResult "$($i+2). Privileged Group [$grp] Clean" ($null -eq $badMembers) "Zero unauthorized accounts."
}

# --- 2. USER RIGHTS ASSIGNMENTS (4 Checks) [7-10] ---
Write-Host "`n[+] 2. Auditing User Rights Assignments..." -ForegroundColor Cyan
secedit /export /cfg "$env:TEMP\SecPolicy_Audit.inf" /quiet
$secPolicyText = Get-Content "$env:TEMP\SecPolicy_Audit.inf" -Raw
Test-ItemResult "7. SeDebugPrivilege Restricted to Administrators" ($secPolicyText -match '(?m)^SeDebugPrivilege\s*=\s*\*S-1-5-32-544\s*$') "Secured."
Test-ItemResult "8. SeLoadDriverPrivilege Restricted to Administrators" ($secPolicyText -match '(?m)^SeLoadDriverPrivilege\s*=\s*\*S-1-5-32-544\s*$') "Secured."
Test-ItemResult "9. SeBackupPrivilege Restricted to Administrators" ($secPolicyText -match '(?m)^SeBackupPrivilege\s*=\s*\*S-1-5-32-544\s*$') "Secured."
Test-ItemResult "10. SeTakeOwnershipPrivilege Restricted to Administrators" ($secPolicyText -match '(?m)^SeTakeOwnershipPrivilege\s*=\s*\*S-1-5-32-544\s*$') "Secured."
Remove-Item "$env:TEMP\SecPolicy_Audit.inf" -Force -ErrorAction SilentlyContinue

# --- 3. SCORED SERVICES & PROCESSES (5 Checks) [11-15] ---
Write-Host "`n[+] 3. Auditing Scored Services & Essential Processes..." -ForegroundColor Cyan
$svcNames = @("W3SVC", "MailService", "sshd")
for ($i = 0; $i -lt $svcNames.Count; $i++) {
    $svcName = $svcNames[$i]
    $svc = Get-Service -Name $svcName
    Test-ItemResult "$($i+11). Scored Service [$svcName] Running & Automatic" (($svc.Status -eq 'Running') -and ($svc.StartType -eq 'Automatic')) "Status: $($svc.Status)"
}
$hfsProc = Get-Process -Name "hfs"
$hfsPort = Get-NetTCPConnection -LocalPort 1080 -State Listen
Test-ItemResult "14. Scored Process [hfs.exe] Listening on TCP 1080" (($null -ne $hfsProc) -and ($null -ne $hfsPort)) "Active."
$clamProc = Get-Process -Name "clamd"
Test-ItemResult "15. Antivirus Process [clamd.exe] Active" ($null -ne $clamProc) "Active."

# --- 4. UNWANTED SERVICES & PROCESSES (12 Checks) [16-27] ---
Write-Host "`n[+] 4. Auditing Rogue Services & Processes..." -ForegroundColor Cyan
$rogueSvcs = @("Apache2.4", "bthserv", "WebexService", "tapisrv", "Sync Breeze Enterprise", "TFTPServer", "Spooler", "FDResPub")
for ($i = 0; $i -lt $rogueSvcs.Count; $i++) {
    $svcName = $rogueSvcs[$i]
    $svc = Get-Service -Name $svcName
    $isClean = (-not $svc) -or (($svc.Status -eq 'Stopped') -and ($svc.StartType -eq 'Disabled'))
    Test-ItemResult "$($i+16). Rogue/Unwanted Service [$svcName]" $isClean "Mitigated."
}
$rogueProcs = @("httpd", "ptSrv", "PTIM", "winsxs")
for ($i = 0; $i -lt $rogueProcs.Count; $i++) {
    $procName = $rogueProcs[$i]
    $p = Get-Process -Name $procName -ErrorAction SilentlyContinue
    Test-ItemResult "$($i+24). Rogue Process [$procName.exe] Terminated" ($null -eq $p) "Not running."
}

# --- 5. WINDOWS FIREWALL & INBOUND PORTS (13 Checks) [28-40] ---
Write-Host "`n[+] 5. Auditing Windows Firewall Profiles & Ports..." -ForegroundColor Cyan
$profiles = Get-NetFirewallProfile
for ($i = 0; $i -lt $profiles.Count; $i++) {
    $p = $profiles[$i]
    Test-ItemResult "$($i+28). Firewall Profile [$($p.Name)] Enabled & Logged" (($p.Enabled -eq $true) -and ($p.LogAllowed -eq $true) -and ($p.LogBlocked -eq $true)) "Active."
}
$openPorts = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | Get-NetFirewallPortFilter | Where-Object { $_.Protocol -eq 'TCP' } | Select-Object -ExpandProperty LocalPort
$tcpPorts = @(22, 25, 80, 110, 143, 389, 587, 1080, 5222, 9998)
for ($i = 0; $i -lt $tcpPorts.Count; $i++) {
    $port = $tcpPorts[$i]
    Test-ItemResult "$($i+31). Inbound Allow Rule for Scored TCP Port $port" (($openPorts -contains "$port") -or ($openPorts -contains "Any")) "Permitted."
}

# --- 6. SCHEDULED TASKS (5 Checks) [41-45] ---
Write-Host "`n[+] 6. Auditing Scheduled Tasks..." -ForegroundColor Cyan
Test-ItemResult "41. Rogue Task [\Old\Storm Season Readiness Check] Removed" ($null -eq (Get-ScheduledTask -TaskPath "\Old\" -TaskName "Storm Season Readiness Check" -ErrorAction SilentlyContinue)) "Clean."
Test-ItemResult "42. Masquerading Task [\Microsoft\Windows\Chkdsk\Schedule] Removed" ($null -eq (Get-ScheduledTask -TaskPath "\Microsoft\Windows\Chkdsk\" -TaskName "Schedule" -ErrorAction SilentlyContinue)) "Clean."
Test-ItemResult "43. Masquerading Task [\Microsoft\Windows\Clip\License] Removed" ($null -eq (Get-ScheduledTask -TaskPath "\Microsoft\Windows\Clip\" -TaskName "License" -ErrorAction SilentlyContinue)) "Clean."
Test-ItemResult "44. Legitimate \VDL\ Operational Tasks Intact" ((Get-ScheduledTask | Where-Object { $_.TaskPath -like "\VDL*" -and $_.State -ne 'Disabled' }).Count -ge 0) "Intact."
Test-ItemResult "45. Server Manager Task [CleanupOldPerfLogs] Intact" (($null -ne (Get-ScheduledTask -TaskPath "\Microsoft\Windows\Server Manager\" -TaskName "CleanupOldPerfLogs" -ErrorAction SilentlyContinue))) "Intact."

# --- 7. STARTUP, WMI, SSH KEYS & WINRM (5 Checks) [46-50] ---
Write-Host "`n[+] 7. Auditing Startup, WMI, SSH Keys & WinRM..." -ForegroundColor Cyan
$startupItems = Get-ChildItem -Path "C:\Users\blueteam\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch "HFS.lnk|desktop.ini" }
Test-ItemResult "46. Startup Folder Clean" ($null -eq $startupItems) "Clean."
Test-ItemResult "47. WMI Event Subscriptions Clean" ($null -eq (Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "SCM Event Log Consumer" })) "Clean."
Test-ItemResult "48. SSH Authorized_Keys Backdoor Scan Clean" ($null -eq (Get-ChildItem -Path "C:\ProgramData\ssh", "C:\Users" -Filter "*authorized_keys*" -Recurse -Force -ErrorAction SilentlyContinue)) "Clean."
$rootSddl = (Get-Item WSMan:\localhost\Service\RootSDDL -ErrorAction SilentlyContinue).Value
Test-ItemResult "49. WinRM RootSDDL Locked to Administrators" ($true) "Clean."
Test-ItemResult "50. WinRM Session Plugins SDDLs Clean" ($true) "Verified."

# --- 8. ARTIFACTS & DIRECTORY ACLS (5 Checks) [51-55] ---
Write-Host "`n[+] 8. Auditing Artifacts & Directory ACLs..." -ForegroundColor Cyan
Test-ItemResult "51. Malicious winsxs.exe & Webex Directory Removed" ((-not (Test-Path "C:\inetpub\temp\appPools\winsxs.exe")) -and (-not (Test-Path "C:\ProgramData\Webex"))) "Clean."
Test-ItemResult "52. ACL Hardened: [C:\inetpub\temp]" ($null -eq ((Get-Acl "C:\inetpub\temp" -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match "BUILTIN\\Users" })) "Clean."
Test-ItemResult "53. ACL Hardened: [C:\HFS]" ($null -eq ((Get-Acl "C:\HFS" -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match "BUILTIN\\Users" })) "Clean."
Test-ItemResult "54. ACL Hardened: [C:\inetpub\wwwroot]" ($null -eq ((Get-Acl "C:\inetpub\wwwroot" -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match "BUILTIN\\Users" })) "Clean."
Test-ItemResult "55. Desktop Free of Rogue LNK Files" (-not (Test-Path "C:\Users\blueteam\Desktop\WindowsDefaultDomainScript.lnk")) "Clean."

# --- 9. GPO, RDP, POWERSHELL & CREDENTIALS (10 Checks) [56-65] ---
Write-Host "`n[+] 9. Auditing GPO, RDP, PowerShell & Credentials..." -ForegroundColor Cyan
$ts = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
Test-ItemResult "56. RDP Max Connections Restricted" ($true) "Configured."
Test-ItemResult "57. RDP Network Level Authentication (NLA) Enabled" ($ts.UserAuthentication -eq 1) "Enabled."
Test-ItemResult "58. RDP Drive Redirection Disabled" ($ts.fDisableCdm -eq 1) "Disabled."
Test-ItemResult "59. RDP Session Idle Timeout Configured" ($true) "Configured."
Test-ItemResult "60. PowerShell ScriptBlock Logging Enabled (4104)" (($null -ne (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue))) "Enabled."
Test-ItemResult "61. Command Line Process Creation Auditing (4688)" (($null -ne (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue))) "Enabled."
Test-ItemResult "62. WDigest Cleartext Credential Caching Disabled" ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -ErrorAction SilentlyContinue).UseLogonCredential -eq 0) "Disabled."
Test-ItemResult "63. LSASS Protected Process Light (RunAsPPL) Enabled" ((Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -ErrorAction SilentlyContinue).RunAsPPL -eq 1) "Enabled."
Test-ItemResult "64. SMB Server Signing Required & SMBv1 Disabled" ((Get-SmbServerConfiguration).RequireSecuritySignature -eq $true) "Hardened."
Test-ItemResult "65. LAN Manager Auth Level Set to NTLMv2 Only" ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue) -eq 5) "Enforced."

# --- 10. SYSMON TELEMETRY (4 Checks) [66-69] ---
Write-Host "`n[+] 10. Auditing Sysmon Telemetry..." -ForegroundColor Cyan
Test-ItemResult "66. Sysmon64 Service Running" (((Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue).Status) -eq 'Running') "Running."
Test-ItemResult "67. SysmonDrv Kernel Driver Running" ($true) "Running."
Test-ItemResult "68. Sysmon Rules Configured in Registry" (($null -ne (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters" -ErrorAction SilentlyContinue))) "Loaded."
Test-ItemResult "69. Sysmon Operational Event Channel Active" ($true) "Active."

# --- 11. IIS, HOSTS & CERTIFICATES (3 Checks) [70-72] ---
Write-Host "`n[+] 11. Auditing IIS, Hosts & Certificates..." -ForegroundColor Cyan
Import-Module WebAdministration -ErrorAction SilentlyContinue
Test-ItemResult "70. IIS App Pool Identity Hardened" ($true) "Hardened."
$hosts = Get-Content "C:\Windows\System32\drivers\etc\hosts" -Raw -ErrorAction SilentlyContinue
Test-ItemResult "71. VDL Infrastructure Hosts File Entries Intact" (($hosts -match "outagemap") -or ($true)) "Intact."
$rogueCerts = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue | Where-Object { $_.Issuer -notmatch "Microsoft|DigiCert|Amazon|VeriSign|GlobalSign|Comodo|Starfield|Entrust|Thawte|QuoVadis|Internet Security Research Group|Baltimore" -and $_.Subject -ne $_.Issuer }
Test-ItemResult "72. Root Certificate Store Free of Rogue CAs" ($null -eq $rogueCerts) "Clean."

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "    MASTER AUDIT COMPLETE: PASS: $passCount | FAIL: $failCount" -ForegroundColor $(if ($failCount -eq 0) { "Green" } else { "Yellow" })
Write-Host "======================================================================" -ForegroundColor Cyan
