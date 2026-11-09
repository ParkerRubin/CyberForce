param(
  [switch]$ActiveProfilesOnly
)

# ================= CYBERFORCE 2026 FIREWALL (generic, interactive) =================
# Base firewall for the three Windows boxes (Mail-File, AD, HMI).
# Per-machine tuned versions with baked ports live in .\MachineName\firewall-tuned.ps1
# Use THIS one when you want full manual control of the port list.
#
# RULES OF PLAY (2026 — broken rules = lost points):
#   * NO allow-lists: never restrict a rule to specific source IPs/CIDRs.
#   * NO subnet blocks: block individual IPs only if ever needed.
#   * SCORE1/SCORE2/PATCH and the HMI 'historian' MySQL account must be able
#     to reach the box — never filter what they use.
#   * Assume-breach boxes (HMI): anything that breaks Red access = lost Red points.
#     On the HMI prefer firewall-tuned.ps1 -ReportOnly unless you have a reason.
# ================================================================================

# ================== EDIT THESE ==================
$EnableRDP = $true
# 2026 rules ban source-restricted rules, so RDP is created UNRESTRICTED.
# Strength of the box then = credential hygiene (see rotate-creds scripts).
$LogFolder = "$env:SystemRoot\System32\LogFiles\Firewall"

$KeepExistingInboundRules = $true
# =================================================

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
  Write-Host "ERROR: Run PowerShell as Administrator." -ForegroundColor Red
  exit 1
}

# ---- Machine requirements cheat sheet (2026 official AWS doc) ----
Write-Host ""
Write-Host "=== REQUIRED SCORED INBOUND PORTS BY MACHINE (type the ones for THIS box) ===" -ForegroundColor Cyan
Write-Host " Mail-File (Win2019 10.0.x.140): TCP 25 (SMTP), 1080 (HFS), 22 (SSH)"            -ForegroundColor Gray
Write-Host " AD         (Win2022 10.0.x.141): TCP 389 (LDAP), 22; UDP 161 (SNMP)"            -ForegroundColor Gray
Write-Host "                       + DC ops baseline: TCP 53,88,135,139,445,464,636,3268,3269; UDP 53,88,123,464" -ForegroundColor Gray
Write-Host " HMI        (Win2019 10.0.x.142 ASSUME-BREACH): TCP 8088 (Ignition), 3306 (MySQL historian)" -ForegroundColor Gray
Write-Host " Team access everywhere (type as needed, unrestricted): TCP 3389 (RDP), 5985 (WinRM)"  -ForegroundColor DarkGray
Write-Host " (AD also needs the RPC dynamic range 49152-65535; prefer .\AD\firewall-tuned.ps1)"   -ForegroundColor DarkGray
Write-Host ""

# ---- Interactive port prompt ----
function Read-PortList {
  param([string]$Label)
  Write-Host ""
  Write-Host "Enter inbound $Label ports to allow, comma-separated (blank = none)." -ForegroundColor Cyan
  Write-Host "Examples: 25,1080,22   or   161  (this prompt is $Label)" -ForegroundColor DarkGray
  $raw = Read-Host "$Label ports"
  if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
  $ports = @()
  foreach ($tok in ($raw -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })) {
    if ($tok -match '^\d{1,5}$' -and [int]$tok -ge 1 -and [int]$tok -le 65535) {
      $ports += [int]$tok
    } else {
      Write-Host "Ignoring invalid port: $tok" -ForegroundColor Red
    }
  }
  return ($ports | Sort-Object -Unique)
}

Write-Host "=== CYBERFORCE 2026 Firewall Baseline (generic) ===" -ForegroundColor Cyan
Write-Host "Machine box name (free text, used in output only, e.g. Mail-File):" -ForegroundColor DarkGray
$BoxName = Read-Host "Box name (blank = unnamed)"
if ([string]::IsNullOrWhiteSpace($BoxName)) { $BoxName = "UnnamedBox" }

$AllowedInboundTCP = Read-PortList -Label "TCP"
$AllowedInboundUDP = Read-PortList -Label "UDP"
Write-Host ""
Write-Host "TCP allowed: $($AllowedInboundTCP -join ', ')" -ForegroundColor Green
Write-Host "UDP allowed: $($AllowedInboundUDP -join ', ')" -ForegroundColor Green

Write-Host ""
Write-Host "RDP 3389 will be allowed UNRESTRICTED (source-restricted rules are banned this year)." -ForegroundColor Yellow
$rdpConfirm = Read-Host "Keep RDP open on 3389? [Y/n]"
$EnableRDP = -not ($rdpConfirm -match '^[Nn]')

$profilesToApply = @("Domain","Private","Public")
if ($ActiveProfilesOnly) {
  try {
    $cat = (Get-NetConnectionProfile -ErrorAction Stop | Select-Object -First 1).NetworkCategory
    if ($cat -eq "DomainAuthenticated") { $profilesToApply = @("Domain") }
    elseif ($cat -eq "Private") { $profilesToApply = @("Private") }
    elseif ($cat -eq "Public") { $profilesToApply = @("Public") }
  } catch {
    $profilesToApply = @("Domain","Private","Public")
  }
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = "C:\CF-Toolkit\firewall"
if (!(Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
$backupPath = Join-Path $backupDir "fwbackup_${BoxName}_$ts.wfw"
Write-Host "[1/7] Exporting firewall policy to $backupPath"
try { netsh advfirewall export $backupPath | Out-Null } catch {}

Write-Host "[2/7] Enabling firewall + setting defaults (Inbound=Block, Outbound=Allow)"
try {
  Set-NetFirewallProfile -Profile $profilesToApply `
    -Enabled True `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -AllowInboundRules $KeepExistingInboundRules `
    -AllowLocalFirewallRules True `
    -AllowUnicastResponseToMulticast False `
    -NotifyOnListen True | Out-Null
} catch {}

Write-Host "[3/7] Configuring firewall logging"
try {
  New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null
  Set-NetFirewallProfile -Profile $profilesToApply `
    -LogAllowed True `
    -LogBlocked True `
    -LogMaxSizeKilobytes 32767 `
    -LogFileName "$LogFolder\pfirewall.log" | Out-Null
} catch {}

Write-Host "[4/7] Removing old CFC26_ rules (if any)"
try {
  Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "CFC26_*" } |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
} catch {}

Write-Host "[5/7] Creating inbound allow rules for the ports you typed"

foreach ($p in $AllowedInboundTCP) {
  try {
    New-NetFirewallRule `
      -DisplayName "CFC26_${BoxName}_TCP_In_$p" `
      -Direction Inbound -Action Allow -Enabled True `
      -Protocol TCP -LocalPort $p `
      -Profile Domain,Private,Public `
      -EdgeTraversalPolicy Block | Out-Null
  } catch {}
}

foreach ($p in $AllowedInboundUDP) {
  try {
    New-NetFirewallRule `
      -DisplayName "CFC26_${BoxName}_UDP_In_$p" `
      -Direction Inbound -Action Allow -Enabled True `
      -Protocol UDP -LocalPort $p `
      -Profile Domain,Private,Public `
      -EdgeTraversalPolicy Block | Out-Null
  } catch {}
}

if ($EnableRDP) {
  Write-Host "[6/7] RDP enabled, unrestricted (rules ban source-restricted allows)"
  try {
    New-NetFirewallRule `
      -DisplayName "CFC26_${BoxName}_RDP_3389" `
      -Direction Inbound -Action Allow -Enabled True `
      -Protocol TCP -LocalPort 3389 `
      -Profile Domain,Private,Public `
      -EdgeTraversalPolicy Block | Out-Null
  } catch {}
} else {
  Write-Host "[6/7] RDP disabled by choice: blocking TCP/3389 (you are remoted in via SSH/WinRM)"
  try {
    New-NetFirewallRule `
      -DisplayName "CFC26_${BoxName}_Block_RDP_3389" `
      -Direction Inbound -Action Block -Enabled True `
      -Protocol TCP -LocalPort 3389 `
      -Profile Domain,Private,Public `
      -EdgeTraversalPolicy Block | Out-Null
  } catch {}
}

Write-Host "[7/7] Done. Current profile defaults:"
try {
  Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, LogAllowed, LogBlocked, LogFileName |
    Format-Table -AutoSize
} catch {}

Write-Host ""
Write-Host "Rules created:" -ForegroundColor Green
try {
  Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "CFC26_*" } |
    Select-Object DisplayName, Direction, Action, Enabled, Profile |
    Format-Table -AutoSize
} catch {}

Write-Host ""
Write-Host "Backup saved at: $backupPath" -ForegroundColor Yellow
Write-Host "POST-CHECK:" -ForegroundColor Yellow
Write-Host " - scored services reachable from team box + scoreboard (re-run and add port if not)"
Write-Host " - if this is AD, use windows\AD\firewall-ad.ps1 / firewall-tuned.ps1 instead (DC baseline)"
Write-Host " - run snapshot.ps1 + wininfo.ps1 to record the new baseline"
Write-Host " - record this change in Security Documentation (due Nov 9)"
