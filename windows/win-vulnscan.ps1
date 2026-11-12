param(
  [switch]$Save          # -Save writes ONE transcript file, otherwise console-only
)

# ============================================================
# CYBERFORCE 2026 - WIN-VULNSCAN (winPEAS-style, custom)
# One short console report for hand-triage. Changes NOTHING.
# Sections: system, accounts, persistence, scheduled tasks,
# services, posture, creds/history, listeners.
# Deep sweeps still belong to winPEASx64.exe (see install-tools.ps1)
# - this script filters to CyberForce signal.
# Run as Administrator for full visibility (works degraded without).
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Save) {
  $dir = "C:\CF-Toolkit\vulnscan"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $ts  = Get-Date -Format "yyyyMMdd-HHmmss"
  $file = Join-Path $dir "vulnscan-$env:COMPUTERNAME-$ts.txt"
  Start-Transcript -Path $file -Force | Out-Null
  Write-Host "Transcript: $file"
}
if (-not $isAdmin) {
  Write-Host "[!] Not elevated: security log, ACLs and some checks will be limited." -ForegroundColor Yellow
}

function Section([string]$t) {
  Write-Host ""
  Write-Host "=== $t ===" -ForegroundColor Cyan
}
function Flag([string]$t)  { Write-Host "  [!!] $t" -ForegroundColor Red }
function Warn([string]$t)  { Write-Host "  [?]  $t" -ForegroundColor Yellow }
function Item([string]$t)  { Write-Host "  $t" }

# ---------------- SYSTEM ----------------
Section "SYSTEM"
Item "Host: $env:COMPUTERNAME  ($env:USERDOMAIN)"
$os = Get-CimInstance Win32_OperatingSystem
Item "OS: $($os.Caption) $($os.Version)  build $($os.BuildNumber)"
Item "Uptime since: $($os.LastBootUpTime)"
$lastPatches = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3
Item "Last patches: " + (($lastPatches | ForEach-Object { "$($_.HotFixID) ($($_.InstalledOn))" }) -join ' | ')

# ---------------- ACCOUNTS ----------------
Section "ACCOUNTS"
$localUsers = Get-LocalUser
Item "Local users: " + (($localUsers | ForEach-Object { $_.Name }) -join ', ')
$hidden = $localUsers | Where-Object { $_.Name -match '\$' }
foreach ($h in $hidden)  { Flag "hidden account: $($h.Name)" }
$rid500 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'"
if ($rid500) {
  if ($rid500.Name -ne 'Administrator') { Item "RID-500 renamed: '$($rid500.Name)' (expected name change - note in SecDoc)" }
  else { Item "RID-500: default 'Administrator' (rotate its password too)" }
}
Item "Administrators group:"
foreach ($m in (Get-LocalGroupMember Administrators)) {
  Item "   $($m.Name)  ($($m.PrincipalSource))"
}
$stale = $localUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires }
foreach ($u in $stale) { Warn "$($u.Name): password never expires" }
$noPass = $localUsers | Where-Object { $_.Enabled -and (-not $_.PasswordRequired) }
foreach ($u in $noPass) { Flag "$($u.Name): ENABLED with password-not-required" }

# ---------------- PERSISTENCE ----------------
Section "PERSISTENCE"
foreach ($k in @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
  $props = Get-ItemProperty -Path $k
  if ($props) {
    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
      $looks = if ($_.Value -match 'appdata|temp|programdata|powershell|cmd|wscript|cscript') { ' [!!]' } else { '' }
      Item "Run: $k :: $($_.Name) = $($_.Value)$looks"
    }
  }
}
$wl = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Shell    -ne 'explorer.exe') { Flag "Winlogon Shell hijacked: $($wl.Shell)" }
else { Item "Winlogon Shell: explorer.exe (normal)" }
if ($wl.Userinit -notmatch 'userinit.exe') { Flag "Winlogon Userinit hijacked: $($wl.Userinit)" }
$ifeo = Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
        Where-Object { (Get-ItemProperty $_.PSPath).Debugger }
foreach ($i in $ifeo) { Flag "IFEO debugger on '$($i.PSChildName)' -> $((Get-ItemProperty $i.PSPath).Debugger)" }
$appinit = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows').AppInit_DLLs
if ($appinit) { Flag "AppInit_DLLs set: $appinit" }
$wmiSubs = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
foreach ($w in $wmiSubs) { Flag "WMI event consumer: $($w.__CLASS) $($w.Name)" }
$proxy = netsh interface portproxy show all 2>$null
if ($proxy -match '\d') { Warn "portproxy rules present:"; $proxy | ForEach-Object { Item "   $_" } }
$hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -and $_ -notmatch '^\s*#' }
if ($hosts.Count -gt 2) { Warn "hosts file has extra entries:"; $hosts | ForEach-Object { Item "   $_" } }

# ---------------- SCHEDULED TASKS ----------------
Section "SCHEDULED TASKS (non-Microsoft)"
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }
foreach ($t in $tasks) {
  foreach ($a in $t.Actions) {
    $ex   = $a.Execute
    $args = $a.Arguments
    $odd  = if ($ex -match 'appdata|temp|programdata|powershell|cmd\.exe|wscript|cscript|certutil|bitsadmin') { ' [!!]' } else { '' }
    $runAs = $t.Principal.UserId
    $trig  = ($t.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join ','
    $hot   = if ($trig -match 'Boot|Logon|Idle') { ' [?trigger]' } else { '' }
    Item "$($t.TaskPath)$($t.TaskName)  state=$($t.State)$hot"
    Item "   action: $ex $args$odd    runas: $runAs"
  }
}
if (-not $tasks) { Item "(none)" }

# ---------------- SERVICES ----------------
Section "SERVICES (auto-start, outside C:\Windows, or unquoted)"
$svcs = Get-CimInstance Win32_Service | Where-Object { $_.StartMode -match 'Auto' -and $_.PathName }
foreach ($s in $svcs) {
  $path = $s.PathName.Trim('"')
  $exe  = $path -replace '\s.*$',''
  if ($path -notmatch '^"?C:\\Windows\\' ) {
    $quoted = if ($s.PathName -notmatch '^"' -and $path -match '\s' -and $path -match '\.exe') { ' [UNQUOTED-PATH]' } else { '' }
    Flag "$($s.Name): $($s.PathName)$quoted  state=$($s.State)  acct=$($s.StartName)"
  }
}
$recent = Get-WinEvent -FilterHashtable @{ LogName='System'; Id=7045 } -MaxEvents 8
foreach ($e in $recent) {
  Flag "service installed [$($e.TimeCreated)]: $($e.Message -replace "`r`n",' | ')"
}

# ---------------- POSTURE ----------------
Section "POSTURE"
$mp = Get-MpComputerStatus
if ($mp) {
  Item "Defender realtime: $($mp.RealTimeProtectionEnabled)  AV: $($mp.AntivirusEnabled)"
  if (-not $mp.RealTimeProtectionEnabled) { Flag "Defender real-time protection OFF" }
}
$pref = Get-MpPreference
$excl = @(); if ($pref) { $excl = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ } }
if ($excl) { Flag "Defender EXCLUSIONS present:"; $excl | ForEach-Object { Item "   $_" } } else { Item "Defender exclusions: none" }
$aie_hkcu = (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
$aie_hklm = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer').AlwaysInstallElevated
if ($aie_hkcu -eq 1 -and $aie_hklm -eq 1) { Flag "AlwaysInstallElevated: ON (MSI privesc path)" } else { Item "AlwaysInstallElevated: off" }
$rdpNla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
Item "RDP NLA (UserAuthentication): $rdpNla  (0 = NLA off)"
$lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').LmCompatibilityLevel
if ($lm -ne $null) { Warn "LmCompatibilityLevel: $lm (2 or below sends weak NTLMv1)" } else { Item "LmCompat: default" }
Item "SMB shares (non-default):"
foreach ($sh in (Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$)' })) {
  Item "   $($sh.Name) -> $($sh.Path)"
  foreach ($acc in (Get-SmbShareAccess -Name $sh.Name | Where-Object { $_.AccessControlType -eq 'Allow' })) {
    if ($acc.AccountName -match 'Everyone|Anonymous') { Flag "   share '$($sh.Name)' allows $($acc.AccountName)" }
  }
}
$laps = (Get-Command Get-LapsADPassword -ErrorAction SilentlyContinue) -or (Test-Path "$env:ProgramFiles\LAPS\CSE\Admpwd.dll")
if (-not $laps) { Warn "LAPS not detected (rotate local admin manually + document)" }

# ---------------- CREDS / HISTORY ----------------
Section "CREDS / PS HISTORY"
Item "cmdkey stored credentials:"
cmdkey /list | Select-String -Pattern 'Target|User' | ForEach-Object { Item "   $($_.Line.Trim())" }
$histRoots = @("$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine")
Get-ChildItem "C:\Users" -Directory | ForEach-Object {
  $histRoots += Join-Path $_.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
}
foreach ($h in ($histRoots | Sort-Object -Unique | Where-Object { Test-Path $_ })) {
  foreach ($f in (Get-ChildItem $h -Filter *history*.txt)) {
    Item "history: $($f.FullName) ($((Get-Content $f).Count) lines)"
    Get-Content $f | Where-Object { $_ -match 'passw|secret|token|psw|cred|mount|netsh|enc' } | ForEach-Object { Flag "   hist: $_" }
  }
}

# ---------------- LISTENERS ----------------
Section "LISTENERS (TCP, with owning process)"
$net = Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique
foreach ($c in $net) {
  $p  = Get-Process -Id $c.OwningProcess
  $pn = if ($p) { $p.Name } else { 'unknown' }
  $pp = if ($p) { $p.Path } else { '' }
  $odd = if ($pp -match 'AppData|Temp|ProgramData') { ' [!! odd path]' } else { '' }
  Item "$($c.LocalAddress):$($c.LocalPort)  <- $pn$odd" + $(if ($pp) { "  ($pp)" })
}
Write-Host ""
if ($Save) { Stop-Transcript | Out-Null; Write-Host "Transcript saved: $file" -ForegroundColor Green }
