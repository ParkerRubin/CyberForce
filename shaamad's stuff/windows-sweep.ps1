# ============================================================
# windows-sweep.ps1 v1 - NCAE blue-team persistence & exposure sweep
# Targets: Mail/File (2019), AD (2022), HMI (2019, ASSUME BREACH = watch only!)
# READ-ONLY: reports findings, changes nothing. First run = baseline,
# later runs DIFF - catches NEW drops (active red team) mid-competition.
# Built from the 31-image Windows answer-key census.
# Usage:  powershell -ExecutionPolicy Bypass -File .\windows-sweep.ps1 [-Quiet] [-Log]
# Run as Administrator for full coverage (firewall/audit/services).
# Exit code = number of CRIT findings.
# DO NOT run on HMI/PLC2 (Assume Breach) - viewing is fine, just never change.
# ============================================================
param([switch]$Quiet, [switch]$Log)
$ErrorActionPreference = 'SilentlyContinue'
if ($Log) {
  $logf = "winsweep-$(Get-Date -Format yyyyMMdd-HHmmss).log"
  Start-Transcript -Path $logf | Out-Null
}
$State = "$env:ProgramData\winsweep"
New-Item -ItemType Directory -Force -Path $State | Out-Null

$script:CRIT = 0; $script:WARN = 0
function Ok($m)   { if (-not $Quiet) { Write-Host "  [ OK ] $m" } }
function Info($m) { if (-not $Quiet) { Write-Host "  [INFO] $m" } }
function Warn($m) { Write-Host "  [WARN] $m"; $script:WARN++ }
function Crit($m) { Write-Host "  [CRIT] $m"; $script:CRIT++ }
function Hdr($m)  { Write-Host "`n== $m ==" }

function SaveBaseline($name, $text) {
  Set-Content -Path "$State\$name.txt" -Value $text -Encoding UTF8
}
function BaseDiff($name, $text) {
  # returns "NEW:<lines>" or "SAME" or "FIRST"
  $f = "$State\$name.txt"
  $cur = ($text | Sort-Object) -join "`n"
  if (-not (Test-Path $f)) { SaveBaseline $name $cur; return "FIRST" }
  $old = (Get-Content $f) -join "`n"
  if ($old -eq $cur) { return "SAME" }
  $oldSet = $old -split "`n"; $curSet = $cur -split "`n"
  $new = Compare-Object $oldSet $curSet | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject
  $gone = Compare-Object $oldSet $curSet | Where-Object SideIndicator -eq '<=' | ForEach-Object InputObject
  $r = @()
  if ($new)  { $r += "NEW: " + ($new -join ' | ') }
  if ($gone) { $r += "GONE(was that you?): " + ($gone -join ' | ') }
  return ($r -join "`n")
}
function DiffCheck($name, $text, $label) {
  $d = BaseDiff $name $text
  switch ($d) {
    "FIRST" { Ok "$label baseline recorded" }
    "SAME"  { Ok "$label unchanged" }
    default {
      if ($d -match '^NEW:|`nNEW:') { Crit "$label CHANGED since baseline: $d" }
      else { Warn "$label changed since baseline: $d" }
    }
  }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[!] NOT elevated - firewall/audit/service checks will be blind. Run as Admin." }

Write-Host "windows-sweep v1 $(Get-Date -F 'yyyy-MM-dd HH:mm:ss') on $env:COMPUTERNAME"

# --- 1. local users (census #9: hidden/extra users) -------------
Hdr "local users"
# DO-NOT-TOUCH list (scoring/competition accounts - never delete/disable/lock these!)
$DNT = @('score1','score2','patch','green-user','green-admin','blueteam','historian')
$users = Get-LocalUser
DiffCheck 'users' ($users | ForEach-Object { "$($_.Name)|enabled=$($_.Enabled)|lastlogon=$($_.LastSignonDate)" }) 'local user list'
foreach ($u in $users) {
  if ($DNT -contains $u.Name) {
    Info ("do-not-touch account present: {0} enabled={1}" -f $u.Name, $u.Enabled)
    continue
  }
  if ($u.Name -like '*$') { Warn "hidden-style account (trailing `$): $($u.Name)" }
}
# profile-list cross-check: accounts in registry but not in user list (hidden users)
$regUsers = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
  ForEach-Object { $_.PSChildName }) | Where-Object { $_ -match '^-?S-1-5-21-' }
$sidNames = @{}
foreach ($s in $regUsers) { $n = ([System.Security.Principal.SecurityIdentifier]$s).Translate([Security.Principal.NTAccount]).Value; $sidNames[$s] = $n }
$orphan = $sidNames.Values | Where-Object { $n = ($_ -split '\\')[-1]; -not ($users.Name -contains $n) }
if ($orphan) { Warn "registry profiles with no matching local account (deleted-but-traced or renamed backdoor): $($orphan -join ', ')" } else { Ok "no orphan profiles" }

# --- 2. administrators / groups ---------------------------------
Hdr "administrators"
DiffCheck 'admins' (Get-LocalGroupMember Administrators | ForEach-Object { "$($_.Name)|$($_.PrincipalSource)" }) 'Administrators group'
foreach ($m in Get-LocalGroupMember Administrators) {
  $n = ($m.Name -split '\\')[-1]
  if ($DNT -notcontains $n -and $m.PrincipalSource -eq 'Local' -and $n -ne 'Administrator') {
    Warn "local admin (confirm you made it): $($m.Name)"
  }
}

# --- 3. guest account (census #6) -------------------------------
Hdr "guest account"
$guest = Get-LocalUser Guest
if ($guest -and $guest.Enabled) { Crit "Guest account ENABLED - disable it" } else { Ok "Guest disabled" }

# --- 4. password policy (census #5) -----------------------------
Hdr "password policy"
net accounts | Out-File "$State\pwpolicy-live.txt" -Encoding UTF8
Get-Content "$State\pwpolicy-live.txt" | Where-Object { $_ } | ForEach-Object { Info "  $_" }
$pp = Get-Content "$State\pwpolicy-live.txt" | Out-String
if ($pp -match 'password length.{0,10}\b0\b|Minimum password length.*0') { Warn "min password length = 0" }
if ($pp -match 'history.*None|history length.{0,10}\b0\b') { Warn "no password history" }
DiffCheck 'pw-policy' (Get-Content "$State\pwpolicy-live.txt") 'password policy'
# --- 5. SMB shares (census #3: 24 images flag this) -------------
Hdr "smb shares"
$shares = Get-SmbShare | Where-Object { $_.Name -notmatch '^IPC\$|^ADMIN\$|^C\$' }
DiffCheck 'shares' ($shares | ForEach-Object { "$($_.Name)=$($_.Path)" }) 'share list'
foreach ($s in $shares) {
  $acl = Get-SmbShareAccess -Name $s.Name
  foreach ($a in $acl) {
    if ($a.AccountName -match 'Everyone|ANONYMOUS|BUILTIN\\Users' -and $a.AccessRight -ne 'None') {
      Warn "share '$($s.Name)' grants $($a.AccessControlType)/$($a.AccessRight) to $($a.AccountName)"
    }
  }
  Info "  share $($s.Name) -> $($s.Path)"
}
# writable C: root / Program Files by non-admin = drop zone
foreach ($p in @('C:\','C:\Program Files\','C:\Program Files (x86)\','C:\Windows\','C:\Windows\System32\')) {
  $w = Get-Acl $p | Select-Object -ExpandProperty Access |
    Where-Object { $_.FileSystemRights -band 2 -and $_.AccessControlType -eq 'Allow' -and
                   $_.IdentityReference -match 'Everyone|Users|ANONYMOUS' }
  if ($w) { Crit "WRITABLE system path: $p -> $($w.IdentityReference -join ',')" }
}
Ok "system path ACL scan done"

# --- 6. RDP hardening (census #4) -------------------------------
Hdr "rdp"
$ts = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
if ($ts -eq 0) { Info "RDP enabled (ok for a Windows box you must reach)" } else { Info "RDP disabled" }
$nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
if ($ts -eq 0 -and $nla -ne 1) { Warn "RDP without NLA (UserAuthentication=$nla) - set to 1" } else { Ok "NLA state=$nla" }
$enc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').SecurityLayer
if ($ts -eq 0 -and $enc -eq 0) { Warn "RDP SecurityLayer=0 (no TLS/Neg SSP)" } else { Ok "RDP security layer=$enc" }

# --- 7. services with odd ImagePath (census #7) -----------------
Hdr "services (odd ImagePath)"
$svc = Get-CimInstance Win32_Service
DiffCheck 'services-list' ($svc | ForEach-Object { "$($_.Name)=$($_.PathName)" }) 'service list'
DiffCheck 'services-state' ($svc | ForEach-Object { "$($_.Name)=$($_.State)" }) 'service states (flaps are normal - investigate before reacting)'
foreach ($s in $svc) {
  $path = $s.PathName -replace '^"?([^"]+)"?.*','$1'
  if ($path -and $path -notmatch '^(?i)C:\\Windows\\(system32|System32)') {
    if ($path -match '(?i)temp|users|desktop|downloads|programdata\\(?!(Microsoft|VMware))') {
      Warn "service $($s.Name) [$($s.State)] runs from odd path: $($s.PathName)"
    }
  }
  if ($s.Name -match '^(?i)(svhost|scvhost|windbg|backdoor|netcat|update\d+|mssecmgr)$' -or
      ($s.State -eq 'Running' -and $s.PathName -match 'svhost|scvhost')) {
    Warn "suspicious service name/path: $($s.Name) ($($s.PathName))"
  }
}
Ok "service scan done"

# --- 8. scheduled tasks (census #11) ----------------------------
Hdr "scheduled tasks"
$tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' }
DiffCheck 'tasks' ($tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)=$($_.State)" }) 'non-Microsoft tasks'
foreach ($t in $tasks) {
  $act = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
  if ($act -match '(?i)powershell.*-enc|-w hidden|cmd /c .*&|http|nc\.exe|\.vbs|\.bat$') {
    Warn "task $($t.TaskPath)$($t.TaskName) action: $act"
  }
}

# --- 9. registry persistence (census #12: Run keys, AutoLogon) --
Hdr "registry autostart"
$runPaths = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$runText = foreach ($rp in $runPaths) {
  $k = Get-ItemProperty $rp
  if ($k) { $k.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "$rp\$($_.Name) = $($_.Value)" } }
}
DiffCheck 'runkeys' $runText 'Run keys'
foreach ($l in $runText) {
  if ($l -match '(?i)regsvr32|powershell|wscript|http|\.hta|Users\\Public|Temp') { Crit "run key callback: $l" }
}
$al = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($al.AutoAdminLogon -eq '1') { Warn "AutoAdminLogon=1 (user=$($al.DefaultUserName), pw may be in DefaultPassword)" }
# Image File Execution Options debugger hijack (sethc/utilman/sticky keys)
$ifeo = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' |
  ForEach-Object { $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { "$($_.PSChildName) -> $d" } }
$badIfeo = $ifeo | Where-Object { $_ -match 'sethc|utilman|cmd|powershell' }
if ($badIfeo) { Crit "IFEO debugger hijack (sticky-keys backdoor class): $($badIfeo -join ' | ')" } else { Ok "no IFEO debugger hijack" }

# --- 10. startup folders ----------------------------------------
Hdr "startup folders"
$stText = Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup","$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
  ForEach-Object { $_.FullName }
DiffCheck 'startup' $stText 'startup folders'
# --- 11. firewall (census #8: attacker-added ALLOW rules) -------
Hdr "firewall"
if ($isAdmin) {
  $fwText = netsh advfirewall firewall show rule name=all dir=in |
    Select-String -Pattern 'Rule Name|Enabled:|Direction:|LocalPort|RemoteAddress|Action:|Program:' |
    ForEach-Object { $_.Line.Trim() }
  DiffCheck 'firewall' $fwText 'inbound firewall rules'
  # flag enabled ALLOW rules from any address to odd ports (attacker door)
  $raw = netsh advfirewall firewall show rule name=all dir=in
  $blocks = @(); $cur = @{}
  foreach ($l in $raw) {
    if ($l -match '^Rule Name:\s+(.*)$') { if ($cur.Count) { $blocks += [pscustomobject]$cur }; $cur = @{ name = $Matches[1] } }
    elseif ($l -match '^Enabled:\s+(.*)$')      { $cur.enabled = $Matches[1] }
    elseif ($l -match '^LocalPort:\s+(.*)$')    { $cur.port = $Matches[1] }
    elseif ($l -match '^RemoteIP:\s+(.*)$')     { $cur.rip = $Matches[1] }
    elseif ($l -match '^Action:\s+(.*)$')       { $cur.action = $Matches[1] }
  }
  if ($cur.Count) { $blocks += [pscustomobject]$cur }
  foreach ($b in $blocks) {
    if ($b.action -eq 'Allow' -and $b.enabled -eq 'Yes' -and
        ($b.rip -eq 'Local' -or $b.rip -eq 'Any' -or $b.rip -match '0\.0\.0\.0')) {
      if ($b.port -and $b.port -notmatch '^(RPC|Any|\d+-(\d+))?$' -and $b.port -notmatch '^(22|25|80|123|135|139|389|445|464|502|1080|1883|20000|3306|3389|5985|5986|8080|8088|49152-65535)$') {
        Warn "odd open inbound rule: '$($b.name)' port $($b.port) from $($b.rip)"
      }
    }
  }
  $profs = netsh advfirewall show allprofiles state | Select-String 'State'
  Info "  profiles: $($profs -join ' | ')"
} else { Warn "not elevated - firewall check skipped" }

# --- 12. audit / logging (census #1: 29 of 31 images!) ----------
Hdr "audit & logs"
if ($isAdmin) {
  $ap = auditpol /get /category:*  | Select-String -Pattern '(\S+.*)\s+(Success|Failure|Success and Failure|No Auditing)\s*$'
  $noAudit = $ap | Where-Object { $_.Matches[0].Groups[2].Value -eq 'No Auditing' } |
    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }
  $important = $noAudit | Where-Object { $_ -match '(?i)logon|logoff|account management|process creation|policy change' }
  if ($important) { Warn "no auditing on: $($important -join ', ')" } else { Ok "core audit categories enabled" }
  DiffCheck 'auditpol' ($ap | ForEach-Object { $_.Line.Trim() }) 'audit policy'
}
# event logs must exist and be writable; note sizes
foreach ($lg in @('System','Security','Application')) {
  $e = Get-EventLog -List | Where-Object { $_.Log -eq $lg }
  if ($e) { Info "  log $lg : maxKB=$($e.MaximumKilobytes) retDays=$($e.OverflowAction)" } else { Warn "event log $lg missing" }
}
# clear-text of logs being cleared is a red flag you cannot see after the fact:
Info "check Saturday: Security event 1102 (audit log cleared) = attacker footprint"

# --- 13. prohibited files / media (census #2: 27 images) --------
Hdr "prohibited files"
$exts = @('.mp3','.mp4','.avi','.mkv','.wav','.mov','.wmv','.jpg','.jpeg','.png','.gif','.torrent','.zip','.rar','.7z')
$roots = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","$env:USERPROFILE\Documents",
           "$env:ProgramData\Microsoft\Windows\Start Menu",'C:\Windows\System32','C:\inetpub\wwwroot')
$hits = foreach ($r in $roots) {
  Get-ChildItem $r -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $exts -contains $_.Extension.ToLower() } |
    ForEach-Object { "$($_.FullName) ($([math]::Round($_.Length/1MB,1))MB)" }
}
if ($hits) { Warn ("media/archive files in system/user dirs (delete unless scored):`n  " + (($hits | Select-Object -First 12) -join "`n  ")) } else { Ok "no prohibited media found" }
# browser download dirs + Public profile junk
$pub = Get-ChildItem 'C:\Users\Public' -Recurse -File -ErrorAction SilentlyContinue
if ($pub) { Info "  C:\Users\Public has $($pub.Count) files (inspect anything you didn't put there)" }

# --- 14. WinRM / LLMNR-ish quick posture ------------------------
Hdr "misc posture"
$winrm = Get-Service WinRM
if ($winrm.Status -eq 'Running') { Info "WinRM running (needed? not on your scored list - consider stopping Saturday)" }
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1) { Crit "SMBv1 ENABLED" } else { Ok "SMBv1 disabled" }
$llnr = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DNSClient' -ErrorAction SilentlyContinue
if ($llnr.EnableMulticast -eq 1) { Warn "LLMNR multicast enabled" } else { Ok "LLMNR policy: disabled/absent" }

# --- summary ----------------------------------------------------
Write-Host "`n=============== RESULT: $CRIT crit / $WARN warn ==============="
if ($CRIT -gt 0) { Write-Host "Fix CRITs first; one change-log line per fix. Re-sweep after." }
if ($Log) { Stop-Transcript | Out-Null }
exit $CRIT


