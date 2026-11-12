param(
  [string]$ToolDir = "$env:USERPROFILE\cf-tools"
)

# ============================================================
# CYBERFORCE 2026 - INSTALL TOOLS (Windows side)
# Stages portable run-on-demand tools. NO services installed.
# Runs WITHOUT admin (files under user profile).
# Pre-stage BEFORE comp day (Nov 2-13) - VMs have internet, but
# don't bet on it during the event.
# Sysinternals (ProcExp/Autoruns/Sigcheck/TCPView) -> tools.ps1
# ============================================================

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $ToolDir | Out-Null
Write-Host "Tool dir: $ToolDir" -ForegroundColor Cyan

function Get-Tool {
  param([string]$Name, [string]$Url)
  $dest = Join-Path $ToolDir $Name
  if (Test-Path $dest) {
    Write-Host "[skip] $Name already staged" -ForegroundColor DarkGray
    return $true
  }
  try {
    Write-Host "[get ] $Name ..." -NoNewline
    Invoke-WebRequest -Uri $Url -OutFile $dest -UserAgent 'Mozilla/5.0' -TimeoutSec 120
    Write-Host " ok" -ForegroundColor Green
    return $true
  } catch {
    Write-Host " FAILED: $($_.Exception.Message)" -ForegroundColor Red
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    return $false
  }
}

# ---- PEASS-ng: winPEAS (vuln/privesc/persistence deep sweep) ----
Get-Tool 'winPEASx64.exe' 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe'
Get-Tool 'winPEAS.bat'    'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEAS.bat'

# ---- 7zr.exe: console 7-Zip, needed to open the anomaly USB package ----
Get-Tool '7zr.exe' 'https://www.7-zip.org/a/7zr.exe'

# ---- SHA verify + usage notes ----
Write-Host ""
Write-Host "=== STAGED (with SHA256) ===" -ForegroundColor Cyan
Get-ChildItem $ToolDir -File | ForEach-Object {
  $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.Substring(0,16)
  "{0,-20} {1,10:N0} bytes  SHA256:{2}..." -f $_.Name, $_.Length, $h
}

Write-Host ""
Write-Host "=== USAGE ===" -ForegroundColor Cyan
Write-Host " winPEASx64.exe            deep vuln/persistence sweep (slow, noisy - run once early, review offline)"
Write-Host " winPEAS.bat               if only cmd/ps is allowed on a box (no exe execute)"
Write-Host " 7zr.exe x <file>.7z       unpack anomaly files (day-of; NOTE: full .zip support needs 7-Zip GUI or Windows Explorer)"
Write-Host ""
Write-Host "ALSO stage once per team laptop:" -ForegroundColor Yellow
Write-Host " - Sysinternals suite -> run windows\tools.ps1 (ProcExp, Autoruns, Sigcheck, TCPView)"
Write-Host " - nmap (installer from nmap.org/download) for the subnet sweep from your laptop"
Write-Host " - the FAU pentest kit -> reference\pentest\install.sh on a Kali/player box (ffuf, nuclei, seclists)"
