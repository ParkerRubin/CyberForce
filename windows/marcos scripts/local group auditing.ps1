<#
.SYNOPSIS
    CyberForce 2026 - Local Group Backup, Purge & Reversion Utility
.DESCRIPTION
    1. Backs up current members of critical security groups to a JSON file.
    2. Purges unauthorized accounts while preserving authorized administrative & scoring accounts.
    3. Provides a restore function to roll back group memberships instantly if needed.
#>

$BackupPath = "C:\SecurityBackup_LocalGroups.json"

# Authorized accounts to preserve across critical groups
$AllowedAccounts = @("Administrator", "score1", "score2", "patch", "blueteam", "DefaultAccount", "Guest", "WDAGUtilityAccount")

# Critical local groups to manage
$TargetGroups = @(
    "Administrators",
    "Remote Management Users",
    "Remote Desktop Users",
    "Backup Operators",
    "Hyper-V Administrators",
    "Network Configuration Operators"
)

function Backup-LocalGroups {
    Write-Host "[+] Backing up current local group memberships..." -ForegroundColor Cyan
    $groupData = @()
    foreach ($group in $TargetGroups) {
        $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
        $groupData += [PSCustomObject]@{
            GroupName = $group
            Members   = @($members)
        }
    }
    $groupData | ConvertTo-Json -Depth 3 | Set-Content -Path $BackupPath -Encoding UTF8
    Write-Host "[PASS] Group state successfully saved to $BackupPath" -ForegroundColor Green
}

function Purge-UnauthorizedMembers {
    Write-Host "[+] Purging unauthorized members from critical groups..." -ForegroundColor Cyan
    foreach ($group in $TargetGroups) {
        $members = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue
        if (-not $members) { continue }

        foreach ($member in $members) {
            $shortName = $member.Name.Split('\')[-1]

            # Safety check: Never purge the built-in Administrator from Administrators
            if ($group -eq "Administrators" -and $shortName -eq "Administrator") { continue }

            if ($AllowedAccounts -notcontains $shortName) {
                Write-Host "    [REMOVING] '$($member.Name)' from [$group]" -ForegroundColor Yellow
                Remove-LocalGroupMember -Group $group -Member $member.Name -ErrorAction SilentlyContinue
            } else {
                Write-Host "    [KEPT] '$($member.Name)' in [$group]" -ForegroundColor DarkGray
            }
        }
    }
    Write-Host "[PASS] Group purge complete." -ForegroundColor Green
}

function Restore-LocalGroups {
    if (-not (Test-Path $BackupPath)) {
        Write-Host "[FAIL] Backup file not found at $BackupPath. Cannot restore." -ForegroundColor Red
        return
    }
    Write-Host "[+] Restoring local groups from $BackupPath..." -ForegroundColor Cyan
    $backupData = Get-Content -Path $BackupPath -Encoding UTF8 | ConvertFrom-Json
    foreach ($entry in $backupData) {
        $group = $entry.GroupName
        $savedMembers = $entry.Members
        if (-not $savedMembers) { continue }

        $currentMembers = (Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue).Name

        foreach ($m in $savedMembers) {
            if ($currentMembers -notcontains $m) {
                Write-Host "    [ADDING BACK] '$m' to [$group]" -ForegroundColor Yellow
                Add-LocalGroupMember -Group $group -Member $m -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Host "[PASS] Group state restored successfully." -ForegroundColor Green
}

# --- Interactive Menu ---
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "   LOCAL GROUP BACKUP, PURGE & RESTORE UTILITY" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "1. Backup current state AND purge unauthorized members"
Write-Host "2. Backup current state ONLY (no changes)"
Write-Host "3. Restore group memberships from backup JSON"
$choice = Read-Host "Select an option (1-3)"

switch ($choice) {
    "1" { Backup-LocalGroups; Purge-UnauthorizedMembers }
    "2" { Backup-LocalGroups }
    "3" { Restore-LocalGroups }
    default { Write-Host "[!] Invalid option selected. Exiting." -ForegroundColor Red }
}
