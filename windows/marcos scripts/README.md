# Marco's Windows scripts

Collected by shaamad from Marco, Nov 14. Run as Administrator.

| Script | Type | What it does |
|---|---|---|
| `verify hardening.ps1` | AUDIT (read-only) | 72-point master verification: admins/groups, user rights (secedit export), scored services (W3SVC/MailService/sshd/HFS 1080/clamd), rogue services+procs, firewall profiles + scored inbound ports, scheduled tasks, startup/WMI/SSH-keys/WinRM, ACLs, RDP/PS logging/WDigest/LSASS PPL/SMB signing/NTLMv2, Sysmon, IIS/hosts/root-CA store. PASS/FAIL count at the end. |
| `local group auditing.ps1` | **CHANGES THINGS** (menu 1) | Backup-then-purge unauthorized members of Administrators/RMU/RDP/Backup Ops/Hyper-V/NetCfg Ops to `C:\SecurityBackup_LocalGroups.json`. Menu 2 = backup only, menu 3 = restore from JSON. |
| `general hardening (for the mail box).ps1` | **CHANGES THINGS** | Mail/File box lockdown: disables non-allowlist local users, removes non-Microsoft root-path scheduled tasks, enables firewall profiles + logging, opens scored TCP ports (22/25/80/110/143/389/587/5222/9998), enforces W3SVC/MailService/sshd auto+running. |
| `inbound rule audit.ps1` | AUDIT (read-only) | Firewall profiles + every active inbound allow rule with ports and program paths. |
| `audit outbound.ps1` | AUDIT (read-only) | Outbound default actions + every active outbound rule incl. remote address/port bindings. |
| `smb share.ps1` | **CAPTURED REPORT OUTPUT, not code** | Marco's SMB shares + NTFS ACL report (Archive/ControlRoomLogs/FieldReports/Finance/HR/IT/Maintenance/Regulatory/StormPlans/Vendors). Do not "run" it — reference for expected share permissions. |

## Cautions (competition rules)

- The two CHANGES-THINGS scripts follow the scored-port list 22/25/80/110/143/389/587/5222/9998 — that's the Mail/File box matrix. Do NOT run the lockdown script on the HMI or AD box without checking that box's own port set first.
- `local group auditing.ps1` purges group members — always pick option 2 (backup only) FIRST, review the JSON, then purge.
- Audit scripts are safe on any Windows box, including Assume-Breach (HMI/PLC2 are Windows-adjacent — document only there).
