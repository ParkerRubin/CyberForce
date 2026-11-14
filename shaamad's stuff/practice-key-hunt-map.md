# Practice-key hunt map — from 57 image keys to the Team23 boxes
*The community answer keys are the closest ground truth we have to what the
CyberForce build crew seeds — same scoring engine (aeacus-style checks), same
vuln classes, same "keep services up while removing malware" constraint. Every
class below was SEEN in a key, with the box it likely lives on, the detection
one-liner, and the fix. Pair with the FAU report-generator prewrites for SecDoc
language (folder names match classes).*

## Concrete seeded examples mined from the keys (proving the overlap)
- `PermitRootLogin yes` in sshd_config → set `no` (Among Us, SH11)
- **`PermitRootLogin without-password` + /root/.ssh/authorized_keys** — our PLC2
  lead on Nov 13 matches a known seeded class (SH11 keys in /home/*/.ssh)
- `ld.so.preload` + libprocesshider (Mr. Robot — process hiding via preload)
- **root's .bashrc aliases/implants** — Fellowship of the Ring runs a train when
  root runs `ls` (check rc files for joyride/aliases)
- Hidden users: `sierra` (Kali's Ubuntu), `mkbutsuj-` (Kimetsu) — names that
  look almost normal are the pattern
- World-writable nginx.conf / Apache dirs scored by name (Critical Service Chaos)
- Prohibited software john/nmap flagged as removable (Aperture Science)
- Windows: `LmCompatibilityLevel` in registry (Aperture Windows)
- Hollow Knight: `.bashrc` + git-history forensics (FQ answers in files)

## Linux hunt order (Task → PLC1 → PLC2)
| # | Class (keys) | Detect | Fix | SecDoc prewrite |
|---|---|---|---|---|
| 1 | Hidden/rogue users (35 keys) | `awk -F: '$1 ~ /^\./ \|\| $1 ~ /\.\./' /etc/passwd` + baseline diff | lock/delete (NOT score*/green-*) | passwd |
| 2 | sudoers NOPASSWD drops (5) | `grep -rh NOPASSWD /etc/sudoers.d/` | remove drop file | sudoers |
| 3 | rc-file implants (Fellowship train) | `grep -rlE '/dev/tcp\|curl.*\|sh\|nc -e' /etc/profile* /etc/bash.bashrc /root/.bashrc /home/*/.bashrc` | strip line | privatekeys/passwd |
| 4 | authorized_keys backdoors (4) | `find /root /home -name authorized_keys` — check fingerprints vs yours | remove key | privatekeys |
| 5 | SUID oddballs (8) | `find / -xdev -perm /6000 -type f` minus whitelist | chmod u-s (verify not scored) | suid |
| 6 | ld.so.preload process hiding (1) | `[ -s /etc/ld.so.preload ]` | empty the file | — |
| 7 | systemd units/timers (6) | `systemctl list-timers --all`; cat units in /etc/systemd/system + /usr/lib/systemd/system | disable+remove (NOT dnp3/modbus) | OutdatedService |
| 8 | cron drops (6) | `ls /etc/cron.d/ /var/spool/cron/tabs/` baseline | remove drop | — |
| 9 | Container abuse (14) | `podman ps -a`, `~/.docker/config.json`, group members | inspect/remove | DefaultCredService |
| 10 | Attack tooling (14) | `command -v hydra john nmap steghide...` | `rpm -e` / `apt remove` (not scored) | — |
| 11 | World-writable web/db confs | `find /etc/nginx /srv/www /etc/apache2 -perm /022` | chmod 640/644 | WebInfoDisclosure |
| 12 | PAM auth bypass | `grep -r pam_permit /etc/pam.d/`; hash-check pam_deny.so | restore pam_deny | weakDomainPassPolicy |
| 13 | Empty passwords | `awk -F: '($2==""){print $1}' /etc/shadow` | passwd rotate | passwd |
| 14 | xattr hiding spots | `getfattr -R -m 'user\.' -d /etc /root /home` | remove attr | — |

## Windows hunt order (Mail-File → AD → HMI watch-only)
| # | Class (keys) | Detect | Fix | SecDoc prewrite |
|---|---|---|---|---|
| 1 | Audit policy gutted (29 keys!) | `auditpol /get /category:*` | restore core categories | — |
| 2 | Prohibited files/media (27) | sweep Desktop/Downloads/ProgramData/System32 | delete | — |
| 3 | Everyone-granted shares (24) | `Get-SmbShareAccess -Name <s>` | fix ACL | OpenSMBShare |
| 4 | RDP hardening (16) | NLA `UserAuthentication=1`, SecurityLayer | set | — |
| 5 | Weak password policy (12) | `net accounts` (min len 0 / history none) | set policy | weakDomainPassPolicy |
| 6 | Guest enabled (10) | `Get-LocalUser Guest` | disable | DefaultCredService |
| 7 | Odd-Imagepath services (8) | services running from Temp/Users/ProgramData | stop+disable+delete | OutdatedService |
| 8 | Attacker firewall ALLOWs (8) | firewall rule baseline diff | remove single rule | winFirewall |
| 9 | Hidden users (7) | `Get-LocalUser` + registry ProfileList orphans | remove (NOT score*/green-*) | passwd |
| 10 | sethc/utilman IFEO hijack (5) | `Debugger` value under IFEO keys | delete value | UtilmanBackdoor |
| 11 | Scheduled tasks (4) | non-Microsoft tasks w/ encoded PS/http actions | remove | OutdatedService |
| 12 | Run keys / AutoLogon (2+undercounted) | HKCU/HKLM Run diffs | remove entry | — |
| 13 | LmCompat/NTLMv1 (keys) | LmCompatibilityLevel registry | raise level | NTLMv1 |
| 14 | ConsoleHost_history leaks | grep PS history for creds | rotate + clear | AdminLeakedCreds |

## Rules of the road (from the keys' penalty side)
- Deleting legit users = negative points in practice images; CyberForce identical
  (score1/score2/patch/green-*/historian NEVER). When in doubt on a user:
  **disable, don't delete** — reversible, still scores the fix.
- Stopping critical services = negative points → before removing anything
  service-shaped, check it against the required-ports list for that box
  (REQUIRED-PORTS.md files in this repo).
- Forensics/anomaly answers get written to files on the box (Hollow Knight FQ
  pattern: `ANSWER1: ...` in a Desktop file) — same discipline for CyberForce
  anomalies: match the syntax hint EXACTLY, easy ones allow one attempt.
