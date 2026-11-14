# Practice-Image Answer Key Census — distilled for CyberForce 2026
**Built:** Fri Nov 13 2026 (night before competition) · **Sources:** 57 image answer keys
(LINUX + WINDOWS zips) — 62 key PNGs + 20 PDFs OCR'd, 166 text answers folded in.
**Corpus location (this machine):** `%TEMP%\keyscorpus\*.txt` (56 of 57 files; the
Windows Persistence Practice Image key was auto-quarantined by Defender — its text contains
literal malware commands. Re-extract from the zip to a non-scanned folder if needed.)
**Caveats:** OCR noise; counts blend key content + README boilerplate — the *ordering* is
the signal, not exact numbers.

## Structural lesson #1: the scoring engines score RESTRAINT (aeacus scoring.conf, Hollow Knight)
- Positive checks: vuln fixed / FQ answered via answer file on Desktop.
- **PENALTY checks (negative points):** deleting a legitimate user (-10 each), deleting a
  critical service account (-1000), stopping a critical service (-10). Legit-user lists are
  long; "remove users" is only rewarded for the seeded rogues. CyberForce identical:
  score1/score2/patch/green-*/historian untouched, services stay up.
- Check TYPES used by scoring engines: file-contains-regex, command-output, user-in-group,
  program-installed-not, permission-is. Fix = make the artifact *look right to a scanner*.

## Linux census (29 images) — hunt priority for Task VM + PLC boxes
| Rank | Class (images mentioning) | persist-sweep v2 status |
|---|---|---|
| 1 | Firewall rules incl. attacker-added ALLOWs (40) | ✅ firewall-cmd diff |
| 2 | Hidden/rogue/test users (35) | ✅ old.* + passwd diff — ADD pattern hunt for `..`-style/odd names |
| 3 | Docker/podman abuse: docker group, privileged, sock mount (14) | ❌ ADD (Task VM runs rootless podman!) |
| 4 | Attack tools left installed: wireshark/john/hydra/steghide/nmap (14) | ❌ ADD package scan |
| 5 | MySQL/MariaDB: anon users, remote root, bad grants (13) | ✅ partial — ADD remote-root + grants check |
| 6 | Netcat-style backdoors: renamed binaries, .bashrc listeners (11) | ✅ rc pattern hunt — ADD renamed-service-binary check |
| 7 | Insecure services: telnet/ftp/tftp/xinetd (10) | ❌ ADD service inventory vs allowlist |
| 8 | SUID abuse (8) | ✅ |
| 9 | Password policy: pam pwquality/pwhistory/minlen (8) | ❌ ADD policy config check |
| 10 | Forensics CVE-knowledge Qs (7) | (anomaly prep, not sweepable) |
| 11-13 | Cron persistence (6) · sshd config root/empty/extra ports (6) · systemd persistence (6) | ✅ all three |
| 14-16 | Samba guest/masks (5) · shadow perms (5) · base64 reverse shells (5) | ✅ |
| 17-20 | sudoers NOPASSWD (5) · updates (4) · SSH key backdoors (4) · webshell/php (4) | ✅ |
| rare | UID-0 dupes (2) · polkit (1) · ld.so.preload (1) · PHP hardening (1) | ✅ covered anyway |

## Windows census (31 images) — hunt priority for Mail/File, AD, HMI
| Rank | Class (images mentioning) | Windows-sweep spec item |
|---|---|---|
| 1 | Audit/logging config (29) | auditpol/advanced audit policy + wevtutil log presence |
| 2 | Prohibited files/software/media in system dirs (27) | scan Program Files/system32/user dirs for media/games/junk |
| 3 | SMB share permissions incl. Everyone-shares (24) | `net share` + Get-SmbShareAccess enumeration |
| 4 | RDP hardening (16) | RDP enabled-only-where-needed, NLA on |
| 5 | Password policy (12) | net accounts / PasswordComplexity/maxpwage/pwhistory |
| 6 | Guest account enabled (10) | Guest disabled check |
| 7 | Malicious services (8) | services with odd ImagePath (user-writable paths, /temp, renamed) |
| 8 | Firewall incl. attacker-added allows (8) | netsh advfirewall rule diff/baseline |
| 9 | Hidden/extra users (7) | local user inventory vs provided list (do-not-touch: score1/2/patch) |
| 10 | Sticky-keys/sethc/utilman backdoors (5) | compare sethc/utilman binaries + registry Image File Execution |
| 11 | Scheduled tasks (4) | schtasks inventory + non-Microsoft tasks |
| 12 | AutoLogon/autostart (2) | Winlogon AutoLogon + Run keys |
| rare | Startup-folder items (1) · rogue local admins (1) · Run keys (0 in OCR — likely undercounted) | check all anyway |

## Forensics-question flavor (161 FQ files)
Dominant shapes: CVE identification + disclosure dates + researcher names · JWT/token decoding ·
auth-log brute-force IP attribution → cross-ref DB · webshell parameter extraction ·
base64-obfuscated callback destinations · git-history secret recovery · flag-in-file.
**Tonight prep:** CyberChef + jwt.io bookmarked, log-frequency one-liner muscle memory
(`grep "Failed password" auth.log | awk '{print $NF}' | sort | uniq -c | sort -rn | head`),
`git log`/`git show` habit, 7-Zip/gpg ready for the anomaly USB.

## Tomorrow-morning priority order (synthesis of all sources)
1. Scored services up (PLC started, Ignition wired, HTTP/MySQL/SMB answering) — biggest point mass
2. persist-sweep full run on Task VM; fix CRITs only, log every change
3. Windows boxes: run `windows-sweep.ps1` (same dir as this doc; baseline first run,
   diff every run after) — covers audit/prohibited files/shares/RDP/Guest/services/tasks/sethc/run keys/firewall
4. HMI/PLC2: WATCH only (Assume Breach) — log red-team activity, change nothing
5. Green checklist 12 items via task.blue0023.cfc.local from subnet machine
6. Anomalies: answer file discipline, syntax/case per hints, never early-access the USB
