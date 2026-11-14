# Shaamad's stuff

Shaamad's toolkit for CyberForce 2026 — complements the main repo's scripts,
doesn't replace them. Read the deltas below to know which tool to run when.

## Which script when

| Situation | Run |
|---|---|
| Fresh box, first hour (prep day) | `first-run.sh` — bootstrap: tools + full backups |
| Periodic check / "did red move?" | `persist-sweep.sh` — diff vs baseline |
| About to submit SecDoc / after any fix | `secdoc-verify.sh` — re-verify every promise |
| On a Windows box, same tripwire idea | `windows-sweep.ps1` |

## Scripts

### persist-sweep.sh (v3.8) — LEAP/UBUNTU/DEBIAN persistence tripwire
Different mission from `linux-vulnscan.sh`: vulnscan = one-shot point-in-time
audit; this one = **baseline + diff**. First run records state to
`/var/tmp/persist-sweep/`, every later run flags anything NEW (catches active
red-team drops mid-competition). Read-only, changes nothing. 29 sections incl.
things no other tool here does: rpm package integrity (trojaned binaries),
podman/container abuse, attack-tooling package scan, PAM `pam_permit` +
pam_deny-hash tamper check, xattr hiding spots, MySQL remote-root/SUPER grants,
polkit/motd/systemd-sockets baselines.
Run: `sudo ./persist-sweep.sh` (add `--log` for a file, `--quiet` for cron).
Exit code = # of CRIT findings.

**v3.2+** WordPress deep (plugins/mu-plugins/drop-ins diff, wp-config require()
audit, WP admins via the DB — auths with the creds from wp-config.php, so no
mysql root needed; green-user/green-admin must stay admins).
**v3.3–v3.5** false-positive fixes (root-only sudoers check, real-uploads-dir
match, immutable check skips dirs) + service vuln probes: uptime sanity for the
three scored services, ServerTokens/TRACE/directory-listing/.git + xmlrpc/REST
user-enum live probes, smb.conf parse + hosts-allow/deny scorer check, sshd
posture, postfix open-relay, mysql empty-password/local_infile, forgotten
listeners (tftp/nfs/rpcbind).
**v3.6** competition required-services matrix — auto-detects the box (openSUSE
= HTTP 80/MySQL 3306/SMB 139-445, Ubuntu with port 502 = OpenPLC 8080/Modbus
502 + ufw + default-creds probe, Debian = assume-breach monitor-only note).
One script covers Task .145, PLC1 .144, and PLC2 .143.
**v3.7** AB-intel cross-check: stray shadow copy files (the PLC2
`/etc/shadow.old` class) + finger listener on 79.
**v3.8** WP checks auth via wp-config creds; sudoers checks include
`/usr/etc/sudoers.d` (openSUSE's second @includedir — a real blind spot).

### first-run.sh (v2.1) — prep-day bootstrap (any distro, SUSE-fixed)
What it does, in order:

1. **Package installs** for the distro it detects (zypper on openSUSE). Expect
   noise: `not found` for nmap/auditd/unhide/whowatch is normal on Leap 16 —
   they don't exist in its repos, the `|| true` keeps going. It also removes
   netcat-openbsd (use `/dev/tcp` or socat instead afterward).
2. **rustnet + binsider** from GitHub releases into `/usr/local/bin` — rustnet
   = live per-process network TUI (your port scanner on Leap, since nmap is
   unavailable), binsider = ELF/binary analyzer for examining anything red
   drops.
3. **Webroot discovery + backup** — finds Apache DocumentRoot/nginx
   declarations, common paths, and any dir holding wp-config.php/wp-load.php,
   then copies each into the backup dir before anything else touches them.
4. **Full forensic backup** — `/etc`, `/bin` (a full merged-usr copy, expect
   ~700 MB), `/root`, `/etc/passwd`+`group`, PAM configs + pam modules, and
   every user's `.bashrc`/`.profile`/`.bash_history`/`.ssh` (rc implants and
   history are evidence gold). Plus point-in-time captures of listening ports
   and established connections.
5. **sshd hardening** — appends PermitRootLogin no, PermitEmptyPasswords no,
   AllowTcpForwarding no, X11Forwarding no (v2.1 finds the config in
   /etc/ssh or /usr/etc/ssh or sshd_config.d — Leap 16 has no
   /etc/ssh/sshd_config). Optional env toggles: NOPUB / AUTHKEY= / ROOTPUB=.
6. **Restarts** sshd + the web stack it finds (v2.1 prefers systemctl; the
   deprecated `service` deprecation warnings are gone). Brief blip — run
   between scoring rounds, not mid-round.
7. **pspy64 + linpeas.sh** land in the script's own directory (the shaamad's
   stuff checkout), with a writable-dir fallback.

Backup lands in **`/var/tmp/first-run/initial`** (v2.1; /tmp is purge-timer
territory). What's worth grabbing from it later: `listen`/`estab` (port
baseline), `homes/*/.*history` (pre-wipe evidence), `webroots/` (pre-deface
copies), `pam/` (pre-tamper module copies). **php.ini hardening is
intentionally NOT done** — the risky flags break WP admin + the historian
fetch on this HTTP-only box; web exposure is covered by web-recon findings
instead.

### secdoc-verify.sh (TASK-ONLY) — re-check every SecDoc promise
Walks each Task vulnerability row in the Team23 Security Documentation (the two
reinstalling backdoor services + immutable files, the 3 web shells + uploads
perms, svc-backup cron, the 45926 root shell + fake `ls`, LAN-bridge keylogger,
`cfc-redteam` key, sshd posture, ec2-user, firewall port set, extra `score` DB
account, mysql nologin, ServerTokens, credentials.zip, default-password
landmines). PASS/FAIL/WARN per row — FAIL = the SecDoc promise isn't currently
true. Fix, flip the row to past tense, re-run until clean.
Run: `sudo ./secdoc-verify.sh`
Competition-day verified: all rows PASS (false FAILs fixed — merged-usr
`/bin/ls`, systemd unit ExecStart parse incl. `/usr/lib`/`/usr/libexec`,
quarantined credentials.zip counts as gone, mysql client fallback to
`/usr/local/bin` + `/opt/mysql/bin`).

### windows-sweep.ps1 (v1) — WINDOWS persistence tripwire (same baseline→diff idea)
Complements `win-vulnscan.ps1` (that one's the one-shot audit). This keeps a
baseline under `HKLM:\ProgramData\winsweep` and diffs every run — new services =
CRIT, state flaps = WARN. Covers share ACLs/Everyone grants, writable system
paths, RDP/NLA, Run keys + AutoLogon + **IFEO sticky-keys hijack (CRIT)**,
non-Microsoft tasks, firewall rule diff + odd-port ALLOW flags, auditpol core
categories, prohibited media. Tested end-to-end (two-run diff cycle verified).
Run as Admin: `powershell -ExecutionPolicy Bypass -File .\windows-sweep.ps1`
DO NOT change anything on HMI/PLC2 (Assume Breach) — this script is read-only,
but so is the job description there.

## Intel docs

### answer-key-census.md
57 community practice-image answer keys mined and frequency-counted → hunt
priority lists for Linux and Windows + forensics-question shapes.

### secdoc-and-anomalies.md
SecDoc rubric distilled from the official annotated example (cross-section
consistency is graded; hand-drawn diagram > incomplete Visio; 22 vuln rows =
"not proficient"; tools-used must be listed) + anomaly attempt/syntax rules.

### ics-addendum.md
Deltas from the Team23 ICS guide: radar = PLC2/DNP3 independent of PLC1/Modbus
(check both streams after any incident), PLC2 persistence leads (inetd.conf,
/root/.ssh, exim4), historian cred confirmed `CyberForce2026!`.

### ab-quick-guide.md
One-pager for the two Assume-Breach boxes (PLC2 .143, HMI .142): golden rules,
first-30-min baseline commands, 30–60-min sweep cadence, PLC2 known state from
the Team23 findings (inetd.conf/root-ssh/exim4 leads, MQTT peers, the
shadow.old→Task chain), HMI first-walk checklist, evidence→SecDoc pipeline.
