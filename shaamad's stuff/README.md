# Shaamad's stuff

Shaamad's toolkit for CyberForce 2026 — complements the main repo's scripts,
doesn't replace them. Read the deltas below to know which tool to run when.

## Scripts

### persist-sweep.sh (v3.1) — LEAP/UBUNTU/DEBIAN persistence tripwire
Different mission from `linux-vulnscan.sh`: vulnscan = one-shot point-in-time
audit; this one = **baseline + diff**. First run records state to
`/var/tmp/persist-sweep/`, every later run flags anything NEW (catches active
red-team drops mid-competition). Read-only, changes nothing. 25 sections incl.
things no other tool here does: rpm package integrity (trojaned binaries),
podman/container abuse, attack-tooling package scan, PAM `pam_permit` +
pam_deny-hash tamper check, xattr hiding spots, MySQL remote-root/SUPER grants,
polkit/motd/systemd-sockets baselines.
Run: `sudo ./persist-sweep.sh` (add `--log` for a file, `--quiet` for cron).
Exit code = # of CRIT findings.

### secdoc-verify.sh (TASK-ONLY) — re-check every SecDoc promise
Walks each Task vulnerability row in the Team23 Security Documentation (the two
reinstalling backdoor services + immutable files, the 3 web shells + uploads
perms, svc-backup cron, the 45926 root shell + fake `ls`, LAN-bridge keylogger,
`cfc-redteam` key, sshd posture, ec2-user, firewall port set, extra `score` DB
account, mysql nologin, ServerTokens, credentials.zip, default-password
landmines). PASS/FAIL/WARN per row — FAIL = the SecDoc promise isn't currently
true. Fix, flip the row to past tense, re-run until clean.
Run: `sudo ./secdoc-verify.sh`

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
