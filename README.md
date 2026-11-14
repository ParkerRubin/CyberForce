# CyberForce 2026 Toolkit

Blue Team scripts for the **DOE CyberForce Competition — November 13–14, 2026, Tinley Park Convention Center (Chicagoland)**.
Scenario: operations team for **Vulcana Dynamics Ltd. (VDL)**, the sole geothermal power utility of the Kaldera Archipelago. Opened with an unexplained **2:36 grid outage**; the **Island Defense Radar Network** depends on your grid staying up.

Official docs: https://github.com/CyberForceCompetition/2026_CyberForce_Competition (keep an eye on Rules-Expectations for updates — rule changes are announced in Discord #announcements).

---

## Environment (7 VMs, AWS VPC `10.0.x.0/27`, OpenVPN access)

### Traditional infrastructure — full hardening allowed

| VM | OS | IP | Required scored services | Default creds (rotate day 1!) |
|---|---|---|---|---|
| Task | OpenSUSE Leap | 10.0.x.145 | HTTP 80, MySQL 3306, SMB 139/445, SSH 22 | blueteam:BlueTeam2026! |
| Mail/File | Windows Server 2019 | 10.0.x.140 | HFS 1080, SMTP 25, SSH 22 | blueteam:BlueTeam2026! |
| AD | Windows Server 2022 | 10.0.x.141 | LDAP 389, SNMP 161/udp, SSH 22 | blueteam:BlueTeam2026! |
| PLC1 | Ubuntu 24 | 10.0.x.144 | Modbus 502, OpenPLC 8080 (`openplc:openplc`) | blueteam:BlueTeam2026! |

### Assume-breach — MONITOR ONLY, extreme caution (report Red attack chains = 1000 Red pts)

| VM | OS | IP | Required scored services | Default creds |
|---|---|---|---|---|
| PLC2 (DNP3) | Debian 13 | 10.0.x.143 | DNP3 20000, MQTT 1883 | blueteam:BlueTeam2026! |
| HMI/CnC | Windows Server 2019 | 10.0.x.142 | Ignition Gateway 8088, MySQL historian 3306 (`historian:CyberForce2026!` — NEVER rotate) | blueteam:BlueTeam2026! |

Plus **1 Anomaly VM** (creds competition day only). Total 7 VMs, environment limited to those.

### Scoring (10,000 total)

Red 2500 (AB attack-chain reporting 1000 + external pentest 1500) · Blue 2500 (uptime on required ports + geothermal production + radar uptime) · Green 1500 (website survey on Task VM) · Orange 2000 (video 1000 due Nov 2, 8AM PT + SecDoc 1000 due Nov 9, 8AM PT) · Anomalies 1500 (via USB on Friday Nov 14).

### Rules that constrain scripts

1. **NO allow-lists, NO subnet/CIDR blocks** — block individual IPs only. Blocked-IP mistakes lose points (any blocked IP may be a scorer).
2. **Never modify SCORE1 / SCORE2 / PATCH** (scoring SSH/RDP accounts) — no password changes, lockouts, deletes, or group changes.
3. **Never modify green-user / green-admin** (Green Team accounts on the WordPress site — keep them working).
4. **Never rotate the `historian` MySQL account on the HMI** (`historian/CyberForce2026!`) — Ignition and scoring depend on it.
5. **Never stop or remove modbus.service, dnp3.service, or OpenPLC** (PLC1/PLC2 ICS services).
6. **No hostname or IP changes** on any machine.
7. Assume-breach boxes: monitor at your own risk; no IP blocking there; anything that breaks Red access or scoring costs Red points.
8. Keep ONE shared, up-to-date team password list — record every new password BEFORE changing it.
9. VM naming: restored snapshots keep the identical name — **150 pts/vm misnamed**.
10. Snapshot revert limit 2/VM/hour; fresh re-image **75 pts/box** (snapshot early + often via Controller).
11. >2 password-reset ticket requests = 50 pts each; DMing staff = 10 pts each (use #ticket-system).
12. Free/open-source software only. **No AI tools** for anomaly resolution or defense.
13. Every infra change -> Security Documentation (template in comp repo).

---

## Layout (OS first; generic scripts at OS base; per-machine folders for host-specific content)

```
CyberForce\
  windows\                       <- generic Windows toolkit (push to Mail-File / AD / HMI)
    win-vulnscan.ps1             winPEAS-style console report: accounts/persistence/tasks/services/posture/creds/listeners (-Save = one file)
    install-tools.ps1            stages winPEASx64.exe, winPEAS.bat, 7zr.exe into %USERPROFILE%\cf-tools (run BEFORE comp day)
    snapshot.ps1                 baseline: firewall .wfw + users/services/netstat/processes/tasks (run every 15 min)
    wininfo.ps1                  inventory: ports<->rules, unsigned bins, LLMNR/mDNS/SSDP, Run keys
    triage_full.ps1              fast triage: SUMMARY.txt, LOLBins+cmdlines, targeted Security events
    tools.ps1                    Sysinternals installer (ProcExp, Autoruns, Sigcheck, TCPView)
    marcos scripts\              verify hardening.ps1 (72-pt PASS/FAIL audit) | local group auditing.ps1 (backup/purge/restore, CHANGES things) | general hardening (mail box).ps1 (lockdown, CHANGES things) | inbound rule audit.ps1 | audit outbound.ps1 | smb share.ps1 (captured report, not code) + README.md
    Mail-File\                   rotate-creds.ps1 | firewall-tuned.ps1 | REQUIRED-PORTS.md
    AD\                          rotate-creds.ps1 | firewall-tuned.ps1 | firewall-ad.ps1 | REQUIRED-PORTS.md
    HMI\                         rotate-creds.ps1 | firewall-tuned.ps1 (-ReportOnly) | REQUIRED-PORTS.md
  linux\                         <- generic Linux toolkit (push to Task / PLC1 / PLC2)
    linux-vulnscan.sh            linpeas-style console report: accounts/persistence/SUID/sshd/creds/listeners/ICS services (--save = one file; --fix = safe auto-remediation; --fix-ssh = sshd hardening; AB boxes need --confirm-ab) — NOTE: actually lives at PLC1\linux-vuln-scans.sh (PLC1-scoped for now; verify paths before running on Task/PLC2)
    install-tools.sh             distro-detect (apt/zypper): nmap, tcpdump, gpg, sshpass + stages linpeas.sh into ~/cf-tools
    precomp-hardening.sh         PRE-COMP window only (before scoring starts): updates, junk-service/old.* cleanup, listener ID, optional fail2ban, scored-port self-check (--comp-day = disable fail2ban before scoring starts)
    linuxinfo.sh                 inventory, --save writes Inventory_<host>_<ts>/inventory.txt
    readme.md                    manual hardening notes (passwd, rc customization, ufw, threat hunt)
    Task\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
    PLC1\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
    PLC2\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
  reference\                     cmd-cheatsheet.md | CCDC-command-dictionary.md | firewall-generic.ps1 | firewall-generic.sh
    pentest\                     web-recon.sh | web-vuln-tests.sh | master-vuln-checklist.md | install.sh
  shaamad's stuff\               persist-sweep.sh (v3.8 baseline→diff tripwire — auto-detects Task/PLC1/PLC2, comp required-services matrix, WP deep, AB cross-checks) | secdoc-verify.sh (Task SecDoc rows, comp-day verified) | windows-sweep.ps1 (Windows tripwire) | first-run.sh (v2 bootstrap, SUSE-fixed) | intel docs (answer-key census, practice-key hunt map, SecDoc/anomaly rules, ICS addendum)
  writeups\                      per-box hardening narratives (SecDoc-ready) — PLC1-hardening-log.md + img\ terminal-reconstruction SVGs + session handoff
  README.md
```

- **The canonical firewall per box lives in its machine folder** (`firewall-tuned.*`): that machine's scored ports are hard-wired, and the script still prompts for EXTRA TCP/UDP ports on top (same as the old generic). The generic scripts moved to `reference\` for two uses only: the **Anomaly VM** (no folder, unknown services until comp day) and emergency re-wiring when a scored port changes mid-event.

### PLC1 (10.0.186.144) current state — see `writeups\PLC1-hardening-log.md` for full detail
- **5 vulnerabilities self-patched in vendor OpenPLC code** (unauthenticated exec RCE; CVE-2026-14480 ×2 sinks; CVE-2026-71268; one beyond-CVE avatar-extension write path). Code backups on box: `webserver.py.bak-2026-11-14`, `.bak2-preS45`.
- **None of the code patches survive re-image** — and re-image costs 75 pts, so the recovery path is **snapshot revert** (free, ≤2/hr), not re-image. If a re-image ever happens: re-apply SUID fixes (`find`, `mount.nfs`, `polkit-agent-helper-1`) + firewall + the runbook in the writeup.
- OpenPLC v3 is EOL (Apr 2026) — CVE-2021-47770 documented-by-design, CVE-2026-11826 mitigation-only (recovery runbook), plaintext UI passwords inherited weakness. Full table in the writeup.
- Recovery one-liner if 502 drops: web UI (8080) → **Start PLC** → `sudo ss -tlnp | grep :502` → HMI (.142) auto-reconnects.

### Self-pentest (attack your own boxes first)
`reference\pentest\` + `CCDC-command-dictionary.md` are tools for the **self-pentest lane**: rules allow testing your OWN infrastructure and require finding its vulnerabilities for SecDoc (rubric wants a big mitigated vuln list; other infra off-limits).
- Prep phase (pre-comp — continue on remaining boxes mid-event): run `web-recon.sh` against http://10.0.x.145 (Task WP site), 10.0.x.140:1080 (HFS), 10.0.x.142:8088 → ffuf/nuclei/quick-wins; then `web-vuln-tests.sh` on every form/param you find. Walk `master-vuln-checklist.md` per box (its sections A web / B creds / C Linux / + Windows-AD cover exactly what winpeas/linpeas surface too).
- nuclei against scoring boxes MUST be rate-limited (uptime = Blue points; don't DoS your own box): build `cf-targets.txt` from the web surfaces above, then `nuclei -l cf-targets.txt -rl 20 -c 5 -timeout 10 -silent`.
- The FAU `report-generator` (in the FAU repo, not copied here) has ~35 prewritten findings (sudoers, suid, shadow, passwd, rootlogin, privatekeys, SQLi, XSS, NTLMv1, DefaultCredService, OutdatedService, weakDomainPassPolicy...) — perfect source language for the SecDoc "known vulnerabilities" table with CVSS.
### Scripts-first philosophy
- Everything ships as a **portable script or pre-staged binary run on demand** (winPEAS/linpeas/nmap/nuclei/ffuf) — **no new services/daemons installed** on scoring boxes.
- Default output = **one short console report per run** for hand-triage; files only where an explicit flag (`--save` / `-Save`) asks.
- winpeas/linpeas/nuclei are for the **deep/odd spots** (persistence, privesc, web edges) — the quick truths come from netstat/tasklist style one-liners in cmd-cheatsheet.md and the vulnscan scripts' console output.

Run order per box (AWS access day / first contact with a new box): `rotate-creds` -> `firewall(-tuned)` -> `precomp-hardening` -> `snapshot` -> `wininfo`/`linuxinfo`; then repeat snapshot on an interval and watch dnp3/modbus/Ignition/MySQL. **Snapshots are taken by the team (initial snapshot already exists) — confirm one exists before every hardening/fix run, and take a fresh one after, so the next revert lands on the post-change state.**

### Generic firewall notes
- Machine folders hold the only firewall you run in normal flow (`firewall-tuned.*`); nothing there prompts for source-address restrictions (banned this year); RDP 3389 goes in unrestricted.
- `reference\firewall-generic.ps1/.sh` exists ONLY for the Anomaly VM and unplanned port changes; it prompts TCP + UDP from scratch and prints the port cheat sheet before asking.

---
## Planned scripts (lean build list)

Philosophy: **scripts not services** - portable scripts + run-on-demand binaries only (winPEAS/linpeas/nmap/nuclei/ffuf), nothing installed on scoring boxes. Default output is a **short console report** for hand-triage; files only behind an explicit `--save`/`-Save` flag. Deep tools live in `reference\pentest\` or a pre-staged toolkit; the vulnscan scripts below just make the obvious answers faster.

### Windows (windows\) - DONE
1. **`win-vulnscan.ps1`** [x BUILT] - one console report, sections in priority order (`-Save` = one transcript file):
   - accounts: local users/admins/hidden `$` accounts/rid500/PasswordNeverExpires/blank-password detect
   - persistence: Run+RunOnce (HKCU/HKLM), Winlogon Shell/UserInit, IFEO, AppInit_DLLs, WMI event subs, netsh portproxy, hosts file
   - scheduled tasks: non-Microsoft, Action path+args+RunAs+trigger, boot/idle triggers flagged
   - services: auto-start outside C:\Windows, unquoted paths, recent 7045s
   - posture: Defender status+exclusions, RDP NLA, LmCompat, shares w/ Everyone, LAPS, AlwaysInstallElevated
   - creds/PS history: ConsoleHost_history.txt greps, cmdkey /list
   - listeners: TCP w/ owning process path (odd-path flags)
2. **`install-tools.ps1`** [x BUILT] - stages winPEASx64.exe, winPEAS.bat, 7zr.exe (anomaly USB unpacking) into `%USERPROFILE%\cf-tools`; SHA256 printed; Sysinternals stay via `tools.ps1`, nmap manual from laptop.
3. Optional later: `task-sweep.ps1` (fast re-run of just tasks+services).

### Linux (linux\) - DONE
1. **`linux-vulnscan.sh`** [x BUILT] - same shape, console report (`--save` = one file):
   - accounts: uid0 list, empty-password shadow, shell-capable users, sudoers NOPASSWD, wheel members, failed-SSH counts
   - persistence: cron dirs+user crontabs+at, systemd units/timers (odd Exec paths, ICS units marked DO-NOT-TOUCH), rc.local, authorized_keys w/ fingerprints, ld.so.preload, profile/bashrc greps
   - SUID shortlist (standard set whitelisted, odd ones flagged), world-writable /etc+/usr, PATH-dot check
   - sshd posture: PermitRootLogin/PasswordAuth/MaxAuthTries/PermitEmptyPasswords
   - creds greps: /etc conf files, bash_history, private keys, MySQL historian hints
   - listeners (ss -tulpn) + established outbound + running-deleted-binaries (dropper tell) + ICS service status (dnp3/modbus/ignition/openplc)
2. **`install-tools.sh`** [x BUILT] - distro-detect apt/zypper: nmap, tcpdump, gnupg, sshpass, lsof + stages linpeas.sh into `~/cf-tools` + usage one-liners (incl. tcpdump ring-pcap for AB boxes).
3. Still manual: linpeas/nmap/tcpdump run-on-demand from the staged tools (pcap > txt on AB boxes).

### Web + ICS
1. **`green-check`** (pure curl, mirrors your web-recon style) - the 12 Green survey items in one console pass/fail, optional `-save` log.
2. **`ics-watch`** - console-only live view: required ICS ports (502/20000/1883/8080/8088) open/closed + dnp3/modbus/Ignition service status + who is connected right now, refreshed; writes pcap ONLY on explicit flag (`tcpdump -C` ring, off by default).
3. Deep web surface stays manual: your `web-recon.sh` / `web-vuln-tests.sh` + nuclei against own boxes only (rules of engagement in the section above).

### Cross-cutting
1. **`baseline-diff`** (both OS) - "everything new since the good snapshot": console table from two snapshot/linuxinfo runs; no txt dump unless -save.
2. **`secdoc-gen`** (PS + bash) - the ONE file-producing tool by design: merges snapshot/wininfo/linuxinfo + vulnscan findings into the official SecDoc template tables (asset inventory, ports, vuln list w/ CVSS-ready rows; pairs with the FAU report-generator prewrites for language).
