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
2. **Never modify SCORE1 / SCORE2 / PATCH** (scoring SSH/RDP accounts).
3. Assume-breach boxes: monitor at your own risk; no IP blocking there; anything that breaks Red access or scoring costs Red points.
4. VM naming: restored snapshots keep the identical name — **150 pts/vm misnamed**.
5. Snapshot revert limit 2/VM/hour; fresh re-image **75 pts/box** (snapshot early + often via Controller).
6. >2 password-reset ticket requests = 50 pts each; DMing staff = 10 pts each (use #ticket-system).
7. Free/open-source software only. **No AI tools** for anomaly resolution or defense.
8. Every infra change -> Security Documentation (template in comp repo).

---

## Layout (OS first; generic scripts at OS base; per-machine folders for host-specific content)

```
CyberForce\
  windows\                       <- generic Windows toolkit (push to Mail-File / AD / HMI)
    snapshot.ps1                 baseline: firewall .wfw + users/services/netstat/processes/tasks (run every 15 min)
    wininfo.ps1                  inventory: ports<->rules, unsigned bins, LLMNR/mDNS/SSDP, Run keys
    triage_full.ps1              fast triage: SUMMARY.txt, LOLBins+cmdlines, targeted Security events
    tools.ps1                    Sysinternals installer (ProcExp, Autoruns, Sigcheck, TCPView)
    Mail-File\                   rotate-creds.ps1 | firewall-tuned.ps1 | REQUIRED-PORTS.md
    AD\                          rotate-creds.ps1 | firewall-tuned.ps1 | firewall-ad.ps1 | REQUIRED-PORTS.md
    HMI\                         rotate-creds.ps1 | firewall-tuned.ps1 (-ReportOnly) | REQUIRED-PORTS.md
  linux\                         <- generic Linux toolkit (push to Task / PLC1 / PLC2)
    linuxinfo.sh                 inventory, --save writes Inventory_<host>_<ts>/inventory.txt
    readme.md                    manual hardening notes (passwd, rc customization, ufw, threat hunt)
    Task\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
    PLC1\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
    PLC2\                        rotate-creds.sh | firewall-tuned.sh | REQUIRED-PORTS.md
  reference\                     cmd-cheatsheet.md | firewall-generic.ps1 | firewall-generic.sh
  README.md
```

- **The canonical firewall per box lives in its machine folder** (`firewall-tuned.*`): that machine's scored ports are hard-wired, and the script still prompts for EXTRA TCP/UDP ports on top (same as the old generic). The generic scripts moved to `reference\` for two uses only: the **Anomaly VM** (no folder, unknown services until comp day) and emergency re-wiring when a scored port changes mid-event.

Run order per box on Nov 2 (AWS access day): `rotate-creds` -> `firewall(-tuned)` -> `snapshot` -> `wininfo`/`linuxinfo`; then repeat snapshot on an interval and watch dnp3/modbus/Ignition/MySQL.

### Generic firewall notes
- Machine folders hold the only firewall you run in normal flow (`firewall-tuned.*`); nothing there prompts for source-address restrictions (banned this year); RDP 3389 goes in unrestricted.
- `reference\firewall-generic.ps1/.sh` exists ONLY for the Anomaly VM and unplanned port changes; it prompts TCP + UDP from scratch and prints the port cheat sheet before asking.

---

## Planned: defensive enumeration / hardening / vuln-hunting scripts (build list)

Everything below is **report-only** style: none of these change the system, they surface what to fix so hardening choices are deliberate and SecDoc-documented (and nothing breaks scoring without review) unless they clearly modify only state safe to change (rotate-creds).

### Web vulnerabilities
- **`green-check` (Linux)** — automate all 12 Green survey items on Task's WordPress-style site (landing page, orange accent #ea4524, nav order, volcano-1.png banner, tagline, About Us, both logins/APIs + Admin button visibility, users list, footer, Geothermal Data charts, logo, chatbot reply) into a pass/fail + curl-reproduce script for every listed item. This site is GOLD for 1500 Green pts: checking it from OUTSIDE the box catches breakage you caused with your own hardening.
- **`web-vulnscan` (bash + PS variant)** — curl-based, unauthenticated web scanner for anything listening on 80/1080/8080 in your range: HTTP method reachability (OPTIONS/TRACE/PUT/DELETE), directory indexing, common exposure probes (.git/HEAD, .env, wp-config.php.bak, backup.zip, /admin, /wp-admin, /phpmyadmin, /xmlrpc.php, /wp-json/wp/v2/users), server banner fingerprints, missing security headers, default-credential attempt against exposed login forms (blueteam-style credentials are public knowledge in the repo), reflect-on-input quick XSS/SQLi probes into obvious query parameters. Every hit = evidence with reproducible curl lines.

### Windows enumeration (winPEAS-style, homemade, opensource)
- **`win-vulnscan.ps1`** — patch level + hotfixes, Defender status/exclusions (Active/defog/off), services with unquoted paths, weak service binary/folder ACLs, mismatched service Account-vs-install, scheduled tasks writable by non-admins, AlwaysInstallElevated on 2 HK keys, LLMNR/mDNS/NetBIOS exposure (cross-ref wininfo), RDP NLA?, WinRM allowed from where, SMBv1 status, SMB signing, shares with Everyone/Anonymous, installed-software quick inventory (flag old versions), local password/lockout policy, users with PasswordNeverExpires or blank flags, PS Read-Host perms, autoruns by helper, saved PS history, greps Creds: locations (cmdkey /runas?), LAPS presence, current shell Win-who|priv check -> printable findings with a "how to fix" line under each.
- **`win-backdoor-hunter.ps1`** — persistence-focused deep sweep: Run/RunOnce (HKCU + HKLM), Winlogon Shell/UserInit, custom services binaries outside standard dirs, Scheduled Task XML (creators, actions, triggers), WMI Event Subscriptions, IFEO entries, AppInit_DLLs, netsh portproxy entries, hosts-file edits, hidden accounts (names ending in '$'), accounts created since last snapshot delta, recently created tasks (Sec Events 4698/7045), processes running unsigned/TEMP-path binaries, established connections on unknown ports (PID map), alternate data streams. Pairs with snapshot.ps1 to diff baseline vs now.

### Linux enumeration (linpeas-style, homemade, opensource)
- **`linux-vulnscan.sh`** — SUID/SGID inventory (non-standard bins highlighted), world-writable files/dirs incl. /etc content, empty-password users in shadow, users with login shells, uid-0 duplicates, sudoers/l-sudo audit (NOPASSWD, wildcards, Cmnd_Alias), PATH entries with '.' or dirs writable by us, cron files user/system, systemd timers + units writable, rc.local/profile.d scripts, kernel + distro version vs known CVE era (report only), package counts (upgradable via zypper/apt --dry-run if safe), exposes cleartext config greps (passw|secret|token in /etc /srv /var/www), .ssh private keys anywhere, NFS exports + no_root_squash, mounted shares, umask values, /etc/ssh/sshd_config harden-check (PermitRootLogin, PasswordAuthorization, X11, MaxAuthTries), firewall status consistency with required ports, per-user bash history depth, any HTTP service banner/version on 80/3306/502 listening interfaces.
- **`linux-backdoor-hunter.sh`** — authorized_keys across all homes (with fingerprints), root cron entries + at jobs, systemd units added/modified recently (mtime), ExecStart paths outside /usr/bin, LD_PRELOAD, /etc/ld.so.preload, recent mtimes under /etc and /usr/bin, processes running deleted binaries (via /proc), outbound established connections with owning user, history files, shell rc injections (append logs, base64 blobs), /dev/shm droppers, SSH AuthorizedKeysFile alternate paths, listening sockets owned by accounts that never appear in passwd logically, systemd socket activations, swapped sshd binary path. Pairs with linuxinfo.sh --save outputs.

### Hardening checklists (enumerate -> print recommended fix commands, NOT applied automatically)
- **`win-hardening-check.ps1`** — prints a hardening scorecard per box: password/lockout policy gaps, LLMNR/mDNS/SSDP still on, SMBv1 on, RDP NLA off, auto logins, stale admin group members, service account defaults, Defender exclusions, unquoted service paths, legacy protocols, NTLMv1 (via LmCompatibility), 32-bit legacy bins — each with the exact one-line command to fix (commented as copy/paste lines), grouped "safe day-one" vs "confirm-with-team".
- **`linux-hardening-check.sh`** — same idea: shells in passwd, sshd knobs, umask, cron perms, world-write surface, kernel-sysctl values, suggestions grouped the same.
- **`svc-watch`** — uptime logger for required ports (Blue evidence): loops over the box's required ports (from REQUIRED-PORTS.md), logs `timestamp|port|up/down` every 60s + immediate Discord-friendly alert line in the log file if anything went down, systemd timer + schtasks generator included.

### ICS / OT
- **`ics-monitor` (bash + PS)** — read-only passive watch of 502/20000/1883/8080/8088: TCP flags, per-foreign-port connection counters, + periodic tcpdump ring buffer for pcap capture sized for the comp weekend; Modbus register/coil read-only dump vs documented normal thresholds (ESD, wellhead pressure/floor/temp), via the OpenPLC index/modbus register list endpoint. No writes/commands to PLCs anywhere.
- **`ab-evidence` (bash + PS)** — read-only assume-breach evidence pack builder: log source enable check, ssh-involved auth lines, capture of all Windows Security/user + System/App events of interest, auditd enablement (documented, from official recommendation only), full netstat/-p lsof sweep, service unit dumps, registry Run keys, ICS historian DB table list/careers read-only; writes everything into structured pack + a README of what was gathered and why.

### Documentation / score support
- **`secdoc-gen`** — merges snapshot/wininfo/linuxinfo CSVs into the comp Security Documentation Template structure (asset inventory + network diagram table + known-vulnerability list starter rows from the win-vulnscan/linux-vulnscan findings).
- **`cred-sheet` helpers** — after rotate-creds runs: quick import of the output sheets into a single team password vault file (never store plaintext in a public place; last-resort'). Just centralizing.

Order of build (suggested): win-vulnscan.ps1 & linux-vulnscan.sh green first, use, web-vulnscan, backdoor-hunters, supporting hardening-checks and ML `svc-watch` for uptime, ics/ab packs before comp weekend.
