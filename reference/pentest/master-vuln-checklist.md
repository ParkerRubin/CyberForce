# Master Vuln Hunt Checklist — CPTC "everything a person could look for"
Built 2026-11-03 from: our seed list + UF prewrites vocabulary + UCI free-vulns + CPTC10 globals corpus.
**Philosophy from real CPTC reports:** not every finding is big. Small, well-evidenced findings
(default creds, info disclosure, cleartext anything) stack up faster than one deep exploit.
Rule: **found → evidence screenshot → one-liner in findings file → keep hunting.** Never park.

## A. Web app (run first, wins fastest)
- [ ] SQL injection (login/forms/search/URL params — `' OR 1=1--`, sqlmap the interesting params)
- [ ] XSS (reflected in search/error pages, stored in profile/comment fields)
- [ ] IDOR (change IDs in URLs/API for other users' data — `?id=`, `/api/user/123`)
- [ ] LFI/RFI (`?page=`, `?file=`, `../../../../etc/passwd`)
- [ ] Unauthenticated API endpoints (find routes in JS, call them logged-out)
- [ ] Hardcoded secrets in JS/HTML source (API keys, tokens, internal URLs)
- [ ] Missing SRI/CSP/security headers (Small finding, free points)
- [ ] Admin panel: client-side auth only? default creds? reachable unauthenticated?
- [ ] CSRF on state-changing forms
- [ ] SSRF in URL/image-fetch fields
- [ ] Broken access control (admin functions as normal user; horizontal + vertical)
- [ ] phpinfo()/debug pages, `.git/` dumps, backup files (`.bak`, `.old`, `~`)
- [ ] Verbose/error disclosure, version banners (WebInfoDisclosure)
- [ ] Git dumps → git-dumper → source review → more creds
- [ ] File upload: unrestricted type → webshell
- [ ] Command injection in any "ping/lookup/convert" feature

## B. Credentials & secrets (the highest points-per-minute lane)
- [ ] Cleartext passwords in configs, scripts, source, comments, wikis, shares
- [ ] Default creds (admin:admin, printer/web-app/db defaults — DefaultCredService prewrite)
- [ ] Non-rotated/reused passwords (same cred works across hosts/services = a FINDING)
- [ ] Private keys on shares/web/git (privatekeys prewrite) — whose? where else valid?
- [ ] Password in command lines (`ps aux`, scripts, history)
- [ ] Hardcoded DB creds → reused elsewhere?
- [ ] Password policy findings (weakDomainPassPolicy) — length/complexity/lockout from spraying evidence
- [ ] Creds in user shell history (`~/.bash_history`, PSReadLine `ConsoleHost_history.txt`)
- [ ] Secrets in environment variables (`env`, systemd units, docker inspect)

## C. Linux host (after landing — run local-linux-enum.sh first)
- [ ] SUID/SGID binaries (find / -perm -4000) — sudoers/passwd/shadow/suid prewrites
- [ ] /etc/sudoers + sudo -l misconfigs (NOPASSWD, wildcards, GTFOBins)
- [ ] Writable /etc/passwd (add root-uid line) or shadow readable
- [ ] Cron jobs + writable cron scripts/scripts' dirs
- [ ] Users/groups misconfig (UID 0 non-root accounts, dormant humans still active)
- [ ] World-readable sensitive files (/home perms, /var/backups, /var/mail)
- [ ] .ssh dirs: authorized_keys reuse, id_rsa lying around
- [ ] NFS no_root_squash exports; writable shares
- [ ] Service creds in /etc (mysql my.cnf, samba smbusers, etc.)
- [ ] Kernel exploit check (uname vs. known CVEs — OverlayFS/DirtyPipe era)
- [ ] noAntivirus prewrite (missing EDR/AV = a finding)
- [ ] Firewall disabled/absent (winFirewall prewrite, ufw/iptables off)

## D. Windows / AD host or domain
- [ ] AS-REP roastable accounts (no preauth)
- [ ] Kerberoastable SPN services
- [ ] SMB signing not required (relay risk) / anonymous share listing (OpenSMBShare)
- [ ] Open shares: IT/backup/user-profile shares readable (loot: docs, scripts, creds)
- [ ] NTLMv1 allowed (NTLMv1 prewrite — crackable, downgrade attacks)
- [ ] GPP cpassword in SYSVOL (once creds allow read)
- [ ] LAPS missing/not applied → local admin reuse
- [ ] Password-not-required / never-expires accounts
- [ ] Domain admins logged into workstations (creds in memory)
- [ ] Unconstrained/constrained delegation abuse; RBCD
- [ ] Utilman/sethc backdoors left by prior "admins" (UtilmanBackdoor prewrite)
- [ ] Missing patches by service version (OutdatedService) — banner evidence suffices
- [ ] Zerologon (NetLogonEnabled prewrite) if DC vulnerable
- [ ] Guest account enabled; default local admin behavior

## E. Data & dumps (the "any dump" lane — highest report value per minute)
- [ ] Any readable database dump (sql dumps, app.db, backup exports)
- [ ] S3/cloud bucket misconfig (public listing, unauth access)
- [ ] PII exposure: customer lists, SSNs, DOBs, addresses, emails
- [ ] HIPAA-shaped data (medical records, insurance, patient IDs) — flag regulatory angle
- [ ] PCI-shaped data (card numbers, expiry) — flag regulatory angle
- [ ] Financial/investor/M&A documents (client-context gold for Butters framing)
- [ ] Mail spools readable; mail server dumps
- [ ] Backups on shares (`.bak`, `dump`, `export`, `tar/zip` anywhere world-readable)

## F. Network & services
- [ ] Anonymous FTP with sensitive content
- [ ] DNS zone transfer allowed (ZoneTransfer prewrite)
- [ ] SNMP default communities (public/private) → full device config
- [ ] SMTP open relay / user enumeration (VRFY)
- [ ] Outdated SSH algorithms/CVEs (OutdatedSSHCVE)
- [ ] LDAP anonymous bind → user/attribute dump
- [ ] Misconfigured proxies/VPNs; split-tunnel leaks
- [ ] Plaintext protocols in production (telnet, ftp, http logins)
- [ ] Service banners leaking versions/architecture (info disclosure)

## G. "Small findings" — PROOF they score (CPTC10 globals, finals team A: 26 findings)

Team A's actual severity spread: **1 Critical, 7 High, 4 Medium, 4 Low, 10 Info/other —
and they were a FINALS team.** The majority of a finalist's report was NOT big exploits.
Their finding types (from the redacted report itself):
- Cleartext password (Critical 9.8 — the single biggest finding was a *password*, not an exploit)
- Admin account exposure · Exchange misconfig (unauthorized mail send) · API endpoint authz
- SMB share file exposure · stored XSS · NTLMv1 allowed · NTLM relay signing gaps
- Missing account lockout · exposed interpreter (GOLASH) · unrestricted file upload
- Missing HTTP security headers · no rate limiting (chatbot) · self-signed/expired cert config
- Outdated/vulnerable service on 10.0.1.6 · platform-wide misconfigs (yyy.chat)
→ **Moral: the cleartext password beat every exploit in their report.** Hunt credentials and
config hygiene FIRST (sections A/B), screenshots always, severity honestly small when small.

## Usage law
1. Triage order: A/B in parallel with F while C/D/E deepen per-host — the [report generator]
   prewrites map 1:1 to most items above (ASREPRoasting, OpenSMBShare, IDOR, LFI, SQLi, suid,
   passwd, shadow, sudoers, privatekeys, rootlogin, noAntivirus, weakDomainPassPolicy, winFirewall,
   NetLogonEnabled, NTLMv1, UtilmanBackdoor, OutdatedSSHCVE, ZoneTransfer, DefaultCredService,
   AdminLeakedCreds, PHPInfo, WebInfoDisclosure, MissingSRI, UnauthAPIendpoint, InsecureAdminPanel,
   ClientSideAdminAuth, BrokenAccessControl, CSRF, XSSInjection, Jellyfin*, WebInfoDisclosure…).
2. Evidence standard: screenshot + affected host(s) + one-line business impact, in the generator.
3. A finding found but not documented = not found. Ten small documented > one big unfinished.
