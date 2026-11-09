#!/usr/bin/env bash
# ==============================================================================
# install.sh — one-shot CPTC VM bootstrap (Kali / Debian-based)
#
# Usage:
#   sudo ./install.sh              # full install (~30-60 min, big downloads)
#   sudo ./install.sh --dry-run    # resolve + report only, installs nothing
#   sudo ./install.sh --no-msf     # skip metasploit (policy choice)
#   sudo ./install.sh --hardening  # only the defensive/hardening batch
#
# - Every apt package is installed independently: one bad name never kills the run.
#   Failures are logged to ./install-fails.txt
# - GitHub-only binaries (linpeas, pspy, chisel, ligolo, SharpHound...) land in
#   <user-home>/tools/ (+ tools/windows, tools/powershell)
# - pip tools (git-dumper, bloodhound-python) go through pipx
# - Wordlists: seclists + wordlists packages (rockyou included)
# ==============================================================================
set -u
DRY=0; NO_MSF=0; ONLY_HARDENING=0
for a in "$@"; do
    case "$a" in
        --dry-run)    DRY=1 ;;
        --no-msf)     NO_MSF=1 ;;
        --hardening)  ONLY_HARDENING=1 ;;
        --help|-h)
            grep '^#' "$0" | head -18 | tail -16; exit 0 ;;
        *) echo "unknown flag: $a"; exit 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "[!] run me as root: sudo ./install.sh"; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

# Where do shared tools live? (as root, install into the sudo-ing user's home)
if [ -n "${SUDO_USER:-}" ]; then
    HOME_DIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    HOME_DIR="$HOME"
fi
TOOLSBIN="$HOME_DIR/tools"
mkdir -p "$TOOLSBIN/windows" "$TOOLSBIN/powershell"
LOG=/tmp/install-cptc.log
: > "$LOG"
if [ $DRY = 1 ]; then
    FAILS=/dev/.null
else
    FAILS="$(pwd)/install-fails.txt"; : > "$FAILS"
fi

grp() { echo -e "\n########## $1 ##########"; }

# --- apt section ---------------------------------------------------------------
apt_install_one() {
    local p="$1"
    if dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q 'install ok installed'; then
        echo "  [=] $p (already there)"; return 0
    fi
    echo "  [+] $p"
    [ $DRY = 1 ] && return 0
    apt-get install -y -qq "$p" >>"$LOG" 2>&1 \
        && return 0 || { echo "$p" >> "$FAILS"; echo "  [-] FAILED: $p (see $LOG)"; return 1; }
}

group_apt() {
    echo "[*] apt batch: $1"
    for p in $2; do apt_install_one "$p"; done
}

if [ $DRY = 0 ] && ! has apt-get; then
    echo "[!] apt-get not found — this installer assumes Debian/Kali"; exit 1
fi

# --- the big lists -------------------------------------------------------------
APT_CORE="tmux nano curl wget tar gzip bzip2 xz-utils sed gawk gcc make htop git
          unzip jq less python3-pip pipx net-tools iproute2 traceroute dnsutils lsof"

APT_NET="nmap masscan rustscan arp-scan nbtscan enum4linux enum4linux-ng
         smbclient smbmap netexec python3-impacket impacket-scripts
         responder evil-winrm whowatch socat ncat netcat-openbsd
         proxychains4 sshuttle iptables ufw tcpdump tshark wireshark"

APT_WEB="gobuster ffuf feroxbuster nuclei sqlmap whatweb dirsearch wafw00f
         arjun dalfox zaproxy burpsuite mitmproxy wpscan seclists exploitdb"

APT_PW="hydra john john-data hashcat cewl wordlists"

APT_AD="neo4j postgresql bloodhound"

APT_PRIVE="python3-pwntools"
[ $NO_MSF = 0 ] && APT_PRIVE="$APT_PRIVE metasploit-framework"

APT_HARDENING="auditd rsyslog rkhunter debsums unhide strace procps chkrootkit
               fail2ban lynis logwatch sysstat"

APT_DESKTOP="xrdp xfce4 xfce4-terminal"

if [ $ONLY_HARDENING = 1 ]; then
    group_apt "hardening/defense" "$APT_HARDENING"
    echo "[+] hardening batch done. Next: enable services (auditd, ufw, fail2ban)."
    exit 0
fi

{
echo "==== apt update ===="
[ $DRY = 0 ] && apt-get update -qq
} >>"$LOG" 2>&1

group_apt "core/shell"            "$APT_CORE"
group_apt "network/enum"          "$APT_NET"
group_apt "web"                   "$APT_WEB"
group_apt "passwords"             "$APT_PW"
group_apt "AD/BloodHound backends" "$APT_AD"
group_apt "privesc/exploit"       "$APT_PRIVE"
group_apt "desktop/rdp-in"        "$APT_DESKTOP"
group_apt "hardening/defense"     "$APT_HARDENING"

# --- pipx tools (not in apt) ---------------------------------------------------
grp "pipx tools"
if ! has pipx && [ $DRY = 0 ]; then
    apt-get install -y -qq pipx >>"$LOG" 2>&1
fi
for PYPKG in git-dumper bloodhound-python certipy droopescan; do
    echo "  [+] pipx: $PYPKG"
    [ $DRY = 1 ] && continue
    (sudo -u "${SUDO_USER:-$USER}" bash -lc "userbase=\$(dirname \"\$HOME/.local\"); pipx ensurepath >/dev/null 2>&1; pipx install '$PYPKG'" >>"$LOG" 2>&1) \
        || { echo "$PYPKG" >> "$FAILS"; echo "  [-] pipx FAILED: $PYPKG"; }
done

# --- GitHub-release binaries ----------------------------------------------------
grp "GitHub binaries -> $TOOLSBIN"

# resolve the newest download URL from a repo's latest release, matching a pattern
gh_latest() { # repo  asset-regex
    curl -fsSL --max-time 20 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null \
        | grep -oE "https://[^\"]*/releases/download/[^\"]*" \
        | grep -E "$2" | head -1
}
dl() { # url  dest-filename
    local url="$1" dst="$TOOLSBIN/$2"
    [ -n "$url" ] || { echo "$2 (url not resolved)" >> "$FAILS"; echo "  [-] no URL for $2"; return 1; }
    echo "  [+] $2"
    [ $DRY = 1 ] && return 0
    curl -fSL --max-time 300 -o "$dst" "$url" >>"$LOG" 2>&1 \
        && chmod +x "$dst" || { echo "$2" >> "$FAILS"; echo "  [-] FAILED download: $2"; }
}

U="peass-ng/PEASS-ng"
dl "$(gh_latest "$U" 'linpeas\.sh$')"  "linpeas.sh"
dl "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "linux-exploit-suggester.sh"
dl "$(gh_latest 'diego-treitos/linux-smart-enumeration' 'lse\.sh$')" "lse.sh"
dl "$(gh_latest 'DominicBreuker/pspy' '/pspy64$')" "pspy64"
dl "$(gh_latest 'ropnop/kerbrute' 'linux_amd64$')" "kerbrute"
dl "$(gh_latest 'jpillora/chisel' 'linux_amd64\.gz$')" "chisel_linux_amd64.gz"
if [ $DRY = 0 ] && [ -f "$TOOLSBIN/chisel_linux_amd64.gz" ]; then
    gunzip -f "$TOOLSBIN/chisel_linux_amd64.gz" && mv "$TOOLSBIN/chisel_linux_amd64" "$TOOLSBIN/chisel" 2>/dev/null
    chmod +x "$TOOLSBIN/chisel" 2>/dev/null
fi
# ligolo-ng: agent (runs on target) + proxy (runs on our box) — separate tarballs
dl "$(gh_latest 'nicocha30/ligolo-ng' 'agent.*linux_amd64\.tar\.gz$')" "ligolo-agent.tar.gz"
dl "$(gh_latest 'nicocha30/ligolo-ng' 'proxy.*linux_amd64\.tar\.gz$')" "ligolo-proxy.tar.gz"
if [ $DRY = 0 ] && [ -f "$TOOLSBIN/ligolo-agent.tar.gz" ]; then
    mkdir -p "$TOOLSBIN/ligolo-agent" "$TOOLSBIN/ligolo-proxy"
    tar -xzf "$TOOLSBIN/ligolo-agent.tar.gz" -C "$TOOLSBIN/ligolo-agent" \
        && cp -f "$TOOLSBIN/ligolo-agent/agent" "$TOOLSBIN/" 2>/dev/null
    tar -xzf "$TOOLSBIN/ligolo-proxy.tar.gz" -C "$TOOLSBIN/ligolo-proxy" \
        && cp -f "$TOOLSBIN/ligolo-proxy/proxy" "$TOOLSBIN/" 2>/dev/null
    chmod +x "$TOOLSBIN/agent" "$TOOLSBIN/proxy" 2>/dev/null
fi

# Windows-side binaries (for boxes we land on)
dl "$(gh_latest "$U" 'winPEASx64\.exe$')" "windows/winPEASx64.exe"
# SharpHound: release asset is SharpHound_vX.Y.Z_windows_x64.zip (non-debug build)
dl "$(gh_latest 'SpecterOps/SharpHound' 'SharpHound_.*_windows_x64\.(zip|exe)$')" "windows/SharpHound.zip"
dl "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" \
   "powershell/PowerView.ps1"

# --- config jobs (echo, not automatable safely) --------------------------------
grp "manual config reminders"
cat <<EOF
  1) neo4j (BloodHound):    sudo neo4j-admin dbms set-initial-password 'changeme-long'
                            sudo systemctl enable --now neo4j;  then run bloodhound
  2) xrdp (rdp INTO kali):  sudo systemctl enable --now xrdp
                            Windows box RDP -> this VM's IP :3389
  3) rockyou:               /usr/share/wordlists/rockyou.txt should exist; else
                            zcat /usr/share/wordlists/rockyou.txt.tar.gz > path
  4) wave your PATH:        echo 'export \$PATH=\$PATH:$TOOLSBIN' >> ~/.zshrc (or .bashrc)
  5) burp+zap:              both community builds installed; license as required
EOF

echo ""
if [ $DRY = 1 ]; then
    echo "[dry-run] nothing was installed. Resolve results printed above."
else
    if [ -s "$FAILS" ]; then
        echo "[!] finished, but these FAILED (rerun or apt them by hand):"; cat "$FAILS"
    else
        echo "[+] install complete — no failures."
    fi
fi
