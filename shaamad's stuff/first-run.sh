#!/bin/sh
# @d_tranman/Nigel Gerald/Nigerald
# KaliPatriot | TTU CCDC | Landon Byrge
# shaamad was also here a little
# v2: dynamic webroot discovery + backup, openSUSE fixes (zypper flags, php-fpm
#     names, netcat-openbsd), rustnet + binsider via GitHub releases,
#     shell-file forensics backup.
# NOTE: php.ini hardening intentionally REMOVED in v2 -- the risky flags
#       (cookie_secure/max_execution_time/allow_url_fopen) break WP admin and
#       the historian fetch on this HTTP-only scored box, and web exposure
#       (expose_php, display_errors) is now covered by the web-recon findings
#       feeding the SecDoc instead.

if [ -z "$BCK" ]; then
    BCK="/tmp/"
fi

BCK=$BCK/initial

mkdir -p $BCK

sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
setenforce 0 2>/dev/null

RHEL(){
    yum check-update -y >/dev/null

    for i in "sudo net-tools iptables iproute sed curl wget tmux htop nmap ufw rkhunter whowatch bash gcc gzip make procps socat tar auditd rsyslog tcpdump unhide strace"; do
        yum install -y $i
    done

    echo "Removing netcat..."
    yum remove -y netcat
}

SUSE(){
    # zypper: -n = non-interactive (its -y is not a valid install flag)
    zypper refresh >/dev/null 2>&1

    for i in "sudo net-tools iptables iproute2 sed curl wget tmux htop nmap rkhunter ufw whowatch bash gcc gzip make procps socat tar auditd rsyslog tcpdump unhide strace"; do
        zypper -n install $i || true
    done

    echo "Removing netcat..."
    # openSUSE ships netcat-openbsd, not "netcat"
    zypper -n remove netcat netcat-openbsd 2>/dev/null || true
}

DEBIAN(){
    apt-get -qq update >/dev/null

    for i in "sudo net-tools iptables iproute2 sed curl wget bash gcc debsums tmux htop nmap ufw rkhunter whowatch gzip make procps socat tar auditd rsyslog tcpdump unhide strace"; do
        apt-get -qq install $i -y
    done

    echo "Removing netcat..."
    apt-get -qq purge netcat* -y
}

UBUNTU(){
    DEBIAN
}

ALPINE(){
    echo "http://mirrors.ocf.berkeley.edu/alpine/v3.16/community" >> /etc/apk/repositories
    apk update >/dev/null
    for i in "sudo iproute2 net-tools curl wget bash iptables util-linux-misc gcc ufw tmux htop nmap rkhunter whowatch gzip make procps socat tar tcpdump audit rsyslog"; do
        apk add $i
    done

    echo "Removing netcat..."
    apk del netcat-openbsd
}

SLACK(){
    slapt-get --update


    for i in "net-tools iptables iproute2 sed curl wget bash gcc tmux htop nmap ufw rkhunter whowatch gzip make procps socat tar tcpdump auditd rsyslog"; do
        slapt-get --install $i
    done

    echo "Removing netcat..."
    slapt-get --remove netcat
}

ARCH(){
    pacman -Syu --noconfirm >/dev/null

    for i in "sudo net-tools iptables iproute2 sed curl wget bash tmux htop ufw nmap rkhunter whowatch gcc gzip make procps socat tar tcpdump auditd rsyslog"; do
        pacman -S --noconfirm $i
    done

    echo "Removing netcat..."
    pacman -Rns --noconfirm netcat openbsd-netcat gnu-netcat
}

BSD(){
    pkg update -f >/dev/null
    for i in "sudo bash net-tools iproute2 sed curl wget bash tmux htop nmap ufw rkhunter whowatch gcc gzip make procps socat tar tcpdump auditd rsyslog firewall"; do
        pkg install -y $i || pkg install $i
    done

    echo "Removing netcat..."
    pkg delete -y netcat
}

if command -v yum >/dev/null ; then
  RHEL
elif command -v zypper >/dev/null ; then
  SUSE
elif command -v apt-get >/dev/null ; then
  if $( cat /etc/os-release | grep -qi Ubuntu ); then
      UBUNTU
  else
      DEBIAN
  fi
elif command -v apk >/dev/null ; then
  ALPINE
elif command -v slapt-get >/dev/null || ( cat /etc/os-release | grep -i slackware ) ; then
  SLACK
elif command -v pacman >/dev/null ; then
  ARCH
elif command -v pkg >/dev/null || command -v pkg_info >/dev/null; then
    BSD
fi

# ---- rust tools (not distro packages): rustnet + binsider from GitHub releases
# rustnet  = live per-process network monitor TUI (musl static = works on SUSE)
# binsider = TUI binary analyzer: ELF layout, strings, strace-style dynamic view
install_rust_tool(){
    name="$1"; repo="$2"; tmpl="$3"
    command -v "$name" >/dev/null 2>&1 && { echo "[*] $name already present"; return 0; }
    command -v curl >/dev/null 2>&1 || { echo "[!] curl missing, cannot fetch $name"; return 1; }
    ver=$(curl -s "https://api.github.com/repos/$repo/releases/latest" \
        | sed -n 's/.*"tag_name": *"v\([0-9.]*\)".*/\1/p' | head -1)
    [ -z "$ver" ] && { echo "[!] could not resolve latest $name version"; return 1; }
    url="https://github.com/$repo/releases/download/v$ver/$(echo "$tmpl" | sed "s/\$VER/$ver/g")"
    tmp=$(mktemp -d)
    echo "[*] installing $name $ver ..."
    curl -sSL "$url" -o "$tmp/$name.tar.gz" \
        && tar -xzf "$tmp/$name.tar.gz" -C "$tmp" || { echo "[!] $name download/extract failed"; rm -rf "$tmp"; return 1; }
    bin=$(find "$tmp" -type f -name "$name" | head -1)
    [ -z "$bin" ] && { echo "[!] $name binary not found in archive"; rm -rf "$tmp"; return 1; }
    mv "$bin" /usr/local/bin/$name && chmod +x /usr/local/bin/$name
    # packet capture caps (harmless no-op for tools that don't need them)
    setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /usr/local/bin/$name 2>/dev/null || true
    rm -rf "$tmp"
    echo "[+] $name installed -> /usr/local/bin/$name"
}

install_rust_tool rustnet  domcyrus/rustnet 'rustnet-v$VER-x86_64-unknown-linux-musl.tar.gz'
install_rust_tool binsider orhun/binsider  'binsider-$VER-x86_64-unknown-linux-gnu.tar.gz'

# ---- webroot discovery: common paths + config-declared roots + app files ----
# Collect candidates, then keep only top-most dirs (no parent+child duplicates)
WEBROOTS=$( {
    ls -d /var/www /var/www/html /var/www/vhosts /srv/www /srv/www/htdocs \
          /srv/www/vhosts /usr/share/nginx/html /opt/lampp/htdocs \
          /var/htdocs /home/*/public_html 2>/dev/null
    # apache DocumentRoot / nginx root directives
    grep -rhsE '^[[:space:]]*DocumentRoot[[:space:]]+' /etc/apache2 /etc/httpd /etc/http 2>/dev/null | awk '{print $2}' | tr -d '"'
    grep -rhsE '^[[:space:]]*root[[:space:]]+/' /etc/nginx/nginx.conf /etc/nginx/sites-enabled /etc/nginx/conf.d 2>/dev/null | awk '{print $2}' | tr -d ';'
    # any dir holding an app config / entry file (WordPress etc.), capped
    find / -xdev -maxdepth 6 \( -name wp-config.php -o -name wp-load.php \) 2>/dev/null | xargs -r -n1 dirname
} | sort -u | awk '{n[NR]=$0}
    END { for (i=1;i<=NR;i++) { p=1
        for (j=1;j<=NR;j++) if (j!=i && n[j]!="" && index(n[i]"/", n[j]"/")==1 && length(n[j])<length(n[i])) p=0
        if (p && n[i]!="") print n[i] } }' )

mkdir -p $BCK/webroots
echo "$WEBROOTS" > $BCK/webroots.txt
echo "[*] webroots found:"; echo "$WEBROOTS" | sed 's/^/    /'
for w in $WEBROOTS; do
    tgt="$BCK/webroots/$(echo "$w" | sed 's#^/##; s#/#_#g')"
    cp -r "$w" "$tgt" 2>/dev/null
done

# backup /etc/passwd
mkdir -p $BCK
cp /etc/passwd $BCK/users
cp /etc/group $BCK/groups
cp -r /etc/ $BCK/etcback
cp -r /bin/ $BCK/binback
cp -r /root/ $BCK/root

# shell files per user (rc implants + history are evidence gold)
mkdir -p $BCK/homes
for h in /root /home/*; do
    [ -d "$h" ] || continue
    mkdir -p "$BCK/homes/$h"
    for f in .bashrc .profile .bash_profile .bash_logout .bash_history .ssh; do
        [ -e "$h/$f" ] && cp -r "$h/$f" "$BCK/homes/$h/" 2>/dev/null
    done
done

# check our ports
if command -v sockstat >/dev/null ; then
    LIST_CMD="sockstat -l"
    ESTB_CMD="sockstat -46c"
elif command -v netstat >/dev/null ; then
    LIST_CMD="netstat -tulpn"
    ESTB_CMD="netstat -tupwn"
elif command -v ss >/dev/null ; then
    LIST_CMD="ss -blunt -p"
    ESTB_CMD="ss -buntp"
else
    echo "No netstat, sockstat or ss found"
    LIST_CMD="echo 'No netstat, sockstat or ss found'"
    ESTB_CMD="echo 'No netstat, sockstat or ss found'"
fi

$LIST_CMD > $BCK/listen
$ESTB_CMD > $BCK/estab

chmod 640 -R /root/

docker ps >> $BCK/docker

# pam
mkdir -p $BCK/pam/conf
mkdir -p $BCK/pam/pam_libraries
cp -R /etc/pam.d/ $BCK/pam/conf/
MOD=$(find /lib/ /lib64/ /lib32/ /usr/lib/ /usr/lib64/ /usr/lib32/ -name "pam_unix.so" 2>/dev/null)
for m in $MOD; do
    moddir=$(dirname $m)
    mkdir -p $BCK/pam/pam_libraries/$moddir
    cp $moddir/pam*.so $BCK/pam/pam_libraries/$moddir
done

# ---- sshd hardening --------------------------------------------------------
sys=$(command -v service || command -v systemctl)
FILE=/etc/ssh/sshd_config
if [ -f "$FILE" ]; then
    SED="sed -i''"
    if sed --version >/dev/null 2>&1; then
        SED="sed -i"
    fi
    cp "$FILE" "$BCK/sshd_config.prehardening"
    $SED 's/^AllowTcpForwarding/# AllowTcpForwarding/' "$FILE"
    echo 'AllowTcpForwarding no' >> "$FILE"
    $SED 's/^X11Forwarding/# X11Forwarding/' "$FILE"
    echo 'X11Forwarding no' >> "$FILE"
    $SED 's/^PermitRootLogin/# PermitRootLogin/' "$FILE"
    echo 'PermitRootLogin no' >> "$FILE"
    $SED 's/^PermitEmptyPasswords/# PermitEmptyPasswords/' "$FILE"
    echo 'PermitEmptyPasswords no' >> "$FILE"

    if [ ! -z "$NOPUB" ]; then
        $SED 's/^PubkeyAuthentication/# PubkeyAuthentication/' "$FILE"
        echo 'PubkeyAuthentication no' >> "$FILE"
    fi
    if [ ! -z "$AUTHKEY" ]; then
        $SED 's/^AuthorizedKeysFile/# AuthorizedKeysFile/' "$FILE"
        echo "AuthorizedKeysFile $AUTHKEY" >> "$FILE"
    fi
    if [ ! -z "$ROOTPUB" ]; then
        $SED 's/^PubkeyAuthentication/# PubkeyAuthentication/' "$FILE"
        echo 'PubkeyAuthentication no' >> "$FILE"
        echo 'Match User root' >> "$FILE"
        echo '    PubkeyAuthentication yes' >> "$FILE"
    fi
else
    echo "Could not find sshd config"
fi

# ---- service restarts (openSUSE names: apache2, ssh, php-fpm) --------------
if [ -z $sys ]; then
  if [ -f "/etc/rc.d/sshd" ]; then
    RC="/etc/rc.d/sshd"
  else
    RC="/etc/rc.d/rc.sshd"
  fi
  $RC restart
else
  $sys restart ssh || $sys ssh restart || $sys restart sshd || $sys sshd restart
fi

if [ -d /etc/nginx ]; then
    $sys nginx restart || $sys restart nginx
    echo nginx restarted
fi

if [ -d /etc/apache2 ]; then
    $sys apache2 restart || $sys restart apache2
    echo apache2 restarted
fi

if [ -d /etc/httpd ]; then
    $sys httpd restart || $sys restart httpd
    echo httpd restarted
fi

if [ -d /etc/lighttpd ]; then
    $sys lighttpd restart || $sys restart lighttpd
    echo lighttpd restarted
fi

if [ -d /etc/ssh ]; then
    $sys ssh restart || $sys restart ssh || $sys restart sshd || $sys sshd restart
    echo ssh restarted
fi

file=$(find /etc -maxdepth 3 -type f -name 'php-fpm*' -print -quit)
if [ -d /etc/php/*/fpm ] || [ -n "$file" ]; then
    $sys php-fpm restart || $sys restart php-fpm 2>/dev/null \
        || systemctl restart 'php*fpm*' 2>/dev/null
    echo php-fpm restarted
fi

# ---- tooling: pspy + linpeas (drops into the script's own directory, i.e.
#      the shaamad's stuff checkout; falls back if that dir isn't writable) ---
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)
TOOLDIR="$SCRIPT_DIR"
if [ -z "$TOOLDIR" ] || [ ! -w "$TOOLDIR" ]; then
    TOOLDIR="/usr/local/share/first-run-tools"
    echo "[i] script dir not writable — falling back to $TOOLDIR"
fi
mkdir -p "$TOOLDIR"
cd "$TOOLDIR" || exit 1
wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64
wget -q https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
echo "[+] pspy64 + linpeas.sh -> $TOOLDIR/"

# ---- perms -----------------------------------------------------------------
chmod 644 /etc/passwd
chmod 600 /etc/shadow

# ---- forensics capture ------------------------------------------------------
find / -perm 4000 2>/dev/null >> $BCK/suid
ps aux >> $BCK/processes
cat /etc/crontab >> $BCK/cron1
ls -altr /var/spool/cron/ >> $BCK/cron2
crontab -l >> $BCK/cron3

echo
echo "[*] first-run complete. backup at $BCK:"
du -sh $BCK 2>/dev/null
ls $BCK


