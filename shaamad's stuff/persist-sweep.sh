#!/bin/bash
# ============================================================
# persist-sweep.sh v3 — NCAE blue-team persistence & exposure sweep
# Target: OpenSUSE Leap 16 scored box (HTTP 80 / MySQL 3306 / SMB 139,445)
# READ-ONLY: reports findings, changes nothing. First run = baseline,
# every later run DIFFS — the point is catching NEW drops (active red team).
# v2 adds what linPEAS misses: package integrity (rpm -V), passwd/shadow
# hash diffs, webroot file-list diff, firewall diff, autostart/user-units,
# udev, kernel modules, PATH-hijack collisions, deleted-but-running,
# outbound C2 view, rc-file tamper patterns, mail-alias pipes.
# v3 adds (from 57-image answer-key census): container/podman abuse,
# attack-tooling package scan, insecure legacy services, password policy,
# MySQL remote-root/SUPER grants, polkit YES rules, motd callbacks,
# systemd sockets baseline, tmpfiles/shadow/cron perms, .env/.bak in webroot,
# extra sshd Ports, odd-username pattern hunt.
#
# Usage:  sudo ./persist-sweep.sh [--quiet] [--log]
#           --quiet : findings only (cron mode)
#           --log   : also write sweep-<timestamp>.log in cwd
#         Exit code = # of CRIT findings (0 = clean).
# ============================================================
set -u
QUIET=0; LOG=0
for a in "$@"; do case "$a" in --quiet) QUIET=1;; --log) LOG=1;; esac; done

STATE=/var/tmp/persist-sweep
mkdir -p "$STATE" 2>/dev/null || { echo "run with sudo"; exit 99; }

CRIT=0; WARN=0
ok()   { [ $QUIET -eq 0 ] && printf '  [ OK ] %s\n' "$1"; }
info() { [ $QUIET -eq 0 ] && printf '  [INFO] %s\n' "$1"; }
warn() { printf '  [WARN] %s\n' "$1"; WARN=$((WARN+1)); }
crit() { printf '  [CRIT] %s\n' "$1"; CRIT=$((CRIT+1)); }
hdr()  { printf '\n== %s ==\n' "$1"; }

basediff() {  # basediff <name> <listing-cmd> [baseline-comment]
  local name=$1 cmd=$2 cur new gone
  cur=$(eval "$cmd" 2>/dev/null | sort)
  if [ ! -s "$STATE/$name" ]; then
    printf '%s\n' "$cur" > "$STATE/$name"
    ok "baseline recorded ($name): $(printf '%s' "$cur" | grep -c .) entries"
  else
    new=$(printf '%s\n' "$cur" | comm -13 "$STATE/$name" - 2>/dev/null)
    [ -n "$new" ] && crit "$name ADDED since baseline: $(echo $new)" \
                 || ok "$name unchanged"
    gone=$(comm -23 "$STATE/$name" <(printf '%s\n' "$cur") 2>/dev/null)
    [ -n "$gone" ] && warn "$name REMOVED since baseline (was that you?): $(echo $gone)"
  fi
}

[ "$(id -u)" -eq 0 ] || echo "[!] not root — several checks blind. sudo me."

# mysql client may live at /opt/mysql/bin/mysql; sudo secure_path hides it
MYSQL=$(command -v mysql 2>/dev/null || true)
[ -z "$MYSQL" ] && [ -x /usr/local/bin/mysql ] && MYSQL=/usr/local/bin/mysql
[ -z "$MYSQL" ] && [ -x /opt/mysql/bin/mysql ] && MYSQL=/opt/mysql/bin/mysql[ $LOG -eq 1 ] && exec > >(tee "sweep-$(date +%Y%m%d-%H%M%S).log") 2>&1
echo "persist-sweep v2 $(date '+%F %T') on $(hostname) — pid $$"

# --- 1. accounts ---------------------------------------------
hdr "accounts"
awk -F: '$3==0{print $1}' /etc/passwd | grep -v '^root$' >/dev/null \
  && crit "UID-0 account besides root: $(awk -F: '$3==0{print $1}' /etc/passwd | tr '\n' ' ')" \
  || ok "only root has UID 0"
basediff passwd "awk -F: '{print \$1\":\"\$3}' /etc/passwd"
basediff shadow-hashes "awk -F: '{print \$1\":\"substr(\$3,1,16)}' /etc/shadow"
info "^ shadow-hashes WARNs = a password CHANGED (could be your rotation)"
OLD=$(awk -F: '/^old\./ && $7 !~ /nologin|false/{print $1}' /etc/passwd)
[ -n "$OLD" ] && warn "old.* accounts still have shells: $(echo $OLD)" || ok "no live old.* shells"
EMPT=$(awk -F: '($2=="" && $1!="root"){print $1}' /etc/shadow 2>/dev/null)
[ -n "$EMPT" ] && crit "EMPTY PASSWORDS: $(echo $EMPT)" || ok "no empty passwords"
grep -q "pam_unix.so nullok" /etc/pam.d/common-password-pc 2>/dev/null \
  && warn "pam nullok allows empty passwords" || ok "pam nullok removed"
basediff group-root "awk -F: '\$1==\"root\"||\$1==\"wheel\"{print \$0}' /etc/group"

# --- 2. package integrity (trojaned binaries) — linPEas NEVER does this
hdr "package integrity (rpm -V core pkgs)"
if command -v rpm >/dev/null; then
  V=$(rpm -V sudo shadow coreutils util-linux openssh openssh-server apache2 samba systemd cronie 2>/dev/null \
      | grep -E '^..5|^......missing' | head -8)
  [ -n "$V" ] && crit "PACKAGE FILE TAMPERED (checksum mismatch):\n$V" || ok "core package files verified"
  info "(5 = content changed, 'missing' = deleted. Review each before replacing.)"
else warn "rpm unavailable — integrity check skipped"; fi

# --- 3. sudo persistence --------------------------------------
hdr "sudoers"
basediff sudoers.d "ls /etc/sudoers.d/"
find /etc/sudoers.d -type f -perm /022 2>/dev/null | grep -q . \
  && crit "world/group-WRITABLE file in /etc/sudoers.d" || ok "sudoers.d perms sane"
grep -rh "NOPASSWD" /etc/sudoers.d/ 2>/dev/null | grep -vq '^#' \
  && warn "NOPASSWD lines in sudoers.d — confirm each is yours" || ok "no stray NOPASSWD"
grep -E '^\s*(@|#)?include' /etc/sudoers 2>/dev/null | grep -v sudoers.d \
  && warn "non-standard include in /etc/sudoers" || ok "no odd sudoers includes"
if [ "$(id -u)" -eq 0 ]; then
  visudo -c >/dev/null 2>&1 || crit "SUDOERS SYNTAX BROKEN (visudo -c to find file/line)"
else
  warn "sudoers syntax not checked (needs root)"
fi

# --- 4. hidden/system-path executables + PATH hijack ----------
hdr "system binaries"
HID=$(find /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin -maxdepth 1 -name ".*" -type f -perm /111 2>/dev/null)
[ -n "$HID" ] && crit "hidden executables: $(echo $HID)" || ok "no hidden executables"
for d in /usr/local/bin /usr/local/sbin; do
  for f in "$d"/*; do
    [ -e "$f" ] || continue
    b=$(basename "$f")
    [ -e "/usr/bin/$b" ] || [ -e "/usr/sbin/$b" ] \
      && crit "PATH HIJACK: $f shadows /usr*/$b (local bin wins PATH order)"
  done
done
ok "hijack scan done"

# --- 5. SUID / capabilities -----------------------------------
hdr "suid/sgid/caps"
basediff suid "find / -xdev -perm /6000 -type f 2>/dev/null"
find / -xdev -perm /6000 -type f -perm /022 2>/dev/null | grep -q . \
  && crit "world/group-WRITABLE SUID binary" || ok "no writable SUID"
command -v getcap >/dev/null && basediff caps "getcap -r / 2>/dev/null"
ls -l /usr/bin/socat1 2>/dev/null | grep -q '^-rws' \
  && crit "socat1 is SUID (rpm -qf /usr/bin/socat1 to attribute)" || ok "socat1 not SUID/absent"

# --- 6. systemd (system + user level) -------------------------
hdr "systemd"
basediff enabled-units "ls /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null"
basediff user-units "find /root/.config/systemd/user /home/*/.config/systemd/user -name '*.service' -o -name '*.timer' 2>/dev/null"
for f in /etc/systemd/system/*.service; do
  [ -e "$f" ] || continue; rpm -qf "$f" >/dev/null 2>&1 || warn "non-package unit: $f"
done
systemctl list-timers --no-legend 2>/dev/null | awk '{print $NF}' | sort -u | while read -r u; do
  bin=$(systemctl show -p ExecStart --value "$u" 2>/dev/null | awk '{print $1}' | head -1)
  [ -n "${bin:-}" ] && [ -x "$bin" ] \
    && [ -n "$(stat -c '%a' "$bin" 2>/dev/null | cut -c2-3 | grep '[2-7]')" ] \
    && crit "timer $u runs WRITABLE binary: $bin ($(stat -c '%a' "$bin"))"
done
[ -s /etc/ld.so.preload ] && crit "/etc/ld.so.preload NON-EMPTY: $(cat /etc/ld.so.preload)" || ok "ld.so.preload empty"
basediff ldso-confd "ls /etc/ld.so.conf.d/ 2>/dev/null"

# --- 7. autostart (XDG) — user session persistence ------------
hdr "xdg autostart"
basediff autostart "find /etc/xdg/autostart /root/.config/autostart /home/*/.config/autostart -name '*.desktop' 2>/dev/null"
for f in /etc/xdg/autostart/*.desktop /root/.config/autostart/*.desktop /home/*/.config/autostart/*.desktop; do
  [ -e "$f" ] || continue; rpm -qf "$f" >/dev/null 2>&1 || warn "non-package autostart: $f"
done
ok "autostart ownership checked"

# --- 8. cron / at / udev / modules / boot ---------------------
hdr "schedulers & boot"
basediff cron-d "ls /etc/cron.d/ 2>/dev/null"
basediff cron-spool "ls /var/spool/cron/tabs/ /var/spool/cron/crontabs/ 2>/dev/null"
atq 2>/dev/null | grep -q . && warn "pending at jobs: $(atq | head -3)" || ok "no at jobs"
basediff udev "ls /etc/udev/rules.d/ 2>/dev/null"
for f in /etc/udev/rules.d/*; do [ -e "$f" ] || continue; rpm -qf "$f" >/dev/null 2>&1 || warn "non-package udev rule: $f"; done
basediff kmods "lsmod | awk 'NR>1{print \$1}'"
basediff modules-load "ls /etc/modules-load.d/ 2>/dev/null"
[ -s /etc/init.d/boot.local ] && warn "boot.local content: $(grep -vE '^\s*#|^\s*$' /etc/init.d/boot.local | head -3)"
[ -s /etc/rc.local ] && warn "rc.local content: $(grep -vE '^\s*#|^\s*$' /etc/rc.local | head -3)"
ok "boot-path scan done"

# --- 9. rc-file tamper patterns (not diffable — pattern hunt) --
hdr "rc files (pattern hunt)"
RCFILES=$(ls /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null)
HITS=$(grep -lE '(/dev/tcp/|base64 +(-d|--decode)|curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|nc +-[el]|nohup .*&|/dev/shm/)' $RCFILES 2>/dev/null)
[ -n "$HITS" ] && crit "rc file with shell/callback pattern: $(echo $HITS)" || ok "no rc tamper patterns"
basediff rc-hashes "md5sum $RCFILES 2>/dev/null | awk '{print \$1}'"

# --- 10. SSH ---------------------------------------------------
hdr "ssh"
basediff authkeys "find /root /home -name authorized_keys -exec stat -c '%Y %n' {} + 2>/dev/null"
AKF=$(sshd -T 2>/dev/null | awk -F= '/^authorizedkeysfile/{print $2}')
[ -n "$AKF" ] && [ "$AKF" != ".ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/.keys" ] 2>/dev/null \
  && warn "custom AuthorizedKeysFile: $AKF — sweep that path too"
[ "$AKF" != ".ssh/authorized_keys .ssh/authorized_keys2" ] 2>/dev/null \
  && [ -n "$AKF" ] && info "AuthorizedKeysFile = $AKF"
for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -e "$k" ] || continue
  stat -c '%a' "$k" | grep -q '^600$' || warn "$k perms not 600"
  grep -q '^command=' "$k" && warn "$k has forced-command key (inspect!)"
done
sshd -T 2>/dev/null | grep -qi 'permitrootlogin no' || warn "PermitRootLogin not 'no'"

# --- 11. network ------------------------------------------------
hdr "listening ports (expected: 22 80 139 445 3306 33060, lo:25)"
ss -H -tlnp 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | while read -r p; do
  case "$p" in 22|80|139|445|3306|33060|25) ;; *) warn "unexpected listener: $p";; esac
done
systemctl is-active rsyncd >/dev/null 2>&1 \
  && crit "rsyncd ACTIVE (not scored; /etc module = shadow exfil)" || ok "rsyncd down"
info "outbound established (possible C2 view):"
ss -Htnp state established 2>/dev/null | grep -vE '127\.0\.0\.1|::1' | head -5 | while read -r l; do info "  $l"; done
basediff firewall "firewall-cmd --list-all 2>/dev/null"
info "^ firewall diff = someone (you?) changed the rules"
basediff resolv-hash "md5sum /etc/resolv.conf 2>/dev/null | awk '{print \$1}'"
ip -br link | grep -qvE '^(lo|eth0|sit0) ' && warn "unexpected network interface: $(ip -br link | grep -vE '^(lo|eth0|sit0) ')" || ok "no rogue interfaces"

# --- 12. samba --------------------------------------------------
hdr "samba"
grep -qE 'guest ok *= *yes' /etc/samba/smb.conf && warn "guest ok=yes" || ok "no guest shares"
grep -qE 'force user *= *root' /etc/samba/smb.conf && crit "force user=root share" || ok "no root-forced shares"
grep -qE '0777' /etc/samba/smb.conf && warn "0777 masks present" || ok "masks sane"
grep -qE 'wide links *= *yes' /etc/samba/smb.conf && warn "wide links enabled" || ok "wide links off"
testparm -s >/dev/null 2>&1 || warn "smb.conf syntax problem (testparm)"

# --- 13. webroot ------------------------------------------------
hdr "webroot"
WW=$(find /srv/www/vhosts /var/www/html -type f -perm /022 2>/dev/null | head -4)
[ -n "$WW" ] && crit "world/group-WRITABLE web files: $(echo $WW ...)" || ok "webroot not writable"
basediff webroot-files "find /srv/www/vhosts /var/www/html -type f 2>/dev/null"
info "^ new file appearing in webroot = likely webshell drop"
UP=$(find /srv/www/vhosts /var/www/html -type f -path '*/uploads/*' -name '*.php' 2>/dev/null | head -5)
# (real uploads dirs only — a plugin file merely NAMED uploads.php is not this class)
[ -n "$UP" ] && crit "PHP inside uploads dir (classic webshell spot): $(echo $UP)" || ok "no php in uploads"
find /srv/www /var/www -name 'info.php' 2>/dev/null | grep -q . && warn "phpinfo present" || ok "no phpinfo"
[ -r /srv/www/vhosts/wordpress/wp-config.php ] \
  && { p=$(stat -c '%a' /srv/www/vhosts/wordpress/wp-config.php); case "$p" in 600|640|644) ;; *) warn "wp-config.php perms: $p";; esac; }

# --- 14. mysql --------------------------------------------------
hdr "mysql"
if [ -n "$MYSQL" ]; then
  W=$("$MYSQL" -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'" 2>/dev/null | grep -vE '^(score1|score2)@')
  [ -n "$W" ] && crit "unexpected @'%' mysql users: $(echo $W)" || ok "only score1/score2 @'%' (scoring)"
  "$MYSQL" -N -e "SELECT user FROM mysql.user WHERE user=''" 2>/dev/null | grep -q . \
    && crit "anonymous mysql user" || ok "no anon mysql users"
else warn "mysql client missing — skipped"; fi

# --- 15. mail alias pipes (postfix persistence) ---------------
hdr "postfix aliases"
AP=$(grep -vE '^\s*#|^\s*$' /etc/aliases /etc/postfix/aliases 2>/dev/null | grep '\|')
[ -n "$AP" ] && warn "alias pipes to commands:\n$AP" || ok "no alias command pipes"

# --- 16. MAC / audit posture -----------------------------------
hdr "MAC & logging"
command -v getenforce >/dev/null 2>&1 && {
  E=$(getenforce 2>/dev/null)
  [ "$E" = "Enforcing" ] && ok "SELinux Enforcing" || warn "SELinux mode: $E"
}
systemctl is-active auditd >/dev/null 2>&1 && ok "auditd running" || warn "auditd NOT running"
auditctl -l 2>/dev/null | grep -q sudoers-drop && ok "sudoers-drop watch present" || info "add watch: auditctl -w /etc/sudoers.d/ -p wa -k sudoers-drop"

# --- 17. deleted-but-running / proc tricks ---------------------
hdr "process tricks"
DE=$(ls -l /proc/[0-9]*/exe 2>/dev/null | grep '(deleted)' | head -3)
[ -n "$DE" ] && warn "deleted-but-running binaries:\n$DE" || ok "no deleted running exes"
TMPX=$(find /tmp /dev/shm /var/tmp -type f -perm /111 2>/dev/null | grep -v 'persist-sweep\|systemd-private' | head -5)
[ -n "$TMPX" ] && warn "executables in tmp dirs: $(echo $TMPX)" || ok "tmp dirs clean of executables"

# --- 18. immutable implants ------------------------------------
hdr "immutable flags"
for d in /etc/sudoers.d /usr/local/sbin /usr/local/bin /etc/systemd/system; do
  # directories always "look" flagged to lsattr — check regular files only
  IM=$(find "$d" -type f 2>/dev/null | head -3000 | xargs -r lsattr -d 2>/dev/null | awk '$1 ~ /[ia]/ {print $NF}' | head -3)
  [ -n "$IM" ] && warn "immutable/append files in $d: $(echo $IM)" || ok "$d clean"
done

# --- 19. containers / podman (v3) -------------------------------
hdr "containers (v3)"
for g in docker podman; do
  grep -qE "^${g}:" /etc/group 2>/dev/null && {
    M=$(grep "^${g}:" /etc/group | cut -d: -f4 | tr ',' '\n' | grep -vE '^$')
    [ -n "$M" ] && warn "$g group has member users: $(echo $M | tr '\n' ' ')"
  }
done
for f in /root/.docker/config.json /home/*/.docker/config.json; do
  [ -e "$f" ] && grep -q '"auths"' "$f" && warn "stored registry creds: $f"
done
for f in /etc/containers/containers.conf /etc/docker/daemon.json; do
  [ -e "$f" ] && grep -qiE 'insecure|privileged' "$f" && warn "risky container daemon config: $f"
done
if command -v podman >/dev/null; then
  podman ps -a --format '{{.Names}}  {{.Image}}  {{.Command}}' 2>/dev/null | while read -r l; do info "  container: $l"; done
  info "^ unexpected/unknown container = inspect: podman inspect <name>"
fi
basediff containers-cfg "find /root/.config/containers /home/*/.config/containers /etc/containers/registries.conf.d -type f 2>/dev/null"

# --- 20. attack tooling left on box (v3) -------------------------
hdr "attack tooling (v3)"
for t in hydra john nmap wireshark tshark steghide sqlmap medusa dirb gobuster; do
  command -v "$t" >/dev/null 2>&1 && warn "installed: $t ($(rpm -qf "$(command -v $t)" 2>/dev/null | head -1))"
done
rpm -qa 2>/dev/null | grep -iE 'hydra|john|wireshark|steghide|sqlmap|medusa|nmap' | while read -r p; do warn "package: $p"; done
ok "tool scan done"

# --- 21. insecure legacy services (v3) ---------------------------
hdr "legacy services (v3)"
for s in telnet.socket telnet xinetd vsftpd proftpd tftp.socket tftpd rsh.socket rlogin.socket rexec.socket; do
  systemctl is-active "$s" >/dev/null 2>&1 && warn "legacy service ACTIVE: $s"
done
basediff xinetd-d "ls /etc/xinetd.d/ 2>/dev/null"
UDP=$(ss -H -ulnp 2>/dev/null | awk '{print $5}' | sed 's/.*://' | sort -un | tr '\n' ' ')
[ -n "$UDP" ] && info "udp listeners: $UDP (69=tftp; 161=snmp lives on the Windows AD box)"
ok "legacy service scan done"

# --- 22. password policy (v3) ------------------------------------
hdr "password policy (v3)"
PQ=/etc/security/pwquality.conf
[ -s "$PQ" ] || PQ=$(ls /etc/security/pwquality.conf.d/*.conf 2>/dev/null | head -1)
grep -hE '^\s*minlen|^\s*minclass|[dulo]credit' "$PQ" 2>/dev/null | head -5 \
  || warn "no minlen/minclass set in pwquality config"
grep -q 'pam_pwquality' /etc/pam.d/common-password* 2>/dev/null \
  || warn "pam_pwquality not in password stack"
ok "policy scan done"

# --- 23. motd / polkit / sockets / perms (v3) --------------------
hdr "motd, polkit, sockets, perms (v3)"
basediff motd-d "ls /etc/update-motd.d/ 2>/dev/null"
MOT=$(grep -rlE 'curl|wget|nc +' /etc/update-motd.d/ 2>/dev/null)
[ -n "$MOT" ] && crit "motd script with network callback: $(echo $MOT)" || ok "motd scripts clean"
POL=$(grep -rl 'Result.YES' /etc/polkit-1/rules.d/ 2>/dev/null | grep -v '/49-')
[ -n "$POL" ] && warn "polkit rule grants Result.YES: $(echo $POL)" || ok "no rogue polkit YES rules"
basediff polkit-d "ls /etc/polkit-1/rules.d/ 2>/dev/null"
basediff sockets "systemctl list-sockets --no-legend 2>/dev/null | awk '{print \$1}'"
stat -c '%a' /tmp | grep -q '1777' || warn "/tmp is not 1777 sticky (is: $(stat -c '%a' /tmp))"
SH=$(stat -c '%a' /etc/shadow 2>/dev/null); case "$SH" in 400|640|000) ;; *) warn "/etc/shadow perms: $SH";; esac
CD=$(stat -c '%a' /etc/cron.d 2>/dev/null); case "$CD" in 700|750|751|755) ;; *) warn "/etc/cron.d perms: $CD";; esac
EV=$(find /srv/www /var/www \( -name '.env' -o -name '*.bak' -o -name '*.old' -o -name '*.save' \) -type f 2>/dev/null | head -4)
[ -n "$EV" ] && warn "env/backup files in webroot: $(echo $EV)" || ok "no .env/.bak in webroot"
PORTS=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}')
[ "$(echo $PORTS | wc -w)" -gt 1 ] && warn "multiple sshd Ports: $PORTS" || ok "sshd single port (${PORTS:-22})"
ODD=$(awk -F: '$1 ~ /^\./ || $1 ~ /[.:_-]$/ || $1 ~ /\.\./ {print $1}' /etc/passwd)
[ -n "$ODD" ] && crit "odd/path-pattern username: $(echo $ODD)" || ok "no odd-pattern usernames"

# --- 24. mysql grants depth (v3) ---------------------------------
hdr "mysql grants depth (v3)"
if [ -n "$MYSQL" ]; then
  RR=$("$MYSQL" -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='root' AND host NOT IN ('localhost','127.0.0.1','::1')" 2>/dev/null)
  [ -n "$RR" ] && crit "root reachable from non-localhost: $(echo $RR)" || ok "root localhost-only"
  SP=$("$MYSQL" -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE Super_priv='Y' AND user NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','score1','score2')" 2>/dev/null)
  [ -n "$SP" ] && warn "SUPER grant to non-system user: $(echo $SP)" || ok "no stray SUPER grants"
else warn "mysql client missing — skipped"; fi

# --- 25. pam & xattrs (v3.1) ------------------------------------
hdr "pam & xattrs (v3.1)"
PM=$(grep -rl 'pam_permit' /etc/pam.d/ 2>/dev/null)
[ -n "$PM" ] && crit "pam_permit in PAM stack (auth bypass!): $(echo $PM)" || ok "no pam_permit in PAM stack"
PD=/lib/x86_64-linux-gnu/security/pam_deny.so
PP=/lib/x86_64-linux-gnu/security/pam_permit.so
if [ -e "$PD" ] && [ -e "$PP" ]; then
  [ "$(md5sum < "$PD" | awk '{print $1}')" = "$(md5sum < "$PP" | awk '{print $1}')" ] \
    && crit "pam_deny.so == pam_permit.so HASH (deny module tampered!)" \
    || ok "pam_deny/pam_permit hashes differ (expected)"
fi
XA=$(getfattr -R -m 'user\.' -d /etc /root /home 2>/dev/null | grep '^# file' | head -5)
[ -n "$XA" ] && warn "user.* xattrs present (hiding spot — getfattr -d to dump): $(echo $XA)" || ok "no user.* xattrs"

# --- 26. wordpress deep (v3.2) -----------------------------------
hdr "wordpress deep (v3.2)"
WPD=/srv/www/vhosts/wordpress
if [ -d "$WPD/wp-content" ]; then
  # new plugin dir = seeded vuln (wp-file-manager lesson) — drop-ins/mu-plugins auto-load
  basediff wp-plugins "ls $WPD/wp-content/plugins 2>/dev/null"
  info "^ new plugin folder appears = inspect BEFORE activating (plugin CVE class)"
  MU=$(ls "$WPD/wp-content/mu-plugins/" 2>/dev/null | head -5)
  [ -n "$MU" ] && warn "mu-plugins present (auto-load, invisible in WP admin): $(echo $MU)" || ok "no mu-plugins"
  DI=$(ls "$WPD/wp-content/db.php" "$WPD/wp-content/object-cache.php" "$WPD/wp-content/advanced-cache.php" 2>/dev/null)
  [ -n "$DI" ] && warn "wp drop-ins present (auto-load code): $(echo $DI)" || ok "no wp drop-ins"
  # the SecDoc's 'hidden add-on, couldn't disable from admin' class = require() in wp-config
  basediff wp-config-hash "md5sum $WPD/wp-config.php 2>/dev/null | awk '{print \$1}'"
  REQ=$(grep -nE '^\s*(require|include|require_once|include_once)' "$WPD/wp-config.php" 2>/dev/null | grep -vE 'wp-load|wp-settings|wp-blog-header' | head -3)
  [ -n "$REQ" ] && crit "wp-config loads a non-core file (backdoor loader pattern): $(echo $REQ)" || ok "wp-config requires clean"
  basediff htaccess-hash "md5sum $WPD/.htaccess 2>/dev/null | awk '{print \$1}'"
  # WP users: admin inventory + green accounts MUST stay admin (rules-protected)
  # auth uses the WP DB creds from wp-config.php (no mysql root password needed)
  if [ -n "$MYSQL" ]; then
    DBU=$(grep -oP "define\(\s*'DB_USER',\s*'\K[^']+" "$WPD/wp-config.php" 2>/dev/null | head -1)
    DBP=$(grep -oP "define\(\s*'DB_PASSWORD',\s*'\K[^']+" "$WPD/wp-config.php" 2>/dev/null | head -1)
    DB=$(grep -oP "define\(\s*'DB_NAME',\s*'\K[^']+" "$WPD/wp-config.php" 2>/dev/null | head -1)
    PFX=$(sed -n "s/.*\$table_prefix\s*=\s*['\"]\([^'\"]*\).*/\1/p" "$WPD/wp-config.php" 2>/dev/null | head -1)
    PFX=${PFX:-wp_}
    if [ -n "$DB" ] && [ -n "$DBU" ]; then
      export MYSQL_PWD="$DBP"
      ADMINS=$("$MYSQL" -N -u "$DBU" -h127.0.0.1 -D "$DB" -e "SELECT u.user_login FROM ${PFX}users u JOIN ${PFX}usermeta m ON u.ID=m.user_id WHERE m.meta_key='${PFX}capabilities' AND m.meta_value LIKE '%administrator%'" 2>/dev/null)
      unset MYSQL_PWD
      [ -n "$ADMINS" ] && info "WP admins: $(echo $ADMINS | tr '\n' ' ')" || warn "could not list WP admins (creds/DB/prefix — check wp-config defines)"
      echo "$ADMINS" | grep -q 'green-user' && ok "green-user is admin (rules-protected account alive)" \
        || warn "green-user NOT in admin list — restore BEFORE green survey"
      echo "$ADMINS" | grep -q 'green-admin' && ok "green-admin alive" \
        || warn "green-admin NOT in admin list — restore BEFORE green survey"
      export MYSQL_PWD="$DBP"
      basediff wp-users "\"$MYSQL\" -N -u \"$DBU\" -h127.0.0.1 -D \"$DB\" -e 'SELECT user_login FROM ${PFX}users' 2>/dev/null"
      unset MYSQL_PWD
      info "^ new WP user = seeded account (census class #2)"
    else
      warn "wp-config missing DB_NAME/DB_USER defines — WP checks skipped"
    fi
  fi
else warn "wordpress not at $WPD — adjust WPD path or skip this section"; fi

# --- 27. hosts / php-loader / keys / history secrets (v3.2) -------
hdr "hosts, php-loader, keys, history (v3.2)"
basediff hosts-file "cat /etc/hosts 2>/dev/null"
AP=$(grep -rhsE '^\s*(auto_prepend_file|auto_append_file)\s*=\s*[^;[:space:]]' /etc/php*/*/php.ini /etc/php*/*/conf.d/*.ini "$WPD/.htaccess" /etc/apache2/*.conf /etc/apache2/conf.d/*.conf 2>/dev/null | head -3)
[ -n "$AP" ] && crit "php auto_prepend/append_file set (hidden code loader): $(echo $AP)" || ok "no php auto-prepend"
PK=$(find /root /home /srv /tmp /opt -xdev \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \) -type f 2>/dev/null | grep -v '/evidence' | head -5)
[ -n "$PK" ] && warn "stray private keys (SecDoc privatekeys row): $(echo $PK)" || ok "no stray private keys"
HS=$(grep -hiE 'password|passwd|secret|token|bearer|api[_-]?key' /root/.bash_history /home/*/.bash_history 2>/dev/null | grep -viE '^\s*#|^history' | head -4)
[ -n "$HS" ] && warn "possible secrets in shell history — scrub these lines: $(echo $HS | head -3)" || ok "shell history clean of secret-looking lines"

# --- 28. service vuln probes (v3.5) --------------------------------
hdr "service vuln probes (v3.5)"
# uptime sanity FIRST: the three scored services must answer
if command -v curl >/dev/null; then
  curl -sI -m 5 http://127.0.0.1/ | head -1 | grep -qE 'HTTP/1.[01] [123]' \
    && ok "apache answering on 80" || crit "apache NOT answering on 80 (uptime lane!)"
fi
if command -v smbclient >/dev/null; then
  smbclient -L //127.0.0.1/ -N >/dev/null 2>&1 && ok "smb answers (anon list worked — see guest WARN)" \
    || ok "smb anon-list refused (fine if guest is off)"
fi
if [ -n "$MYSQL" ]; then
  "$MYSQL" -h127.0.0.1 -N -e 'SELECT 1' >/dev/null 2>&1 && ok "mysql answering on 3306" \
    || warn "mysql ping failed (root creds — check manually)"
fi

# --- required services matrix (comp table) ---------------------------------
# openSUSE Leap box: HTTP 80, MySQL 3306, SMB 139/445 MUST be up (scored)
# Ubuntu 24.04 box:  OpenPLC UI 8080 + Modbus 502 MUST be up (scored)
OS_ID=$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null)
IS_SUSE=false; IS_PLC=false
command -v zypper >/dev/null 2>&1 && IS_SUSE=true
ss -tln 2>/dev/null | grep -q ':502 ' && IS_PLC=true
if $IS_SUSE; then
  for p in 80 3306 139 445; do
    ss -tln | grep -q ":$p " && ok "required port $p up (openSUSE matrix)" \
      || crit "REQUIRED port $p DOWN (openSUSE matrix: HTTP/MySQL/SMB)"
  done
  systemctl is-active apache2 >/dev/null 2>&1 && ok "apache2 active" || crit "apache2 not active"
  { systemctl is-active smb >/dev/null 2>&1 || systemctl is-active samba >/dev/null 2>&1; } \
    && ok "smb service active" || crit "smb service not active"
  { systemctl is-active mysql84 >/dev/null 2>&1 || systemctl is-active mysql >/dev/null 2>&1 || systemctl is-active mysqld >/dev/null 2>&1; } \
    && ok "mysql service active" || crit "mysql service not active"
fi
if $IS_PLC; then
  ss -tln | grep -q ':502 ' && ok "modbus 502 listening" || crit "REQUIRED Modbus 502 DOWN (uptime lane)"
  ss -tln | grep -q ':8080 ' && ok "OpenPLC UI 8080 up" || crit "REQUIRED OpenPLC UI 8080 DOWN (restore: web UI -> Start PLC, NOT systemd)"
  systemctl is-active modbus >/dev/null 2>&1 && ok "modbus.service active" || warn "modbus.service not 'active' (rules: never disable — verify state)"
  systemctl is-active openplc >/dev/null 2>&1 && ok "openplc.service active" || warn "openplc.service not 'active' (rules: never disable — verify state)"
  if command -v ufw >/dev/null; then
    ufw status 2>/dev/null | grep -q 'Status: active' && ok "ufw active" || warn "ufw INACTIVE (PLC1 firewall step owed — snapshot FIRST)"
  fi
  LC=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -d 'username=openplc&password=openplc' http://127.0.0.1:8080/login 2>/dev/null)
  case "$LC" in 302|303) crit "OpenPLC DEFAULT CREDS still valid (openplc/openplc)";; "") ;; *) ok "OpenPLC default creds rejected/changed ($LC)";; esac
fi
[ "$OS_ID" = "debian" ] && info "Debian box (PLC2?) — assume-breach: monitor/document only, no fixes"

# apache config + live probes
grep -rhsE '^\s*ServerTokens' /etc/apache2 2>/dev/null | grep -v '#' | grep -q Prod \
  && ok "ServerTokens Prod" || warn "ServerTokens not Prod (version banner leak — SecDoc row)"
T=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X TRACE http://127.0.0.1/ 2>/dev/null)
case "$T" in 405|403|000) ok "TRACE rejected ($T)";; "") ;; *) warn "TRACE returned $T (XST class — set 'TraceEnable off')";; esac
curl -s -m 5 http://127.0.0.1/wp-content/uploads/ 2>/dev/null | grep -qi 'index of' \
  && crit "directory listing ON for /wp-content/uploads/" || ok "no directory listing on uploads"
GIT=$(find /srv/www/vhosts /var/www/html -xdev \( -name .git -o -name .svn \) 2>/dev/null | head -3)
[ -n "$GIT" ] && crit "VCS metadata exposed in webroot: $(echo $GIT)" || ok "no .git/.svn in webroot"
X=$(curl -s -o /dev/null -w '%{http_code}' -m 5 http://127.0.0.1/xmlrpc.php 2>/dev/null)
case "$X" in 405|403|000) ok "xmlrpc blocked ($X)";; "") ;; *) warn "xmlrpc answers $X (brute/SSRF class — deny in .htaccess + SecDoc row)";; esac
if command -v curl >/dev/null; then
  U=$(curl -s -m 5 "http://127.0.0.1/?rest_route=/wp/v2/users" 2>/dev/null | grep -c '"slug"')
  if [ "${U:-0}" -gt 0 ] 2>/dev/null; then
    warn "REST API leaks $U usernames (enumeration class — document or filter)"
  else ok "no REST user enumeration"; fi
fi

# samba config
TP=$(testparm -s 2>&1 >/dev/null)
echo "$TP" | grep -qiE 'error|failed' && crit "smb.conf parse problem: $(echo $TP | head -1)" || ok "smb.conf parses clean"
HA=$(grep -rhsE '^\s*(hosts allow|hosts deny)' /etc/samba/smb.conf 2>/dev/null | head -2)
[ -n "$HA" ] && warn "smb hosts allow/deny present — verify it cannot block the SCORER: $(echo $HA)" || ok "no smb hosts allow/deny"

# sshd posture (root-only detail)
if [ "$(id -u)" -eq 0 ] && command -v sshd >/dev/null; then
  T2=$(sshd -T 2>/dev/null)
  echo "$T2" | grep -qi 'permitrootlogin no' || warn "PermitRootLogin not 'no' (SecDoc row)"
  MA=$(echo "$T2" | awk 'tolower($1)=="maxauthtries"{print $2}')
  if [ -n "$MA" ] && [ "$MA" -gt 6 ] 2>/dev/null; then warn "MaxAuthTries=$MA (brute-force friendly)"; else ok "MaxAuthTries sane (${MA:-?})"; fi
  echo "$T2" | grep -qi 'allowagentforwarding no' || warn "AllowAgentForwarding on (agent-hijack class)"
fi

# postfix open-relay posture
if command -v postconf >/dev/null; then
  MN=$(postconf -h mynetworks 2>/dev/null)
  echo "$MN" | grep -qE '0\.0\.0\.0/0|::/0|all' \
    && crit "postfix mynetworks = world (open-relay config)" || ok "mynetworks not world-wide (${MN:-unset})"
fi

# mysql hardening extras
if [ -n "$MYSQL" ]; then
  EP=$("$MYSQL" -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE account_locked='N' AND authentication_string='' AND plugin LIKE '%password%' AND user NOT LIKE 'mysql%'" 2>/dev/null)
  [ -n "$EP" ] && crit "mysql accounts with EMPTY password: $(echo $EP)" || ok "no empty-password mysql accounts"
  LI=$("$MYSQL" -N -e "SHOW VARIABLES LIKE 'local_infile'" 2>/dev/null | awk '{print $2}')
  [ "$LI" = "ON" ] && warn "local_infile ON (LOAD DATA file-read class)" || ok "local_infile off"
fi

# forgotten listeners that love to come back
for u in tftpd tftp nfs-server rpcbind; do
  systemctl is-enabled "$u" >/dev/null 2>&1 && systemctl is-active "$u" >/dev/null 2>&1 \
    && warn "$u active (unscored — disable if unused)"
done

# --- 29. AB intel cross-check (v3.7) --------------------------------
hdr "shadow copies + finger (v3.7)"
SC=$(ls -l /etc/shadow.old /etc/shadow.bak /etc/shadow~ /etc/shadow.copy /etc/shadow.orig 2>/dev/null | awk '{print $NF}')
[ -n "$SC" ] && crit "stray shadow COPY files (second live cred set — quarantine to evidence, chmod 600): $SC" \
  || ok "no stray shadow copies"
ss -tln 2>/dev/null | grep -q ':79 ' \
  && crit "finger LISTENING on 79 (hands out the full account list, no creds needed)" \
  || ok "no finger listener on 79"

echo
echo "=============== RESULT: ${CRIT} crit / ${WARN} warn ==============="
[ $CRIT -gt 0 ] && echo "Fix CRITs first; one change-log line per fix. Re-sweep after."
exit $CRIT
