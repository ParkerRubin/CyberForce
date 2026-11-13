#!/bin/bash
# ============================================================
# persist-sweep.sh v2 — NCAE blue-team persistence & exposure sweep
# Target: OpenSUSE Leap 16 scored box (HTTP 80 / MySQL 3306 / SMB 139,445)
# READ-ONLY: reports findings, changes nothing. First run = baseline,
# every later run DIFFS — the point is catching NEW drops (active red team).
# v2 adds what linPEAS misses: package integrity (rpm -V), passwd/shadow
# hash diffs, webroot file-list diff, firewall diff, autostart/user-units,
# udev, kernel modules, PATH-hijack collisions, deleted-but-running,
# outbound C2 view, rc-file tamper patterns, mail-alias pipes.
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
[ $LOG -eq 1 ] && exec > >(tee "sweep-$(date +%Y%m%d-%H%M%S).log") 2>&1
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
visudo -c >/dev/null 2>&1 || crit "SUDOERS SYNTAX BROKEN"

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
UP=$(find /srv/www/vhosts -path '*uploads*' -name '*.php' 2>/dev/null)
[ -n "$UP" ] && crit "PHP inside uploads dir (classic webshell spot): $(echo $UP)" || ok "no php in uploads"
find /srv/www /var/www -name 'info.php' 2>/dev/null | grep -q . && warn "phpinfo present" || ok "no phpinfo"
[ -r /srv/www/vhosts/wordpress/wp-config.php ] \
  && { p=$(stat -c '%a' /srv/www/vhosts/wordpress/wp-config.php); case "$p" in 600|640|644) ;; *) warn "wp-config.php perms: $p";; esac; }

# --- 14. mysql --------------------------------------------------
hdr "mysql"
if command -v mysql >/dev/null; then
  W=$(mysql -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE host='%'" 2>/dev/null | grep -vE '^(score1|score2)@')
  [ -n "$W" ] && crit "unexpected @'%' mysql users: $(echo $W)" || ok "only score1/score2 @'%' (scoring)"
  mysql -N -e "SELECT user FROM mysql.user WHERE user=''" 2>/dev/null | grep -q . \
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
  IM=$(lsattr -R "$d" 2>/dev/null | awk '$1 ~ /[ia]/ {print $NF}' | head -3)
  [ -n "$IM" ] && warn "immutable/append files in $d: $(echo $IM)" || ok "$d clean"
done

echo
echo "=============== RESULT: ${CRIT} crit / ${WARN} warn ==============="
[ $CRIT -gt 0 ] && echo "Fix CRITs first; one change-log line per fix. Re-sweep after."
exit $CRIT
