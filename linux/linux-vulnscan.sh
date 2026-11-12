#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 - LINUX-VULNSCAN (linpeas-style, custom)
# One short console report for hand-triage. Changes NOTHING.
# Sections: system, accounts, persistence, SUID/ perms, sshd,
# creds/history, listeners, ICS services.
# Deep sweeps still belong to linpeas.sh (see install-tools.sh)
# - this script filters to CyberForce signal.
# Run as root for full visibility (works degraded without).
# Usage: sudo ./linux-vulnscan.sh [--save]  (--save = ONE file)
# ============================================================

set -u
SAVE=0
[ "${1:-}" = "--save" ] && SAVE=1

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
OFF=$(tput sgr0 2>/dev/null || true)

OUT=""
if [ "$SAVE" -eq 1 ]; then
  mkdir -p /tmp/cf-vulnscan
  TS=$(date +%Y%m%d-%H%M%S)
  HOSTN=$(hostname)
  OUT="/tmp/cf-vulnscan/vulnscan-${HOSTN}-${TS}.txt"
  exec > >(tee "$OUT") 2>&1
  echo "Saved transcript: $OUT"
fi

section() { printf "\n%s=== %s ===%s\n" "$CYN" "$1" "$OFF"; }
flag()    { printf "  %s[!!]%s %s\n" "$RED" "$OFF" "$1"; }
warn()    { printf "  %s[?]%s %s\n"  "$YEL" "$OFF" "$1"; }
item()    { printf "  %s\n" "$1"; }

if [ "$(id -u)" -ne 0 ]; then
  warn "Not root: shadow, crontabs, some ACLs and logs will be limited."
fi

# ---------------- SYSTEM ----------------
section "SYSTEM"
item "Host: $(hostname)  IP(s): $(hostname -I 2>/dev/null | tr -s ' ' ',')"
item "OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
item "Kernel: $(uname -r)"
item "Uptime: $(uptime -p 2>/dev/null)"
if command -v apt >/dev/null 2>&1; then
  item "Pending security updates: $(apt list --upgradable 2>/dev/null | grep -c 'security' || echo '?')"
fi

# ---------------- ACCOUNTS ----------------
section "ACCOUNTS"
item "UID-0 accounts (expect only root):"
awk -F: '($3==0){print "   "$1" (uid0)"}' /etc/passwd
awk -F: '($2==""){print "   EMPTY PASSWORD: "$1}' /etc/shadow 2>/dev/null | while read -r l; do flag "$l"; done
item "Shell-capable users: $(awk -F: '($7!~/nologin|false/){printf "%s ", $1}' /etc/passwd)"
item "sudoers (non-#):"
grep -vE '^\s*#|^\s*$' /etc/sudoers 2>/dev/null | while read -r l; do
  case "$l" in *NOPASSWD*) flag "sudo NOPASSWD: $l";; *) item "   $l";; esac
done
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | while read -r l; do
    case "$l" in *NOPASSWD*) flag "sudoers.d/$(basename "$f") NOPASSWD: $l";; *) item "   $l";; esac
  done
done
item "wheel/sudo/admin group members: $(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr '\n' ' ' | tr -s ' ')"
# last logins + failed ssh
if [ -f /var/log/auth.log ] || [ -f /var/log/secure ]; then
  fails=$(grep -c 'Failed password' /var/log/auth.log /var/log/secure 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')
  warn "Failed SSH password attempts in log: $fails (spike = brute force)"
fi

# ---------------- PERSISTENCE ----------------
section "PERSISTENCE"
item "cron jobs:"
for d in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron /var/spool/cron/crontabs; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -f "$f" ] || continue
    case "$f" in *e2scrub*|*dpkg*|*sysstat*) continue;; esac
    warn "cron: $f"; grep -vE '^\s*#|^\s*$' "$f" | head -8 | while read -r l; do item "     $l"; done
  done
done
atq 2>/dev/null | grep . && warn "at jobs queued: $(atq | wc -l)" || item "at jobs: none"
item "systemd units/timers with odd Exec paths:"
find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) 2>/dev/null |
while read -r u; do
  execs=$(grep -hE '^(Exec|OnCalendar|OnBootSec|OnUnitActiveSec)' "$u" 2>/dev/null | tr '\n' ' | ')
  case "$u" in *dnp3*|*modbus*) marker="[ICS - DO NOT TOUCH]";; *) marker="";; esac
  case "$execs" in
    *tmp*|*home*|*dev/shm*|*opt*|*srv*) flag "$marker $u :: $execs";;
    *) [ -n "$marker" ] && item "$marker $u :: $execs";;
  esac
done
grep -qE '^[^#]*Exec' /etc/rc.local 2>/dev/null && warn "rc.local active:" && grep -vE '^\s*#|^\s*$' /etc/rc.local
item "authorized_keys:"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  while IFS= read -r k; do
    fp=$(echo "$k" | ssh-keygen -lf /dev/stdin 2>/dev/null | awk '{print $2}')
    warn "$f :: fp=$fp comment=$(echo "$k" | awk '{print $NF}')"
  done < <(grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null)
done
[ -e /etc/ld.so.preload ] && flag "/etc/ld.so.preload exists:" && cat /etc/ld.so.preload
for f in /etc/profile /etc/bash.bashrc /root/.bashrc /etc/profile.d/*.sh; do
  [ -f "$f" ] || continue
  grep -nE '(curl|wget|base64|chmod|/tmp|nc |ncat|bash -i)' "$f" 2>/dev/null | while IFS=: read -r ln l; do
    flag "$f:$ln: $l"
  done
done

# ---------------- SUID / PERMS ----------------
section "SUID / WRITABLE"
item "SUID binaries (non-standard flagged):"
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r b; do
  case "$b" in
    /usr/bin/su|/usr/bin/sudo|/usr/bin/passwd|/usr/bin/chsh|/usr/bin/chsh|/usr/bin/chfn|/usr/bin/gpasswd|/usr/bin/newgrp|/usr/bin/mount|/usr/bin/umount|/usr/bin/pkexec|/usr/bin/fusermount*|/usr/lib/openssh/ssh-keysign|/usr/lib/dbus-1.0/dbus-daemon-launch-helper|/usr/bin/su.real) item "   $b";;
    *) flag "SUID: $b";;
  esac
done
item "World-writable /etc or /usr files:"
find /etc /usr -xdev -type f -perm -002 2>/dev/null | head -10
echo "$PATH" | grep -qE '(^|:)\.(:|$)' && flag "PATH contains '.' (current dir)"

# ---------------- SSHD POSTURE ----------------
section "SSHD"
sshd_conf="/etc/ssh/sshd_config"
if [ -f "$sshd_conf" ]; then
  for k in PermitRootLogin PasswordAuthentication MaxAuthTries PermitEmptyPasswords; do
    v=$(grep -iE "^${k}\s" "$sshd_conf" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
    item "$k = ${v:-default}"
  done
  rp=$(grep -iE "^PermitRootLogin" "$sshd_conf" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print $2}')
  case "${rp:-yes}" in yes) flag "PermitRootLogin yes (rotate root creds or set to no)";; *) item "(root login restricted)";; esac
fi
[ -f /etc/ssh/ssh_host_ed25519_key ] && warn "host key ed25519 present (pin its fingerprint day-1: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)"

# ---------------- CREDS / HISTORY ----------------
section "CREDS / HISTORY"
grep -rniE '(passw|secret|token|api[_-]?key)' /etc/*.conf /etc/*/* 2>/dev/null |
  grep -vE 'password\s*=\s*\*|passwd|#|pam_pw|shadow|pam.d' | head -12 | while IFS=: read -r f ln l; do
    flag "cred hit: $f:$ln: $(echo "$l" | cut -c1-90)"
  done
for h in /root/.bash_history /home/*/.bash_history; do
  [ -f "$h" ] || continue
  grep -nE '(passw|secret|token|mysql|sudo|ssh |curl|wget|chmod 777)' "$h" 2>/dev/null | head -6 | while IFS=: read -r ln l; do
    warn "$h:$ln: $(echo "$l" | cut -c1-90)"
  done
done
find / -xdev -name 'id_rsa' -not -path '*/openssh/*' 2>/dev/null | while read -r k; do
  head -1 "$k" | grep -q 'PRIVATE KEY' && flag "private key: $k"
done
item "MySQL/mysql historian hints:"
grep -rn 'historian\|blueuser\|blueteam' /etc/mysql/ 2>/dev/null | head -4 | cut -c1-120

# ---------------- LISTENERS ----------------
section "LISTENERS (ss -tulpn)"
ss -tulpn 2>/dev/null | grep LISTEN | while read -r l; do item "$l"; done
warn "Cross-check against REQUIRED-PORTS.md - anything else is a backdoor candidate."

# established OUTBOUND (possible C2)
item "Established outbound connections:"
ss -tupn state established 2>/dev/null | grep -v "127.0.0.1\|::1" | head -15 | while read -r l; do item "$l"; done

# ---------------- DELETED-BINARY PROCESSES ----------------
section "RUNNING DELETED BINARIES (dropper tell)"
for p in /proc/[0-9]*; do
  exe=$(readlink "$p/exe" 2>/dev/null)
  case "$exe" in *"(deleted)") flag "PID ${p#/proc/}: $exe  cmdline: $(tr '\0' ' ' < "$p/cmdline" | cut -c1-100)";; esac
done

# ---------------- ICS SERVICES ----------------
section "ICS SERVICES (do not restart/remove)"
for s in dnp3 modbus ignition openplc; do
  st=$(systemctl is-active "$s" 2>/dev/null)
  if [ "$st" = "active" ]; then
    item "$s.service: active"
  elif systemctl list-unit-files 2>/dev/null | grep -q "^${s}"; then
    flag "$s.service: state=$st  (was expected to run?)"
  fi
done
if command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --state=running 2>/dev/null | grep -viE 'systemd|dbus|cron|ssh|getty|network|rsyslog|udev|polkit|logind|resolved|journald|login|time|chrony' | head -12
fi

printf "\n%s[done] Hand-triage above. Deep sweep: linpeas.sh (see install-tools.sh).%s\n" "$GRN" "$OFF"
