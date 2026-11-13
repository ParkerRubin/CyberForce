#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 - LINUX-VULNSCAN (linpeas-style, custom)
# One short console report for hand-triage. Changes NOTHING.
# Sections: system, accounts, persistence, SUID/ perms, sshd,
# creds/history, listeners, ICS services.
# Deep sweeps still belong to linpeas.sh (see install-tools.sh)
# - this script filters to CyberForce signal.
# Run as root for full visibility (works degraded without).
# Usage: sudo ./linux-vulnscan.sh [--save] [--fix] [--fix-ssh] [--confirm-ab]
#   (--save = ONE file)
#   (--fix  = ALSO auto-fix ONLY the safe class: SUID bits on binaries
#            that are not standard, canonical file modes (shadow/sudoers/
#            ssh keys/authorized_keys), lock empty-password and extra
#            UID-0 accounts, enable auditd/ufw logging. Every fix is
#            reversible, logged to /var/log/cf-changes.log, and /etc is
#            tarred up first. NOTHING ambiguous is auto-touched.)
#   (--fix-ssh = drop-in hardening: PermitRootLogin no, MaxAuthTries 3,
#            LoginGraceTime 30, LogLevel VERBOSE - validated with sshd -t
#            and rolled back automatically if it fails. Reloads sshd
#            WITHOUT dropping your session. Scoring uses score1/score2,
#            never root, so this cannot break it.)
#   ASSUME-BREACH GUARD: if dnp3.service exists (PLC2), --fix/--fix-ssh
#   are refused without --confirm-ab, per competition rules.
# ============================================================

set -u
SAVE=0; FIX=0; FIXSSH=0; CONFIRM_AB=0
for a in "$@"; do
  case "$a" in
    --save) SAVE=1;;
    --fix)  FIX=1;;
    --fix-ssh) FIXSSH=1;;
    --confirm-ab) CONFIRM_AB=1;;
  esac
done

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

# ---------------- FIX ENGINE (Tier-1 safe actions only) ----------------
# Protected accounts are NEVER touched by any automated path:
# score1, score2, patch, historian, green-user, green-admin, openplc,
# modbus, dnp3 (case-insensitive). ICS services are never stopped.
CHANGELOG=/var/log/cf-changes.log
logfix() { printf '%s [cf-fix] %s\n' "$(date '+%F %T')" "$1" >> "$CHANGELOG" 2>/dev/null || true; }

# assume-breach detection: dnp3.service unit present = PLC2 = rules say extreme caution
IS_AB=0
systemctl list-unit-files 2>/dev/null | grep -q '^dnp3\.service' && IS_AB=1
if [ "$IS_AB" -eq 1 ] && [ "$FIX" -eq 1 ] && [ "$CONFIRM_AB" -eq 0 ]; then
  warn "ASSUME-BREACH box detected (dnp3.service): --fix REFUSED without --confirm-ab (report-only run)."
  FIX=0
fi
if [ "$IS_AB" -eq 1 ] && [ "$FIXSSH" -eq 1 ] && [ "$CONFIRM_AB" -eq 0 ]; then
  warn "ASSUME-BREACH box detected (dnp3.service): --fix-ssh REFUSED without --confirm-ab."
  FIXSSH=0
fi

if [ "$FIX" -eq 1 ] || [ "$FIXSSH" -eq 1 ]; then
  warn "FIX MODE: reversible fixes only, each logged to $CHANGELOG."
  warn "Snapshot this VM via the Controller FIRST (revert limit 2/hour, fresh re-image = 75 pts)."
  if [ "$(id -u)" -eq 0 ]; then
    BK=/var/tmp/cf-etc-backup-$(date +%Y%m%d-%H%M%S).tgz
    if tar czf "$BK" /etc 2>/dev/null; then
      item "Pre-change backup: $BK"; logfix "backup /etc -> $BK"
    else
      warn "Backup FAILED - aborting ALL fixes (nothing will be changed)."
      FIX=0; FIXSSH=0
    fi
  else
    warn "Not root: cannot back up /etc - fixes disabled (re-run with sudo)."
    FIX=0; FIXSSH=0
  fi
fi
CF_PROTECTED='^(root|score1|score2|patch|historian|green-user|green-admin|openplc|modbus|dnp3)$'

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
if [ "$FIX" -eq 1 ] && [ "$(id -u)" -eq 0 ]; then
  # lock empty-password accounts (protected accounts NEVER locked - could break scoring)
  awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read -r u; do
    if echo "$u" | grep -Eqi "$CF_PROTECTED"; then
      warn "empty password on PROTECTED account $u - NOT locking (fix by hand with the team)"
    else
      passwd -l "$u" >/dev/null 2>&1 \
        && { flag "FIXED: locked empty-password account $u (restore: sudo passwd -u $u)"; logfix "passwd -l $u (empty password)"; } \
        || flag "FIX FAIL: could not lock $u"
    fi
  done
  # lock UID-0 accounts other than root (root excluded by CF_PROTECTED)
  awk -F: '$3==0{print $1}' /etc/passwd | while read -r u; do
    echo "$u" | grep -Eqi "$CF_PROTECTED" && continue
    passwd -l "$u" >/dev/null 2>&1 \
      && { flag "FIXED: locked UID-0 account $u (restore: sudo passwd -u $u)"; logfix "passwd -l $u (UID 0 besides root)"; }
  done
fi
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
# Only /etc (custom units) are flagged - /usr/lib units are distro-owned.
# Path patterns use slashes so "utmp" (systemd-update-utmp) never matches.
find /etc/systemd/system -maxdepth 2 \( -name '*.service' -o -name '*.timer' \) 2>/dev/null |
while read -r u; do
  execs=$(grep -hE '^(Exec|OnCalendar|OnBootSec|OnUnitActiveSec)' "$u" 2>/dev/null | tr '\n' ' | ')
  case "$u" in *dnp3*|*modbus*) marker="[ICS - DO NOT TOUCH]";; *) marker="";; esac
  case "$execs" in
    *"/tmp/"*|*"/home/"*|*"/dev/shm"*|*"/opt/"*|*"/srv/"*) flag "$marker $u :: $execs";;
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
if [ "$FIX" -eq 1 ]; then
  if [ "$(id -u)" -eq 0 ]; then
    warn "FIX MODE ON: SUID bits on non-standard binaries WILL be removed (reversible)."
  else
    warn "FIX MODE ignored: not root - re-run with sudo to use --fix."
    FIX=0
  fi
fi
find / -xdev -perm -4000 -type f 2>/dev/null | while read -r b; do
  case "$b" in
    /usr/bin/su|/usr/bin/sudo|/usr/bin/passwd|/usr/bin/chsh|/usr/bin/chsh|/usr/bin/chfn|/usr/bin/gpasswd|/usr/bin/newgrp|/usr/bin/mount|/usr/bin/umount|/usr/bin/pkexec|/usr/bin/fusermount*|/usr/lib/openssh/ssh-keysign|/usr/lib/dbus-1.0/dbus-daemon-launch-helper|/usr/bin/su.real) item "   $b";;
    *)
      if [ "$FIX" -eq 1 ]; then
        oldmode=$(stat -c '%a' "$b" 2>/dev/null)
        chmod u-s "$b" 2>/dev/null \
          && flag "FIXED: removed SUID from $b (was mode $oldmode; restore: sudo chmod u+s $b)" \
          || flag "SUID: $b (chmod u-s FAILED - fix by hand)"
      else
        flag "SUID: $b (GTFOBins root-escalation risk - remove with sudo chmod u-s, or rerun with --fix)"
      fi;;
  esac
done
item "World-writable /etc or /usr files:"
find /etc /usr -xdev -type f -perm -002 2>/dev/null | head -10
if [ "$FIX" -eq 1 ] && [ "$(id -u)" -eq 0 ]; then
  # canonical modes for known-correct targets only - reversible, logged
  fixmode() { # fixmode <path> <mode>
    [ -e "$1" ] || return 0
    cur=$(stat -c '%a' "$1" 2>/dev/null)
    [ "$cur" = "$2" ] && return 0
    chmod "$2" "$1" 2>/dev/null \
      && { flag "FIXED: chmod $2 $1 (was $cur; restore: sudo chmod $cur $1)"; logfix "chmod $2 $1 (was $cur)"; } \
      || flag "FIX FAIL: chmod $2 $1"
  }
  item "Canonical file modes (--fix):"
  fixmode /etc/passwd 644
  fixmode /etc/shadow 640
  fixmode /etc/group 644
  fixmode /etc/crontab 644
  fixmode /etc/sudoers 440
  for f in /etc/sudoers.d/*;       do [ -f "$f" ] && fixmode "$f" 440; done
  for f in /etc/cron.d/*;          do [ -f "$f" ] && fixmode "$f" 644; done
  for k in /etc/ssh/ssh_host_*_key; do [ -f "$k" ] && fixmode "$k" 600; done
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] && fixmode "$f" 600; done
  for d in /root/.ssh /home/*/.ssh; do [ -d "$d" ] && fixmode "$d" 700; done
  # additive logging/audit posture - never removes anything
  command -v ufw >/dev/null 2>&1 && { ufw logging low >/dev/null 2>&1 && logfix "ufw logging low"; }
  command -v auditd >/dev/null 2>&1 && ! systemctl is-active auditd >/dev/null 2>&1 \
    && { systemctl enable --now auditd >/dev/null 2>&1 && { flag "FIXED: auditd enabled"; logfix "systemctl enable --now auditd"; }; }
fi
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
if [ "$FIXSSH" -eq 1 ] && [ "$(id -u)" -eq 0 ]; then
  drop=/etc/ssh/sshd_config.d/99-cf-hardening.conf
  mkdir -p /etc/ssh/sshd_config.d
  printf '%s\n' "PermitRootLogin no" "MaxAuthTries 3" "LoginGraceTime 30" "LogLevel VERBOSE" > "$drop"
  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
    flag "FIXED: sshd hardened via $drop (PermitRootLogin no, MaxAuthTries 3, LoginGraceTime 30, LogLevel VERBOSE)"
    item "   reloaded in place - your session was NOT dropped; scoring uses score1/score2, not root"
    logfix "sshd hardened via $drop + reload"
  else
    rm -f "$drop"
    flag "sshd hardening ROLLED BACK (sshd -t failed) - config untouched"
    logfix "sshd hardening rolled back (sshd -t failed)"
  fi
elif [ "$FIXSSH" -eq 1 ]; then
  warn "--fix-ssh needs root (sudo)."
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
# name every listener process (report-only - NEVER killed by this script)
if [ "$(id -u)" -eq 0 ]; then
  item "Listener process details:"
  ss -tlnp 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un | while read -r p; do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-110)
    cwd=$(readlink "/proc/$p/cwd" 2>/dev/null)
    item "   pid=$p cwd=${cwd:-?} cmd=${cmd:-?}"
  done
  warn "openplc-proxy (nginx) owns 8443/18080/18443-style ports on PLC1 - part of the ICS stack, do not touch."
else
  warn "Run with sudo to see listener process names."
fi

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
for s in dnp3 modbus ignition openplc openplc-runtime openplc-proxy; do
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
