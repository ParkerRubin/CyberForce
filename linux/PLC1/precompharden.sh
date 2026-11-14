#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 — PRE-COMP HARDENING (precomp-hardening.sh)
# For the Nov 2-13 access window, BEFORE the competition starts.
# Runs the Tier-2 items that are NOT safe to automate mid-comp:
#   * full listener identification (report-only, kills nothing)
#   * security updates (apt/zypper) + scored-port verify after
#   * unattended-upgrades OFF (no auto-restarts on comp day)
#   * disable junk services (nfs-server, cups, avahi) if present
#   * lock legacy old.* accounts
#   * OPTIONAL fail2ban (prompted; team philosophy = no new
#     daemons on scoring boxes - default is NO)
# NEVER touches: score1/score2/patch, green-*, historian, root,
# openplc/modbus/dnp3 services, hostnames/IPs. Every action is
# logged to /var/log/cf-changes.log (feed into Security Docs).
# Snapshots: the team takes VM snapshots (initial snapshot already
# exists). This script asks and, only if NO snapshot exists, falls
# back to a deep local backup (homes/webroot/MySQL dumps).
#
# Usage:  sudo bash precomp-hardening.sh [--yes] [--confirm-ab]
#         sudo bash precomp-hardening.sh --comp-day
#           --comp-day : competition-day posture - disables
#           fail2ban jails (auto-bans can eat the scoreboard;
#           any blocked IP may be a scorer) and re-checks ports.
# ============================================================
set -u

YES=0; COMP_DAY=0; CONFIRM_AB=0
for a in "$@"; do
  case "$a" in
    --yes) YES=1;;
    --comp-day) COMP_DAY=1;;
    --confirm-ab) CONFIRM_AB=1;;
  esac
done

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
YEL=$(tput setaf 3 2>/dev/null || true)
CYN=$(tput setaf 6 2>/dev/null || true)
GRN=$(tput setaf 2 2>/dev/null || true)
OFF=$(tput sgr0 2>/dev/null || true)

hdr()    { printf "\n%s== %s ==%s\n" "$CYN" "$1" "$OFF"; }
flag()   { printf "  %s[!!]%s %s\n" "$RED" "$OFF" "$1"; }
warn()   { printf "  %s[?]%s %s\n"  "$YEL" "$OFF" "$1"; }
item()   { printf "  %s\n" "$1"; }
doneok() { printf "  %s[OK]%s %s\n"  "$GRN" "$OFF" "$1"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run with sudo (sudo bash precomp-hardening.sh)" >&2; exit 1
fi

CHANGELOG=/var/log/cf-changes.log
logfix() { printf '%s [cf-precomp] %s\n' "$(date '+%F %T')" "$1" >> "$CHANGELOG" 2>/dev/null || true; }

# ---- assume-breach guard (PLC2 = dnp3.service) ----------------
IS_AB=0
systemctl list-unit-files 2>/dev/null | grep -q '^dnp3\.service' && IS_AB=1
if [ "$IS_AB" -eq 1 ] && [ "$CONFIRM_AB" -eq 0 ]; then
  echo "ASSUME-BREACH box detected (dnp3.service - PLC2). Rules: extreme caution."
  echo "Every change here can cost Red points. Re-run with --confirm-ab to proceed."
  exit 1
fi

echo
echo "=== CYBERFORCE PRE-COMP HARDENING — $(hostname) ==="
warn "Confirm a snapshot of this VM exists BEFORE proceeding (revert limit 2/hour)."
warn "All changes below must be mirrored into Security Documentation."
SNAPSHOT_OK=0
if [ "$YES" -eq 0 ]; then
  read -rp "Does a snapshot of this VM exist (or can you take one now)? [Y/n] " snap
  case "${snap:-y}" in
    n|N) warn "No snapshot = no remote rollback. Deep local backup becomes MANDATORY."; logfix "no snapshot confirmed before precomp run";;
    *)   SNAPSHOT_OK=1; doneok "snapshot confirmed - proceeding"; logfix "snapshot confirmed before precomp run";;
  esac
  read -rp "Proceed with hardening? Type HARDEN: " a
  [ "$a" = "HARDEN" ] || { echo "Aborted."; exit 1; }
else
  SNAPSHOT_OK=1
  logfix "precomp-hardening started with --yes (no typed confirmation)"
fi

TS=$(date +%Y%m%d-%H%M%S)
BK=/var/tmp/cf-etc-backup-$TS.tgz
tar czf "$BK" /etc 2>/dev/null && { doneok "Pre-change backup: $BK"; logfix "backup /etc -> $BK"; } \
  || { flag "Backup FAILED - aborting."; exit 1; }

# ---- deep local backup: mandatory only when no snapshot exists ----
if [ "$SNAPSHOT_OK" -eq 0 ]; then
  DB=/var/tmp/cf-deep-backup-$TS
  mkdir -p "$DB"
  hdr "DEEP LOCAL BACKUP -> $DB (homes, webroots, MySQL dumps) - NO SNAPSHOT MODE"
  tar czf "$DB/homes.tgz" /home 2>/dev/null && doneok "homes.tgz" || warn "homes tar had warnings (fine)"
  tar czf "$DB/webroot.tgz" /srv/www /var/www 2>/dev/null && doneok "webroot.tgz" \
    || warn "no webroot found at /srv/www or /var/www (fine on non-Task boxes)"
  if command -v mysqldump >/dev/null 2>&1; then
    mysqldump --all-databases 2>/dev/null | gzip > "$DB/mysql-all.tgz" \
      && doneok "mysql-all.tgz (ALL databases dumped)" \
      || warn "mysqldump failed (auth?) - dump by hand: mysqldump --all-databases | gzip > dump.tgz"
  else
    item "mysqldump not present - skipped"
  fi
  logfix "deep local backup -> $DB (homes/webroot/mysql) - no snapshot mode"
  doneok "Rollback without snapshots = untar these + restore DBs."
else
  item "Snapshot confirmed - deep local backup skipped (the snapshot is the rollback)."
fi

ask() { # ask "label" -> runs only if YES or user says y
  [ "$YES" -eq 1 ] && return 0
  read -rp "  $1 [y/N] " r
  [ "${r:-}" = "y" ] || [ "${r:-}" = "Y" ]
}

# ============ 1. LISTENER IDENTIFICATION (report-only) ============
hdr "1. LISTENER IDENTIFICATION (nothing is stopped)"
ss -tlnp 2>/dev/null | grep LISTEN | while IFS= read -r l; do item "$l"; done
warn "8443/18080/18443-style ports here are usually the openplc-proxy (nginx) stack - DO NOT kill."
item "Process details per listening pid:"
ss -tlnp 2>/dev/null | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -un | while read -r p; do
  cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | cut -c1-110)
  cwd=$(readlink "/proc/$p/cwd" 2>/dev/null)
  item "   pid=$p cwd=${cwd:-?} cmd=${cmd:-?}"
done
warn "Record anything unexplained -> #ticket-system / Security Docs. Do not kill blind."

# ============ 2. SECURITY UPDATES ============
hdr "2. SECURITY UPDATES"
if command -v apt-get >/dev/null 2>&1; then
  N=$(apt list --upgradable 2>/dev/null | grep -c security || true)
  item "Pending security updates: $N"
  if ask "apt-get update && upgrade now? (watch ICS services after)"; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold upgrade >> /var/tmp/cf-apt-upgrade-$TS.log 2>&1 \
      && doneok "upgrade done (log: /var/tmp/cf-apt-upgrade-$TS.log)" \
      || flag "upgrade had errors - read the log"
    logfix "apt-get upgrade (log /var/tmp/cf-apt-upgrade-$TS.log)"
  fi
elif command -v zypper >/dev/null 2>&1; then
  if ask "zypper refresh + update (patches) now?"; then
    zypper -n --non-interactive refresh >> /var/tmp/cf-zypper-$TS.log 2>&1
    zypper -n --non-interactive update --auto-agree-with-licenses >> /var/tmp/cf-zypper-$TS.log 2>&1 \
      && doneok "zypper update done (log: /var/tmp/cf-zypper-$TS.log)" \
      || flag "zypper update had errors - read the log"
    logfix "zypper update (log /var/tmp/cf-zypper-$TS.log)"
  fi
else
  warn "no apt/zypper - skip"
fi

# ============ 3. UNATTENDED-UPGRADES OFF ============
hdr "3. UNATTENDED-UPGRADES OFF (no surprise restarts on comp day)"
if command -v apt-get >/dev/null 2>&1; then
  if systemctl is-enabled unattended-upgrades >/dev/null 2>&1 \
     || systemctl is-active unattended-upgrades >/dev/null 2>&1; then
    if ask "disable unattended-upgrades service + timers?"; then
      systemctl disable --now unattended-upgrades >/dev/null 2>&1
      systemctl disable apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
      doneok "unattended-upgrades + apt timers disabled"
      logfix "disabled unattended-upgrades and apt-daily timers"
    fi
  else
    doneok "already off"
  fi
else
  item "(apt-only; nothing to do here)"
fi

# ============ 4. JUNK SERVICES OFF ============
hdr "4. JUNK SERVICES (nfs/cups/avahi) — never modbus/dnp3/openplc"
for s in nfs-server rpcbind cups avahi-daemon; do
  systemctl list-unit-files 2>/dev/null | grep -q "^$s\.service" || continue
  if systemctl is-active "$s" >/dev/null 2>&1; then
    if ask "stop+disable $s (not in required-services table)?"; then
      systemctl disable --now "$s" >/dev/null 2>&1 \
        && { doneok "$s disabled"; logfix "systemctl disable --now $s"; } \
        || flag "could not disable $s"
    fi
  else
    item "$s already inactive"
  fi
done

# ============ 5. LEGACY old.* ACCOUNTS ============
hdr "5. LEGACY old.* ACCOUNTS"
OLD=$(awk -F: '/^old\./ && $7 !~ /nologin|false/ {print $1}' /etc/passwd)
if [ -n "$OLD" ]; then
  warn "live shells on legacy accounts: $(echo $OLD)"
  if ask "lock + nologin ALL old.* accounts? (restore: passwd -u + usermod -s bash)"; then
    NOL=$(command -v nologin || echo /usr/sbin/nologin)
    for u in $OLD; do
      passwd -l "$u" >/dev/null 2>&1
      usermod -s "$NOL" "$u" >/dev/null 2>&1 \
        && { doneok "$u locked + nologin"; logfix "passwd -l $u; usermod -s $NOL $u (legacy old.*)"; } \
        || flag "failed on $u"
    done
  fi
else
  doneok "no live old.* shells"
fi

# ============ 6. FAIL2BAN (OPT-IN — team philosophy: no new daemons) ============
hdr "6. FAIL2BAN — OPTIONAL (default NO)"
warn "Team rule: no new services/daemons on scoring boxes. Auto-bans during the"
warn "competition can eat the SCOREBOARD (any blocked IP may be a scorer)."
if systemctl is-active fail2ban >/dev/null 2>&1; then
  item "fail2ban is currently ACTIVE."
  if [ "$COMP_DAY" -eq 1 ]; then
    systemctl disable --now fail2ban >/dev/null 2>&1 \
      && { doneok "fail2ban disabled (comp-day posture)"; logfix "systemctl disable --now fail2ban (comp-day)"; }
  else
    warn "Consider --comp-day mode before scoring starts."
  fi
elif [ "$COMP_DAY" -eq 1 ]; then
  doneok "fail2ban not running - comp-day posture already clean"
elif ask "install + enable fail2ban for sshd anyway? (NOT recommended; needs explicit opt-in)"; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban >> /var/tmp/cf-apt-upgrade-$TS.log 2>&1 \
      || flag "install failed - see log"
  fi
  if command -v fail2ban-client >/dev/null 2>&1; then
    cat > /etc/fail2ban/jail.local <<'EOF'
# CF precomp: sshd jail. BEFORE SCORING STARTS re-run this script with
# --comp-day (or systemctl disable --now fail2ban) - a banned IP may be a scorer.
[sshd]
enabled = true
maxretry = 6
findtime = 10m
bantime = 10m
EOF
    systemctl enable --now fail2ban >/dev/null 2>&1 \
      && { doneok "fail2ban installed (sshd jail, 10m bans)"; logfix "installed+enabled fail2ban sshd jail (jail.local)"; }
  fi
else
  doneok "skipped (recommended)"
fi

# ============ 7. SCORED-PORT SELF-CHECK + ICS STATUS ============
hdr "7. SCORED-PORT SELF-CHECK"
OSID=$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")
case "$OSID" in
  opensuse*)          REQ="22 80 3306 139 445";  BOX="Task (OpenSUSE Leap)";;
  ubuntu*)            REQ="22 502 8080";         BOX="PLC1 (Ubuntu 24)";;
  debian*)            REQ="22 1883 20000";       BOX="PLC2 (Debian 13)";;
  *)                  REQ="";                    BOX="unknown OS";;
esac
if [ -n "$REQ" ]; then
  item "Box: $BOX — required inbound: $REQ"
  for p in $REQ; do
    if ss -tlnH "( sport = :$p )" 2>/dev/null | grep -q .; then
      doneok "$p/tcp listening"
    else
      flag "$p/tcp NOT listening — scored service is DOWN"
      case "$BOX" in
        PLC1*) [ "$p" = "502" ] && warn "502 comes up AFTER the OpenPLC web UI (8080) 'Start PLC' button - go click it, then re-check";;
      esac
    fi
  done
else
  warn "unknown OS - run the machine-folder firewall-tuned.sh self-check instead"
fi
hdr "ICS SERVICES (status only — never stopped by script)"
for s in modbus openplc openplc-runtime openplc-proxy dnp3; do
  systemctl list-unit-files 2>/dev/null | grep -q "^$s\.service" || continue
  st=$(systemctl is-active "$s" 2>/dev/null)
  [ "$st" = "active" ] && doneok "$s.service active" || flag "$s.service state=$st"
done

echo
echo "=============== PRECOMP DONE ==============="
warn "Verify scored ports are green, copy $CHANGELOG lines into Security"
warn "Documentation (required by rules)."
warn "Take a fresh snapshot NOW (post-change state) - next revert gets you"
warn "back here, not to the pre-hardening image."
exit 0
