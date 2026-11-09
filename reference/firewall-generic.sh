#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 - FIREWALL (generic, interactive) - LINUX
# Base firewall for the three Linux boxes (Task, PLC1, PLC2).
# Per-machine tuned versions with baked ports live in
# ./MachineName/firewall-tuned.sh - use this one for manual control.
#
# RULES OF PLAY (2026 - broken rules = lost points):
#   * NO allow-lists, NO subnet/CIDR blocks. Individual IP blocks
#     only if ever needed.
#   * Scoreboard + Red team must be able to reach scored ports,
#     especially on assume-breach PLC2 - do not block anything there.
#   * Every change goes into Security Documentation (due Nov 9).
# Run with sudo.
# ============================================================
set -u

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run with sudo (sudo bash firewall.sh)" >&2
  exit 1
fi

echo
echo "=== REQUIRED SCORED INBOUND PORTS BY MACHINE (type the ones for THIS box) ==="
echo " Task (OpenSUSE 10.0.x.145): TCP 22 (SSH), 80 (HTTP), 3306 (MySQL), 139,445 (SMB)"
echo " PLC1 (Ubuntu 24 10.0.x.144): TCP 22 (SSH), 502 (Modbus), 8080 (OpenPLC UI)"
echo " PLC2 (Debian 13 10.0.x.143 ASSUME-BREACH): TCP 22 (SSH), 1883 (MQTT), 20000 (DNP3)"
echo " NOTE: PLC2 - blocking anything risks Red/ICS points; prefer logging only."
echo

echo "Choose system hostname tag (free text, e.g. Task):"
read -rp "Box name (blank=unnamed): " BOX
BOX=${BOX:-UnnamedBox}
TS=$(date +%Y%m%d-%H%M%S)
BACKUP="$HOME/cf-firewall-backup-${BOX}-$TS.txt"

( ufw status verbose 2>/dev/null || true
  firewall-cmd --list-all-zones 2>/dev/null || true ) > "$BACKUP"
echo "Backup of current config: $BACKUP"

read -rp "Extra ALLOW inbound TCP ports, comma-separated (blank=none): " etcp
read -rp "Extra ALLOW inbound UDP ports, comma-separated (blank=none): " eudp
ALLOW_TCP=$(echo "$etcp" | tr -d ' ' | tr ',' ' ' | tr -s ' ')
ALLOW_UDP=$(echo "$eudp" | tr -d ' ' | tr ',' ' ' | tr -s ' ')

# Always keep SSH 22 or you may cut yourself out mid-session
case " $ALLOW_TCP " in *" 22 "*) ;; *) echo "Adding 22/tcp (SSH) automatically so you cannot lock yourself out." ; ALLOW_TCP="22 $ALLOW_TCP" ;; esac

USE=""
if command -v ufw >/dev/null 2>&1; then USE="ufw"
elif command -v firewall-cmd >/dev/null 2>&1; then USE="firewalld"
else
  echo "Neither ufw nor firewalld found."
  echo "Ubuntu/Debian: apt-get install -y ufw   |   OpenSUSE: zypper install firewalld"
  echo "Then re-run this script."
  exit 1
fi
echo "Firewall tool: $USE"
read -rp "Proceed: block all inbound, allow ONLY $ALLOW_TCP / $ALLOW_UDP ? [y/N] " go
[[ $go =~ ^[Yy] ]] || { echo "Aborted."; exit 1; }

if [[ $USE == "ufw" ]]; then
  ufw --force reset >/dev/null
  ufw default deny incoming
  ufw default allow outgoing
  for p in $ALLOW_TCP; do ufw allow "$p/tcp" >/dev/null && echo "  allowed $p/tcp"; done
  for p in $ALLOW_UDP; do ufw allow "$p/udp" >/dev/null && echo "  allowed $p/udp"; done
  ufw --force enable
  echo; echo "=== RESULT ==="; ufw status verbose
else
  systemctl enable --now firewalld >/dev/null 2>&1 || true
  ZONE=$(firewall-cmd --get-default-zone)
  echo "Operating on zone: $ZONE"
  for s in $(firewall-cmd --permanent --zone="$ZONE" --list-services); do
    firewall-cmd --permanent --zone="$ZONE" --remove-service="$s" >/dev/null
  done
  for p in $(firewall-cmd --permanent --zone="$ZONE" --list-ports); do
    firewall-cmd --permanent --zone="$ZONE" --remove-port="$p" >/dev/null
  done
  for p in $ALLOW_TCP; do firewall-cmd --permanent --zone="$ZONE" --add-port="$p/tcp" >/dev/null && echo "  allowed $p/tcp"; done
  for p in $ALLOW_UDP; do firewall-cmd --permanent --zone="$ZONE" --add-port="$p/udp" >/dev/null && echo "  allowed $p/udp"; done
  firewall-cmd --reload
  echo; echo "=== RESULT ==="; firewall-cmd --zone="$ZONE" --list-all
fi

echo
echo "=== SELF-CHECK: ports typed actually listening? ==="
for p in $ALLOW_TCP; do
  if ss -tlnH "( sport = :$p )" 2>/dev/null | grep -q .; then echo "  OK    $p/tcp listening"
  else echo "  MISS  $p/tcp NOT listening"; fi
done
for p in $ALLOW_UDP; do
  if ss -ulnH "( sport = :$p )" 2>/dev/null | grep -q .; then echo "  OK    $p/udp listening"
  else echo "  MISS  $p/udp NOT listening (scored UDP ports: SNMP 161 on the AD box only)"; fi
done
echo
echo "Rollback file: $BACKUP  |  emergency: ufw disable / firewall-cmd --panic off"
echo "Record this change in Security Documentation."
