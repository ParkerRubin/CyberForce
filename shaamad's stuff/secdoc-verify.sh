#!/bin/bash
# ============================================================
# secdoc-verify.sh — verify every fix promised in the Team23
# Security Documentation is still in place (and find anything
# that came back). Read-only. Run with sudo.
#   PASS = fix in place   FAIL = vuln present / fix missing
#   WARN  = manual check  [ -- ] = not applicable on this box
# Pair with persist-sweep.sh: that one is broad+baseline-diff,
# this one is the targeted re-check of documented vulns.
# ============================================================
set -u
CRIT=0; WARN=0
pass(){ printf '  [PASS] %s\n' "$1"; }
fail(){ printf '  [FAIL] %s\n' "$1"; CRIT=$((CRIT+1)); }
warn(){ printf '  [WARN] %s\n' "$1"; WARN=$((WARN+1)); }
na()  { printf '  [ -- ] %s (N/A on this box)\n' "$1"; }
hdr() { printf '\n== %s ==\n' "$1"; }

HOST=$(hostname)
case "$HOST" in
  *186-145*) BOX=task;;   *186-144*) BOX=plc1;;  *186-143*) BOX=plc2;;
  *186-142*) BOX=hmi;;    *186-141*) BOX=ad;;    *186-140*) BOX=mail;;
  *) BOX=other;;
esac
echo "secdoc-verify on $HOST (box=$BOX) $(date '+%F %T')"
[ "$(id -u)" -eq 0 ] || echo "[!] not root — several checks blind. sudo me."

# ---------- helpers used across checks ----------
NONPKG_UNITS=$(for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
  [ -e "$f" ] || continue; rpm -qf "$f" >/dev/null 2>&1 || echo "$f"; done 2>/dev/null)

echo "secdoc-verify on $HOST (box=$BOX) $(date '+%F %T')"
[ "$(id -u)" -eq 0 ] || echo "[!] not root — several checks blind. sudo me."
[ "$BOX" = "task" ] || echo "[!] this script is TASK-ONLY (your box). Other boxes: run the generic sweeps."

# ---------- helpers used across checks ----------
NONPKG_UNITS=$(for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
  [ -e "$f" ] || continue; rpm -qf "$f" >/dev/null 2>&1 || echo "$f"; done 2>/dev/null)
WW=/srv/www/vhosts/wordpress

# ---------- 1. rotation status (rows: default local creds, MySQL default creds) ----------
hdr "rotation (rows: default creds x2)"
HITS=$(grep -rl 'BlueTeam2026' /etc /srv/www /home/blueteam /opt/mysql 2>/dev/null | grep -vE 'cf-tools|evidence|\.log$' | head -6)
[ -n "$HITS" ] && warn "default password still referenced in: $(echo $HITS)" || pass "default password gone from box files"
[ -r "$WW/wp-config.php" ] && {
  grep -q 'BlueTeam2026' "$WW/wp-config.php" \
    && warn "wp-config.php still has default DB password (row: MySQL default creds)" \
    || pass "wp-config DB password rotated"; }

# ---------- 2. backdoor reinstallers (rows: 10-min + 2-sec services, immutable files) ----------
hdr "backdoor services + immutable files (rows: reinstalling services)"
BAD=""
for f in $NONPKG_UNITS; do
  exe=$(awk '/^\s*Exec/{print $2; exit}' "$f" 2>/dev/null)
  case "$exe" in */usr/bin/*|*/usr/sbin/*|*/bin/*|*/sbin/*|"") ;; *) BAD="$BAD $(basename $f)($exe)";; esac
done
[ -n "$BAD" ] && fail "non-package units with odd ExecStart:$BAD" || pass "no odd non-package units"
IM=$(lsattr -R /etc/systemd/system /usr/local/bin /usr/local/sbin /etc/cron.d 2>/dev/null | awk '$1 ~ /[ia]/ {print $NF}' | head -5)
[ -n "$IM" ] && fail "immutable/append files still present (deletion-proof): $(echo $IM)" || pass "no immutable files in key dirs"

# ---------- 3. web shell + uploads (rows: plugin shell, 2 upload shells, writable uploads) ----------
hdr "web shells + uploads (rows: 3 shells, writable uploads)"
UP=$(find "$WW/wp-content/uploads" -type f -name '*.php' 2>/dev/null)
[ -n "$UP" ] && fail "PHP in uploads: $(echo $UP)" || pass "no PHP in uploads"
EV=$(grep -rlE 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|str_rot13)|system[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|shell_exec[[:space:]]*\([[:space:]]*\$_' "$WW/wp-content" 2>/dev/null | grep -v '/evidence' | head -4)
[ -n "$EV" ] && fail "webshell-pattern PHP in wp-content: $(echo $EV)" || pass "no webshell patterns in wp-content"
WD=$(find "$WW/wp-content/uploads" -type d -perm /022 2>/dev/null | head -3)
[ -n "$WD" ] && fail "uploads dirs world-writable: $(echo $WD)" || pass "uploads not world-writable"

# ---------- 4. svc-backup account creator (row: cron added account 17,785x) ----------
hdr "svc-backup creator (row: hidden scheduled job)"
getent passwd svc-backup >/dev/null 2>&1 && fail "svc-backup account EXISTS" || pass "no svc-backup account"
CB=$(grep -riE 'svc-backup|useradd' /etc/cron* /var/spool/cron 2>/dev/null | grep -v '^\s*#' | head -3)
[ -n "$CB" ] && fail "scheduler still creates accounts: $(echo $CB)" || pass "schedulers clean"

# ---------- 5. port-45926 root shell + fake ls (rows: disk-tool backdoor, ls replaced) ----------
hdr "45926 shell + fake ls (rows: disk-tool backdoor, ls replaced)"
ss -H -tln "( sport = :45926 )" 2>/dev/null | grep -q . && fail "port 45926 LISTENING" || pass "45926 closed"
W=$(type -a ls 2>/dev/null | grep -v '/usr/bin/ls' | head -2)
[ -n "$W" ] && fail "ls is shadowed: $(echo $W)" || pass "ls resolves to /usr/bin/ls"

# ---------- 6. LAN-bridge keylogger + cfc-redteam key (rows: password stealer, attacker key) ----------
hdr "LAN-bridge + cfc-redteam key"
LB=$(grep -rliE 'lan.?bridge' /etc/systemd/system /usr/lib/systemd/system /etc/init.d /etc/ld.so.preload 2>/dev/null | head -3)
[ -n "$LB" ] && fail "LAN-bridge remnants: $(echo $LB)" || pass "no lan-bridge units"
RK=$(grep -rl 'cfc-redteam' /root/.ssh /home/*/.ssh 2>/dev/null)
[ -n "$RK" ] && fail "cfc-redteam key present in: $(echo $RK)" || pass "cfc-redteam key gone"
AK=$(find /root /home -name authorized_keys 2>/dev/null | head -5)
[ -n "$AK" ] && warn "authorized_keys exist — eyeball each: $(echo $AK)" || pass "no authorized_keys files"

# ---------- 7. sshd posture (rows: root login, X11, MaxAuthTries, tunneling) ----------
hdr "sshd posture (rows: root login / X11 / attempts / tunneling)"
T=$(sshd -T 2>/dev/null) || warn "sshd -T unavailable (run as root)"
echo "$T" | grep -qi 'permitrootlogin no' && pass "PermitRootLogin no" || fail "PermitRootLogin not 'no'"
echo "$T" | grep -qi 'x11forwarding no' && pass "X11 forwarding off" || fail "X11Forwarding on"
MT=$(echo "$T" | awk 'tolower($1)=="maxauthtries"{print $2}')
[ "$MT" = "3" ] && pass "MaxAuthTries = 3" || warn "MaxAuthTries=$MT (doc promised 3)"
echo "$T" | grep -qi 'allowtcpforwarding no' && pass "TCP forwarding off" || fail "tunneling still on"

# ---------- 8. cloud account + firewall (rows: ec2-user, no firewall) ----------
hdr "ec2-user + firewall (rows: cloud account, firewall off)"
if getent passwd ec2-user >/dev/null 2>&1; then
  S=$(passwd -S ec2-user 2>/dev/null | awk '{print $2}')
  [ "$S" = "L" ] && pass "ec2-user locked" || fail "ec2-user password status: $S (want L)"
  grep -rhs 'ec2-user' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' | grep -q . \
    && fail "ec2-user still has sudo" || pass "ec2-user has no sudo"
else pass "ec2-user absent"; fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --state >/dev/null 2>&1 && pass "firewalld running" || fail "firewalld NOT running"
  P=$(firewall-cmd --list-ports 2>/dev/null | tr ' ' '\n' | tr -d ',' | sort -u)
  echo "$P" | grep -vqE '^(22|80|139|445|3306)/tcp$|^$' && warn "extra open ports: $(echo $P | grep -vE '^(22|80|139|445|3306)/tcp$|^$')" || pass "firewall ports = required set"
elif command -v ufw >/dev/null 2>&1; then
  ufw status 2>/dev/null | grep -qi 'Status: active' && pass "ufw active" || fail "ufw NOT active"
else fail "no firewall tool found (firewalld/ufw)"; fi

# ---------- 9. database rows (score account, mysql shell) ----------
hdr "database (rows: extra 'score' acct, mysql service login)"
if command -v mysql >/dev/null 2>&1; then
  SC=$(mysql -N -e "SELECT CONCAT(user,'@',host) FROM mysql.user WHERE user='score'" 2>/dev/null)
  [ -n "$SC" ] && fail "extra 'score' DB account still exists: $SC" || pass "extra 'score' account gone"
  SH=$(getent passwd mysql 2>/dev/null | awk -F: '{print $NF}')
  case "$SH" in */nologin|*/false|*"") pass "mysql account has no login shell ($SH)";; *) warn "mysql shell: $SH";; esac
else warn "mysql client not on PATH — verify rows manually at /opt/mysql"; fi
grep -rhsE '(score1|score2)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^\s*#' | grep -q . \
  && warn "OPEN row confirmed: scoring accounts have sudo (rules-protected — monitor logins)" \
  || pass "scoring accounts have no sudo (their row stays open for DB grants only)"

# ---------- 10. web version + credentials.zip (rows: version banner, creds zip) ----------
hdr "info disclosure + leftover creds"
ST=$(grep -rhs 'ServerTokens' /etc/apache2/httpd.conf /etc/apache2/*.conf /etc/apache2/conf.d/*.conf 2>/dev/null | grep -v '^\s*#' | tail -1)
case "$ST" in *Prod*|*ServerTokens[[:space:]]+Prod*) pass "ServerTokens Prod";; *) warn "ServerTokens: ${ST:-not found} (doc promised hidden version)";; esac
grep -rhs 'ServerSignature' /etc/apache2/*.conf /etc/apache2/conf.d/*.conf 2>/dev/null | grep -v '^\s*#' | grep -qi 'off' \
  && pass "ServerSignature off" || warn "ServerSignature not 'off'"
CZ=$(find /home /root -name 'credentials.zip' 2>/dev/null)
[ -n "$CZ" ] && fail "credentials.zip still present: $(echo $CZ)" || pass "credentials.zip gone"

# ---------- summary ----------
echo
echo "=============== RESULT: $CRIT fail / $WARN warn ==============="
[ $CRIT -gt 0 ] && echo "FAILs = SecDoc promises not currently true. Fix + flip the row to past tense. Re-run after."
exit $CRIT


