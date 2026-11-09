#!/usr/bin/env bash
# web-recon.sh -- CPTC web player's first 30 minutes on any target.
# Usage:   ./web-recon.sh <target-or-CIDR> [hostname]
# Example: ./web-recon.sh 10.10.20.15
#          ./web-recon.sh 10.10.20.0/24
#
# Everything lands in ./loot/<target>-<timestamp>/ so the report has evidence.

set -u
if [ $# -lt 1 ]; then
    echo "usage: $0 <target-or-CIDR> [hostname]"
    exit 1
fi

TARGET="$1"
HOSTNAME_ARG="${2:-}"
STAMP=$(date +%m%d-%H%M)
OUT="loot/${TARGET//\//_}-${STAMP}"
mkdir -p "$OUT"

# --- 0. SCOPE GUARD ---------------------------------------------------------
echo "[*] Target: $TARGET"
read -rp "  Is $TARGET inside the Rules of Engagement? (y/N) " OK
[ "$OK" != "y" ] && echo "[-] Not in scope. Stop here." && exit 1

has() { command -v "$1" >/dev/null 2>&1; }

# Small helper: only run a tool if it exists, else warn
run() { if has "$1"; then shift; "$@"; else echo "[!] '$1' not installed, skipping"; fi }

# --- 1. PORT SCAN: find every web.Surface port ------------------------------
# Web hides ports other than 80/443/8080 -- check top 1000 + common app ports.
echo "[*] [1/5] nmap: top 1000 ports, service-detect web ones..."
SITES="$OUT/sites.txt"
if has nmap; then
    # top 1000 covers 80/443/8080/8443/8000/8888 etc. -Pn so firewalled-but-up hosts still probe
    # -sT (connect scan): raw SYN (-sS) breaks behind WSL2 NAT/VPN adapters
    nmap -Pn -sT -sV --top-ports 1000 --open "$TARGET" -oN "$OUT/nmap-web.txt"
else
    echo "[!] nmap missing!"
    echo "http://$TARGET/" > "$SITES"
fi

# Build a list of base URLs (http://ip[:port]) from nmap output.
# nmap lines look like: "80/tcp   open  http    Apache"
SITES="$OUT/sites.txt"
: > "$SITES"
if has nmap && [ -s "$OUT/nmap-web.txt" ]; then
    awk '/[Ss]can report for/ {for(i=1;i<=NF;i++) if ($i ~ /^[0-9]+\./) host=$i}
         /^[0-9]+\/tcp/ && /open/ && ($0 ~ /http|ssl|www/) {port=$1; gsub("/.*","",port); print host, port}' \
        "$OUT/nmap-web.txt" | while read -r host port; do
        proto="http://"
        case "$port" in 443|8443|4433) proto="https://";; esac
        case "$port" in
            80|443) u="$proto$host";;
            *)      u="$proto$host:$port";;
        esac
        echo "$u"
    done | sort -u >> "$SITES"
    echo "[+] Open web-relevant ports:"
    grep -E '^[0-9]+/.*open' "$OUT/nmap-web.txt" | tee "$OUT/web-ports.txt" || true
fi
[ ! -s "$SITES" ] && echo "http://$TARGET" >> "$SITES"

echo "[*] Live web targets:"
cp "$SITES" "$OUT/urls.txt"
cat "$SITES"

# --- 2. FINGERPRINT: what app is this ---------------------------------------
echo "[*] [2/5] fingerprinting..."
for u in $(cat "$SITES"); do
    whatweb -a 3 "$u" 2>/dev/null | head -5 >> "$OUT/whatweb.txt" || \
        echo "[!] whatweb missing"
done
[ -f "$OUT/whatweb.txt" ] && cat "$OUT/whatweb.txt"

# --- 3. WAF CHECK: know if the target fights back -------------------------------
echo "[*] [3/6] WAF detection (wafw00f, ~2s per target)..."
if has wafw00f; then
    : > "$OUT/waf.txt"
    for u in $(cat "$SITES"); do
        wafw00f "$u" 2>/dev/null | grep -E 'is behind|seems to be|No WAF detected|Generic' \
            >> "$OUT/waf.txt" || true
    done
    [ -s "$OUT/waf.txt" ] && cat "$OUT/waf.txt" || echo "[i] no WAF entries (or nothing detected)"
else
    echo "[i] wafw00f not installed (install.sh adds it) — skipping WAF check"
fi

# --- 4. QUICK WINS: the free stuff ------------------------------------------
echo "[*] [4/6] checking classic exposures (git, env, robots, admin paths)..."
QUICK="robots.txt .git/HEAD .env .DS_Store server-status /admin /api /api/v1 \
/swagger /swagger.json /openapi.json /graphql /actuator /actuator/health \
/.htaccess /sitemap.xml /backup.zip /phpinfo.php"

for u in $(cat "$SITES"); do
    B="${u%/}"
    for path in robots.txt .git/HEAD .env server-status admin api api/v1 \
                swagger swagger.json openapi.json graphql actuator actuator/health \
                sitemap.xml .htaccess phpinfo.php; do
        CODE=$(curl -sk --max-time 4 -o /dev/null -w '%{http_code}' "$B/$path")
        case "$CODE" in
            200|301|302|401|403) echo "$CODE GET $B/$path" >> "$OUT/quick-wins.txt";;
        esac
    done
done

# exposed .git = full source dump — spell out the next move on the spot
if grep -qsE '^200 GET .*\.git/HEAD' "$OUT/quick-wins.txt"; then
    GITHOST=$(grep -E '^200 GET .*\.git/HEAD' "$OUT/quick-wins.txt" | head -1 | awk '{print $3}' | sed 's#/.git/HEAD##')
    echo "" >> "$OUT/quick-wins.txt"
    echo "EXPOSED .git ON $GITHOST — dump the whole repo, this is source + deleted files:" >> "$OUT/quick-wins.txt"
    echo "  git-dumper $GITHOST/.git/ $OUT/git-dump/" >> "$OUT/quick-wins.txt"
    echo "  then: grep -riE 'pass|key|secret|token|flag' $OUT/git-dump/ | head -50" >> "$OUT/quick-wins.txt"
    [ -s "$OUT/quick-wins.txt" ] && echo "[+] QUICK WINS FOUND:" && cat "$OUT/quick-wins.txt"
fi

# --- 5. DIRECTORY BRUTEFORCE -------------------------------------------------
echo "[*] [5/6] ffuf directory bust (small list, fast)..."
WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
[ -f "$WORDLIST" ] || WORDLIST="/usr/share/wordlists/dirb/common.txt"
if has ffuf && [ -s "$SITES" ]; then
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"
    [ -f "$WORDLIST" ] || WORDLIST="/usr/share/wordlists/dirb/common.txt"
    for u in $(cat "$SITES"); do
        u="${u%/}"
        fname="${u//http:\/\//}"
        fname="${fname//https:\/\//}"
        fname="${fname//\//_}"
        fname="${fname//:/_}"
        ffuf -mc 200,201,301,302,401,403 -w "$WORDLIST" -u "$u/FUZZ" \
             -t 30 -of md -o "$OUT/ffuf-${fname}.md" >/dev/null 2>&1
    done
fi
ls "$OUT"/ffuf-*.md 2>/dev/null || echo "[i] ffuf missing or no output"

# Human-readable roll-up of every ffuf run (raw .md kept as evidence)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-}")" && pwd)"
if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/testing/ffuf_pretty.py" ]; then
    python3 "$SCRIPT_DIR/testing/ffuf_pretty.py" "$OUT" 2>/dev/null || true
fi

# --- 6. KNOWN-VULN SCAN -------------------------------------------------------
echo "[*] [6/6] nuclei (templates: tech + cves + exposed things)..."
if has nuclei; then
    nuclei -l "$SITES" -severity low,medium,high,critical \
        -silent -o "$OUT/nuclei.txt"
else
    echo "[i] nuclei not installed — skip (check whatweb + quick-wins instead)"
fi

echo ""
echo "=============================================="
echo " DONE. Evidence in: $OUT/"
echo " Files:"
ls -1 "$OUT" 2>/dev/null | sed 's/^/  /'
echo ""
echo " NEXT (manual -- this is where the exploit lives):"
echo "  1. cat $OUT/nmap-web.txt   -> what web server? what app?"
echo "  2. curl the quick-wins     -> .git/? .env? api? (git-dumper cmd is written into quick-wins.txt)"
echo "  3. ffuf output             -> hidden admin panels, upload pages"
echo "  4. Open top 3 in browser, look at HTML source + JS files"
echo "  5. Screenshot EVERYTHING now. Future-you writing the report thanks you."
