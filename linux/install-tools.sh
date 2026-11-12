#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 - INSTALL TOOLS (Linux side)
# Stages portable run-on-demand tools. NO services installed.
# Run on each Linux box BEFORE comp day (Nov 2-13 prep window).
# Distro-detect: apt (Ubuntu/Debian) or zypper (OpenSUSE).
# Usage: sudo ./install-tools.sh
# ============================================================

set -u
if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: run as root (sudo $0)" >&2
  exit 1
fi

TOOLDIR="$HOME/cf-tools"
mkdir -p "$TOOLDIR"
echo "Tool dir: $TOOLDIR"

# ---------------- distro detect ----------------
PKG=""
if command -v apt-get >/dev/null 2>&1; then
  PKG="apt"
elif command -v zypper >/dev/null 2>&1; then
  PKG="zypper"
else
  echo "[!] No apt or zypper found - install manually: nmap tcpdump gpg curl" >&2
fi

install_pkgs() {
  case "$PKG" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -qq
      apt-get install -y -qq nmap tcpdump gnupg curl sshpass lsof 2>&1 | tail -3
      ;;
    zypper)
      zypper --non-interactive refresh 2>&1 | tail -2
      zypper --non-interactive install nmap tcpdump gpg2 curl sshpass lsof 2>&1 | tail -3
      ;;
  esac
}

echo "=== [1/3] system packages ==="
if [ -n "$PKG" ]; then
  install_pkgs
else
  echo "[skip] no package manager"
fi

for c in nmap tcpdump gpg curl sshpass; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "[ok  ] $c -> $(command -v $c)"
  else
    echo "[MISS] $c - install manually before comp day"
  fi
done

echo "=== [2/3] linpeas.sh ==="
if [ -f "$TOOLDIR/linpeas.sh" ]; then
  echo "[skip] linpeas.sh already staged"
else
  curl -fsSL -o "$TOOLDIR/linpeas.sh" \
    https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \
    && echo "[ok  ] linpeas.sh ($(stat -c%s "$TOOLDIR/linpeas.sh") bytes)" \
    || echo "[FAIL] linpeas download - manual: curl -o linpeas.sh https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
fi
chmod +x "$TOOLDIR/linpeas.sh" 2>/dev/null

echo "=== [3/3] integrity ==="
cd "$TOOLDIR" && sha256sum * 2>/dev/null

cat <<'EOF'

=== USAGE (run-on-demand, nothing installed) ===
  linpeas.sh -a > /dev/null       deep sweep (noisy, slow) - or:
  sudo ~/cf-tools/linpeas.sh -o cli  console-only quick pass
  nmap -sV -p 22,502,8080 127.0.0.1          self-scan localhost
  nmap -sn 10.0.x.0/24                       subnet discovery (from ONE box, light)
  tcpdump -i any -w cf.pcap -C 50 -W 6       ring pcap (assume-breach evidence)
  sshpass -p 'PASS' ssh user@host            scripted ssh once creds rotated
  ~/cf-tools/linpeas.sh -o cli | tee one-file.txt   if you must save output

NOTE: run linpeas/nmap during prep window or lulls, NOT during scoring runs.
EOF
