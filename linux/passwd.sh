#!/usr/bin/env bash
# ============================================================
# CYBERFORCE 2026 — RESET PASSWORDS (passwd.sh)
# Resets the password for every human user with a valid login
# shell, generating a random 4-word passphrase + "123!".
# Example: "HotelCyberWolfMoon123!"
#
# Output is saved like rotate-creds.sh:
#   timestamped credfile in $HOME (root's home), chmod 600.
#
# NEVER touch: score1, score2, patch, historian, green-user, green-admin,
# root, openplc, modbus, dnp3 (scoring/Green Team/ICS service accounts).
# Match is CASE-INSENSITIVE on purpose - Linux accounts are usually lowercase.
# Override with: PROTECTED='...' sudo bash passwd.sh
# ============================================================
set -eu

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run with sudo (sudo bash passwd.sh)" >&2
  exit 1
fi

PROTECTED="${PROTECTED:-score1|score2|patch|historian|green-user|green-admin|root|openplc|modbus|dnp3}"
TS=$(date +%Y%m%d-%H%M%S)
CREDFILE="$HOME/passwd-creds-$TS.txt"
touch "$CREDFILE" && chmod 600 "$CREDFILE"

log() { echo "$1" | tee -a "$CREDFILE"; }

# A massive list of simple, easy-to-type words
WORDS=(
  # NATO / Phonetic
  "Alpha" "Bravo" "Charlie" "Delta" "Echo" "Foxtrot" "Golf" "Hotel"
  "India" "Juliet" "Kilo" "Lima" "Mike" "November" "Oscar" "Papa"
  "Quebec" "Romeo" "Sierra" "Tango" "Uniform" "Victor" "Whiskey" "Xray"
  "Yankee" "Zulu"
  # Colors
  "Red" "Blue" "Green" "Black" "White" "Gold" "Silver" "Pink" "Cyan"
  "Teal" "Gray" "Brown" "Azure" "Coral" "Ivory" "Onyx" "Ruby" "Jade"
  # Animals
  "Lion" "Tiger" "Bear" "Wolf" "Eagle" "Hawk" "Shark" "Whale" "Cobra"
  "Fox" "Cat" "Dog" "Owl" "Crow" "Deer" "Elk" "Seal" "Crab" "Frog"
  "Duck" "Swan" "Goat" "Lamb" "Puma" "Lynx" "Wasp" "Bee" "Ant"
  # Space & Science
  "Moon" "Sun" "Star" "Mars" "Earth" "Comet" "Orbit" "Space" "Rocket"
  "Nova" "Void" "Atom" "Ion" "Volt" "Watt" "Flux" "Core" "Neon" "Zinc"
  "Iron" "Lead" "Acid" "Base" "Wave" "Beam" "Ray" "Dust" "Gas"
  # Tech
  "Cyber" "Logic" "Data" "Code" "Linux" "Admin" "User" "Host"
  "Byte" "Bit" "Node" "Grid" "Link" "Net" "Web" "Wifi" "Disk" "File"
  "Java" "Perl" "Rust" "Bash" "Shell" "Kern" "Boot" "Load"
  # Nature
  "River" "Lake" "Pond" "Sea" "Ocean" "Rain" "Wind" "Snow" "Ice" "Fire"
  "Sand" "Rock" "Tree" "Leaf" "Rose" "Lily" "Fern" "Moss" "Hill"
  "Peak" "Cliff" "Cave" "Dune" "Reef" "Tide" "Storm" "Hail" "Mist"
  # Food
  "Apple" "Mango" "Lemon" "Berry" "Grape" "Melon" "Peach" "Plum" "Pear"
  "Lime" "Kiwi" "Fig" "Date" "Corn" "Rice" "Bean" "Cake" "Pie"
  "Taco" "Pizza" "Soda" "Tea" "Milk" "Soup" "Beef" "Pork" "Fish" "Salt"
  # Objects
  "Book" "Desk" "Lamp" "Pen" "Door" "Wall" "Roof" "Key" "Lock" "Box"
  "Bag" "Map" "Flag" "Ship" "Car" "Bus" "Train" "Jet" "Bike" "Clock"
  "Watch" "Ring" "Coin" "Cash" "Card" "Wire" "Cord" "Pipe" "Tube" "Gear"
  # Verbs / Actions
  "Run" "Walk" "Jump" "Fly" "Swim" "Dive" "Hide" "Seek" "Find" "Lost"
  "Keep" "Give" "Take" "Make" "Fix" "Cut" "Push" "Pull" "Lift" "Drop"
  # Adjectives
  "Fast" "Slow" "High" "Low" "Hard" "Soft" "Loud" "Quiet" "Hot" "Cold"
  "Big" "Small" "Tall" "Short" "Wide" "Deep" "Rich" "Poor" "Good" "Bad"
  "New" "Old" "True" "False" "Real" "Safe" "Wild" "Calm" "Brave" "Wise"
)

log "== passwd.sh — password reset — $TS =="
log "Protected (skipped): $PROTECTED"
log ""
log "USER,PASSWORD"

# Loop through users with a login shell, skipping protected accounts
skipped=""
for u in $(getent passwd | awk -F: '$7 ~ /(bash|sh|zsh)$/ {print $1}'); do
  if echo "$u" | grep -Eqi "^($PROTECTED)$"; then
    skipped="$skipped $u"
    continue
  fi

  # 1. Pick 4 random words
  W1=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
  W2=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
  W3=${WORDS[$((RANDOM % ${#WORDS[@]}))]}
  W4=${WORDS[$((RANDOM % ${#WORDS[@]}))]}

  # 2. Combine with the hardcoded "123!" suffix
  NEW_PASS="${W1}${W2}${W3}${W4}123!"

  # Change the password and record it in the credfile
  echo "$u:$NEW_PASS" | chpasswd
  log "$u,$NEW_PASS"
done

log ""
[[ -n $skipped ]] && log "SKIPPED (protected):$skipped"
log "=== DONE. Creds saved in: $CREDFILE (chmod 600) ==="
