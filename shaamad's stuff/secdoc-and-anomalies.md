# Newly-mined CyberForce intel: Anomalies 101 + SecDoc rubric + trove status
**Mined:** Fri Nov 13 2026 · from `Downloads\cyberforce-2026\` (official repo — 40+ PDFs,
we had only mined 6; 8 more OCRed tonight, OCR text in `%TEMP%\cf2026\*.txt`)

## ANOMALIES (1,500 pts) — read before opening the USB Saturday
- Attempts SCALE WITH DIFFICULTY: trivia/easy anomalies = **ONE attempt only**.
  Treat every answer like it's your last try: spell it out, match the syntax hint
  in the question, then submit.
- **Syntax-sensitive, not case-sensitive** (case-sensitivity is always explicitly
  stated if it applies). Spelling, grammar, special characters count.
- Anomalies include **physical room clues** — flags posted around the venue. Some
  anomalies literally require getting up and looking around. Assign one walker.
- Anomalies also feed the Red team ("support the Red team with added exploits as
  needed") — clearing them early removes attacker help. Prioritize them high.
- Recommended tooling (official): Wireshark, NMAP, Steghide, Python. Plus our own:
  CyberChef, jwt.io, base64, `strings`, 7-Zip/gpg for the password-protected USB.
- Free practice: Conquer the Hill (cyberforce.energy.gov/conquer-the-hill/),
  picoCTF, HTB CTFs.
- NEVER attempt early access to the USB — penalties.

## SECDOC (Orange, 2,000 pts) — the annotated example IS the rubric
File name MUST include team ID; must NOT reference the college/university.
Five sections, scored Emerging < Developing < Proficient(3) < Exemplary(4):

1. **System summary — ≤250 words, for "senior leadership"** (plain English, define
   every acronym, state purpose + scope). Graded down for jargon and for any
   mismatch with the asset inventory.
2. **Asset inventory table** — every device by name + key attributes (type, OS,
   IP, service). **Must be consistent** with the diagram and the vulnerability
   list — cross-section consistency is explicitly graded.
3. **Network diagram** — all hosts, appliances, services, interconnections,
   internet gateway, VPN, subnet. **"A thorough hand-drawn diagram will score
   HIGHER than an incomplete Visio diagram."** Must include a LEGEND, correct IPs
   (duplicate IPs = automatic developing), matching every inventory entry.
   Logical/geographic layout must make sense.
4. **Vulnerability + mitigation table** — one row per unique vulnerability PER
   HOST (same vuln on 3 hosts = 3 rows). Include mitigations + any open/accepted
   risks ("accepting risk is acceptable" — mark 'to be mitigated next cycle').
   **22 rows was graded "not enough for proficient" — more thorough = higher.**
   Audience is senior leadership: summarize, don't paste raw scanner output.
   → Our persist-sweep/windows-sweep findings logs = direct source for rows.
5. **Hardening & defense procedures — ≤1,250 words + list the TOOLS USED** —
   describe what you did, with materials/tools listed and reasoning per step.
   Missing tools/materials per step = graded down. "Needs another hardening step
   to earn exemplary."

## 101-Library trove — mined vs unmined
- Mined tonight: Anomalies 101, Security Documentation 101, SecDoc Annotated
  Example, SecDoc Network Diagram Examples, ICS and Node-RED, Linux Hardening 101,
  Windows Hardening 101, Typical Services (all in `%TEMP%\cf2026\`).
- Linux/Windows Hardening 101: covers unwanted services, empty passwords, UID-0
  checks, sshd, password policy — **nothing our sweep scripts don't already do.**
- Still unmined (low priority, post-competition): Nmap 101, Nessus 101, JtR 101,
  Steganography 101, Wireshark 101, SQL/Command Injection 101, Encryption/RSA,
  Hashing, File Types, Databases, ICS Node-RED details, Intro to PowerShell/
  Windows/Linux, Networking 101, Linux Cheat Sheet, Useful Protocols, Green Team
  101, CTFs 101, CyberForce Competition 101, Base Tutorial, AWS EC2 101 pair,
  Mentor Agenda, Security Documentation Template.docx (the fill-in blank).
