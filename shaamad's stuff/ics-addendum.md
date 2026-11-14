# ICS addendum — deltas from Team23_ICS_Guide.pdf (Nov 13 findings)
*The PDF itself is the runbook — this file records only what's NEW or CONFIRMED
beyond our earlier brief, so the day-of binder stays short. Print the PDF too.*

## CONFIRMED / resolved
1. **Historian login: `historian / CyberForce2026!`** — the CyberForce2026! vs
   CyberForce2@26! discrepancy from the official docs is resolved in favor of
   CyberForce2026!. Team guide lists it as fact (used Nov 13). NEVER change it.
2. **modbus.service (PLC1) = the MQTT bridge** feeding scoreboard sensor data into
   the PLC. MQTT broker runs on PLC2:1883. Chain confirmed:
   Scoreboard MQTT → PLC2 broker:1883 → modbus.service → PLC1 OpenPLC → HMI.
   (Our earlier sketch had PLC1⇄PLC2 sideways; this is the real direction.)
3. OpenPLC settings page must have: Start PLC → Running, **Enable Modbus Server (502)**,
   **Start OpenPLC in RUN mode** → Save. Verify: `sudo ss -tlnp | grep -E ':502|:8080'`
4. Ignition devices: "Modbus Test" → 10.0.186.144, "DNP3 Test" → 10.0.186.143:20000,
   DNP3 source/master 16, outstation 4. Stuck CONNECTING fix: uncheck Enabled → save
   → re-check → save.
5. Rules-check: single-IP `sudo ufw deny from <IP>` = legal (attacker IPs only,
   never subnets/allow-lists, never scoreboard/HMI/scorer IPs). Guide is compliant.

## NEW finding: RADAR is probably PLC2/DNP3 (unconfirmed but Nov 13 evidence)
Radar Draw MW was LIVE while PLC1 was DOWN → the radar feed does not depend on
PLC1/Modbus. Tags in Ignition Designer: DNP3 / PowerOut, CoolingOutTemp.
**Implication: Blue points = TWO independent streams — geothermal (PLC1/Modbus)
and radar (PLC2/DNP3). Both PLC programs must run; a PLC1 outage does NOT kill
radar points. Check the HMI for each independently after any incident.**

## NEW: PLC2 persistence leads from Nov 13 (Assume Breach — DOCUMENT today, FIX comp day)
- **inetd.service** — check /etc/inetd.conf for shell services
- **PermitRootLogin without-password** in sshd_config → sweep /root/.ssh/authorized_keys
- **exim4 on localhost:25** — default install, not needed; comp-day decision
- Watch-only commands (no changes): `cat /etc/inetd.conf`,
  `sudo cat /root/.ssh/authorized_keys`, `systemctl status inetd exim4`,
  `journalctl -u dnp3.service --since today`

## Day-of watch loop (tmux on PLC1 or HMI)
`watch -n 5 "ss -tnp | grep -E ':502|:2000|:1883'"`
Expected talkers ONLY: HMI (10.0.186.142), scoreboard, MQTT bridge. Anything else
= ICS attack. Response order per guide: screenshot FIRST → `ufw deny from <IP>`
→ restart PLC program → change OpenPLC password (record it).

## Attack signatures (from guide, keep on the printed sheet)
- HMI switches/sliders move with nobody touching them
- Values jump to impossible numbers or freeze
- New connections to 502/2000/1883 from unknown IPs
- OpenPLC program changed/stopped (dashboard shows different program)
- Unknown accounts in OpenPLC or Ignition user lists

## Never-do list (match ours + 3 additions)
Guide adds: **no SSL on Ignition web / no port change on 8088**; **never click HMI
control switches "to test"**; **never run suspicious binaries on Assume Breach
boxes to see what they do**. Terminal showing garbage after cat'ing a binary:
`reset`.
