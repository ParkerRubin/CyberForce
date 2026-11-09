# HMI / CnC (Win Server 2019, 10.0.x.142) - ASSUME-BREACH, extreme caution
- TCP 8088  Ignition Gateway (blueteam:BlueTeam2026! default - rotate)
- TCP 3306  MySQL Data Historian (historian:CyberForce2026! - NEVER change)
Team: TCP 3389 RDP (NO SSH on this box - RDP is the only way in)
Red team is "already inside" by design. Do not block anything that touches scoring (8088/3306).
Prefer firewall-tuned.ps1 -ReportOnly here unless a specific filter is planned.
