# PLC2 DNP3 (Debian 13, 10.0.x.143) - ASSUME-BREACH, extreme caution
- TCP 22     SSH (team)
- TCP 1883   MQTT (sensor feed from scoreboard)
- TCP 20000  DNP3
Red team is "already inside" by design. Do not block anything scored. This box is the
main Red attack-chain evidence source: auditd/logging worth more than firewall here.
Keep dnp3.service running: sudo systemctl restart dnp3.service
