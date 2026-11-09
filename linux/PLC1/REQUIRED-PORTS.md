# PLC1 Modbus (Ubuntu 24, 10.0.x.144) - required scored inbound
- TCP 22    SSH (team)
- TCP 502   Modbus (must stay: feeds geothermal/radar ICS score)
- TCP 8080  OpenPLC web UI (openplc:openplc default - rotate)
Keep modbus.service running: sudo systemctl restart modbus.service
