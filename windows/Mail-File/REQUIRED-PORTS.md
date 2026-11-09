# Mail-File (Win Server 2019, 10.0.x.140) - required scored inbound
- TCP 25    SMTP
- TCP 1080  HFS (HTTP File Server)
- TCP 22    SSH (team)
Team access: TCP 3389 (RDP), 5985 (WinRM) - allowed unrestricted (no allow-lists in 2026)
Hardening roles here: local users, HFS app accounts, SMTP service, SMB shares
