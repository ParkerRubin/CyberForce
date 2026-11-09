# AD / DC (Win Server 2022, 10.0.x.141) - required scored inbound
- TCP 389   LDAP
- UDP 161   SNMP (smb scored via UDP - get this right at the prompt)
- TCP 22    SSH (team)
Also required for domain ops (do NOT remove): TCP 53,88,135,139,445,464,636,3268,3269 + 49152-65535 RPC; UDP 53,88,123,464
Team access: TCP 3389 (RDP), 5985 (WinRM)
Use firewall-tuned.ps1 or firewall-ad.ps1 in this folder - the generic base firewall has no DC baseline baked in.
