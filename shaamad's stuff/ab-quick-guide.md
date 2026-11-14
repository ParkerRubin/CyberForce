# AB Quick Guide — PLC2 (.143) + HMI (.142)

Assume-Breach boxes. **Monitor + document only.** Fixes ONLY if organizers
confirm permissible in writing (ticket submitted — check Discord/ticket reply
before changing anything). Everything here is read-only.

## The golden rules (AB boxes)

- **Never stop** `dnp3.service`, `modbus.service`, or OpenPLC on either box —
  the radar/grid scoring depends on those streams staying up.
- No hostname/IP changes, no firewall edits, no service restarts.
- Never touch `score1`/`score2`/`patch` accounts anywhere.
- Any change we DO make (if approved): one reversible change at a time, log it,
  verify the ICS stream still flows, re-verify in 15 min.
- **After any incident on PLC2, check BOTH streams** — radar = PLC2/DNP3 is
  independent of PLC1/Modbus (ICS addendum). An incident on one box can take
  down its stream and your Green points silently.

## First 30 minutes on each box (baseline = evidence)

1. Baseline everything with timestamps — this IS the deliverable:
   - PLC2: `sudo ./persist-sweep.sh --log` (auto-detects Debian AB → prints
     monitor-only posture; the baseline it writes under `/var/tmp/persist-sweep`
     still works as a tripwire baseline).
   - HMI: `powershell -ExecutionPolicy Bypass -File .\windows-sweep.ps1` +
     Marco's `inbound rule audit.ps1` + `audit outbound.ps1` (both read-only,
     safe on any Windows box).
2. Save the console output to a dated file (`YYYYMMDD-HHMM-<box>.txt`) —
   SecDoc wants the before/after.
3. Log a change-log line even for "observed, no action":
   `HH:MM <box> <finding> -> no action (AB monitor-only)`

## Cadence (every 30–60 min, or right after any red contact)

- PLC2: re-run `persist-sweep.sh` — anything NEW vs baseline = red movement.
  Diff → change-log line → note for SecDoc.
- HMI: re-run `windows-sweep.ps1` — new services = CRIT, flaps = WARN.
- Check the ICS streams still alive (see commands below).

## PLC2 (10.0.186.143, Debian, DNP3 + MQTT) — known state

From the Team23 AB findings handout (8 findings) + our cross-box analysis:

- **Persistence leads already documented**: `inetd.conf` entries, `/root/.ssh`
  content, `exim4` involvement. Do NOT clean these (AB = leave the crime
  scene); just re-check them each sweep for ADDED entries.
- **The cross-box chain (already handled on Task)**: PLC2 held
  `/etc/shadow.old` with old SHA-512 hashes for `l.parker`, `sean.hughes`,
  `theo.banks` — password reuse into Task. Those 3 accounts are `nologin` on
  the Task box already. If the hashes change on PLC2, re-check Task.
- **MQTT baseline (known-good)**: PLC2 talks to scoreboard `192.168.0.41` and
  bridges to PLC1 `10.0.186.144`. Watch for NEW MQTT peers:
  ```bash
  sudo ss -tnp | grep ':1883'
  ```
  New remote IP in that output = new MQTT peer → change-log + SecDoc line.
- **DNP3 stream check** (port 20000 — listening + established peers):
  ```bash
  sudo ss -tnp | grep ':20000'
  systemctl is-active dnp3.service   # observe only — never restart it
  ```
- Extra quick reads (all read-only):
  ```bash
  sudo cat /etc/inetd.conf 2>/dev/null        # diff by eye vs baseline
  sudo ls -la /root/.ssh/                     # new keys?
  sudo ls -la /etc/shadow*                    # new shadow copies?
  ps aux --sort=-%cpu | head -15              # odd CPU hogs
  ```

## HMI (10.0.186.142, Windows) — UNEXAMINED, red foothold expected

Nobody has walked this box yet — expect pre-existing red persistence. First
hour (all read-only):

1. `windows-sweep.ps1` baseline (saves under `HKLM:\ProgramData\winsweep`).
2. Marco's audits: `verify hardening.ps1` (read-only everywhere), `inbound
   rule audit.ps1`, `audit outbound.ps1`. Do NOT run the lockdown or
   group-purge scripts here — their port matrix is the Mail/File box, and
   AB rules forbid changes anyway.
3. Parker's `win-vulnscan.ps1` for the persistence sweep (accounts, tasks,
   Run keys, listeners, creds).
4. Manual eyeball, screenshot anything odd:
   - `Get-ScheduledTask | ? Author -notmatch Microsoft` (rogue tasks)
   - Startup folders + Run keys, `netstat -abno`, `tasklist /svc`
   - `C:\Windows\System32\drivers\etc\hosts`
   - Downloads/Desktop/Documents of the logged-in user
5. **Expect the findings, don't fix them.** Documented persistence = SecDoc
   vulnerability rows + potential Orange/anomaly credit.

## Evidence → SecDoc pipeline

- Every sweep diff + every observation = a change-log line with HH:MM.
- Screenshots before/after any incident on either box (time-stamped console).
- AB findings feed: SecDoc vulnerability rows (detection narrative), the
  anomaly writeup (if we caught red in the act), and Orange (detect +
  document + communicate).
- The Team23 findings PDF (`Team23_AssumeBreach_Findings.pdf`, 8 PLC2 rows)
  is the starting vulnerability table for PLC2 — HMI's table starts empty
  until we walk it.

## Snapshot reminder

Snapshots are ALLOWED on AB boxes (2/hr per VM, exact naming convention or
−150). Take one right after your baseline — it's your timestamped proof the
state was X when you arrived.
