# Authentication log triage report

- **Source file:** `data/sample_auth.log`
- **Generated:** 2026-11-26 11:34
- **Log window:** 2026-01-06 08:29 to 2026-01-09 17:32
- **Events parsed:** 44 (26 failures, 18 successful logins)
- **Source IPs:** 6 | **Accounts touched:** 10
- **Findings:** 1 critical, 2 high, 2 medium, 2 low

## Summary of findings

| Severity | Rule | Source IP | Events | Accounts | Window |
|---|---|---|---|---|---|
| CRITICAL | success_after_failure | `203.0.113.45` | 13 | 1 | 01-07 02:10 -> 01-07 02:14 |
| HIGH | brute_force | `203.0.113.45` | 12 | 1 | 01-07 02:10 -> 01-07 02:13 |
| HIGH | spraying | `198.51.100.7` | 6 | 6 | 01-08 09:05 -> 01-08 09:25 |
| MEDIUM | root_targeting | `192.0.2.99` | 7 | 2 | 01-08 21:30 -> 01-08 22:15 |
| MEDIUM | root_targeting | `198.51.100.7` | 6 | 5 | 01-08 09:05 -> 01-08 09:25 |
| LOW | off_hours | `10.0.0.42` | 1 | 1 | 01-09 03:12 -> 01-09 03:12 |
| LOW | off_hours | `203.0.113.45` | 1 | 1 | 01-07 02:14 -> 01-07 02:14 |

## Detail

### CRITICAL - Successful login after failures (ncancino)

- **Source IP:** `203.0.113.45`
- **Accounts involved:** ncancino
- **Events:** 13 over 4.0 minutes
- **Window:** 2026-01-07 02:10:00 to 2026-01-07 02:14:00
- **MITRE ATT&CK:** T1078 - Valid Accounts
- **NIST CSF:** RS.AN-03 - Analysis of incident

User 'ncancino' authenticated successfully from 203.0.113.45 after 12 failed attempts from the same address. Treat as possible account compromise.

Evidence (latest lines):

```
Jan  7 02:12:42 web01 sshd[2026]: Failed password for ncancino from 203.0.113.45 port 51009 ssh2
Jan  7 02:13:00 web01 sshd[2027]: Failed password for ncancino from 203.0.113.45 port 51010 ssh2
Jan  7 02:13:18 web01 sshd[2028]: Failed password for ncancino from 203.0.113.45 port 51011 ssh2
Jan  7 02:14:00 web01 sshd[2029]: Accepted password for ncancino from 203.0.113.45 port 51240 ssh2
```

### HIGH - Brute force against 'ncancino'

- **Source IP:** `203.0.113.45`
- **Accounts involved:** ncancino
- **Events:** 12 over 3.3 minutes
- **Window:** 2026-01-07 02:10:00 to 2026-01-07 02:13:18
- **MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing
- **NIST CSF:** DE.AE-02 - Adverse event analysis

12 failed authentications for user 'ncancino' from 203.0.113.45 within 10 minutes (threshold: 5).

Evidence (latest lines):

```
Jan  7 02:12:24 web01 sshd[2025]: Failed password for ncancino from 203.0.113.45 port 51008 ssh2
Jan  7 02:12:42 web01 sshd[2026]: Failed password for ncancino from 203.0.113.45 port 51009 ssh2
Jan  7 02:13:00 web01 sshd[2027]: Failed password for ncancino from 203.0.113.45 port 51010 ssh2
Jan  7 02:13:18 web01 sshd[2028]: Failed password for ncancino from 203.0.113.45 port 51011 ssh2
```

### HIGH - Password spraying

- **Source IP:** `198.51.100.7`
- **Accounts involved:** admin, jperez, dmunoz, mgonzalez, test, oracle
- **Events:** 6 over 20.0 minutes
- **Window:** 2026-01-08 09:05:00 to 2026-01-08 09:25:00
- **MITRE ATT&CK:** T1110.003 - Brute Force: Password Spraying
- **NIST CSF:** DE.AE-02 - Adverse event analysis

6 failed authentications against 6 distinct users from 198.51.100.7 within 30 minutes (threshold: 3 users).

Evidence (latest lines):

```
Jan  8 09:13:00 web01 sshd[2032]: Failed password for invalid user dmunoz from 198.51.100.7 port 33002 ssh2
Jan  8 09:17:00 web01 sshd[2033]: Failed password for invalid user mgonzalez from 198.51.100.7 port 33003 ssh2
Jan  8 09:21:00 web01 sshd[2034]: Failed password for invalid user test from 198.51.100.7 port 33004 ssh2
Jan  8 09:25:00 web01 sshd[2035]: Failed password for invalid user oracle from 198.51.100.7 port 33005 ssh2
```

### MEDIUM - Privileged / non-existent account enumeration

- **Source IP:** `192.0.2.99`
- **Accounts involved:** root, administrator
- **Events:** 7 over 45.0 minutes
- **Window:** 2026-01-08 21:30:00 to 2026-01-08 22:15:00
- **MITRE ATT&CK:** T1078.003 - Valid Accounts: Local Accounts
- **NIST CSF:** DE.CM-01 - Network monitoring

7 failed attempts from 192.0.2.99 against privileged or invalid accounts (threshold: 3).

Evidence (latest lines):

```
Jan  8 21:37:00 web01 sshd[2037]: Failed password for root from 192.0.2.99 port 60001 ssh2
Jan  8 21:44:00 web01 sshd[2038]: Failed password for root from 192.0.2.99 port 60002 ssh2
Jan  8 21:51:00 web01 sshd[2039]: Failed password for root from 192.0.2.99 port 60003 ssh2
Jan  8 21:58:00 web01 sshd[2040]: Failed password for root from 192.0.2.99 port 60004 ssh2
```

### MEDIUM - Privileged / non-existent account enumeration

- **Source IP:** `198.51.100.7`
- **Accounts involved:** admin, jperez, dmunoz, mgonzalez, test
- **Events:** 6 over 20.0 minutes
- **Window:** 2026-01-08 09:05:00 to 2026-01-08 09:25:00
- **MITRE ATT&CK:** T1078.003 - Valid Accounts: Local Accounts
- **NIST CSF:** DE.CM-01 - Network monitoring

6 failed attempts from 198.51.100.7 against privileged or invalid accounts (threshold: 3).

Evidence (latest lines):

```
Jan  8 09:09:00 web01 sshd[2031]: Failed password for invalid user jperez from 198.51.100.7 port 33001 ssh2
Jan  8 09:13:00 web01 sshd[2032]: Failed password for invalid user dmunoz from 198.51.100.7 port 33002 ssh2
Jan  8 09:17:00 web01 sshd[2033]: Failed password for invalid user mgonzalez from 198.51.100.7 port 33003 ssh2
Jan  8 09:21:00 web01 sshd[2034]: Failed password for invalid user test from 198.51.100.7 port 33004 ssh2
```

### LOW - Off-hours login (svc_deploy)

- **Source IP:** `10.0.0.42`
- **Accounts involved:** svc_deploy
- **Events:** 1 over 0.0 minutes
- **Window:** 2026-01-09 03:12:00 to 2026-01-09 03:12:00
- **MITRE ATT&CK:** T1078 - Valid Accounts
- **NIST CSF:** DE.CM-01 - Network monitoring

Successful login by 'svc_deploy' from 10.0.0.42 at 03:12, outside the 07:00-20:00 window.

Evidence (latest lines):

```
Jan  9 03:12:00 web01 sshd[2043]: Accepted password for svc_deploy from 10.0.0.42 port 47011 ssh2
```

### LOW - Off-hours login (ncancino)

- **Source IP:** `203.0.113.45`
- **Accounts involved:** ncancino
- **Events:** 1 over 0.0 minutes
- **Window:** 2026-01-07 02:14:00 to 2026-01-07 02:14:00
- **MITRE ATT&CK:** T1078 - Valid Accounts
- **NIST CSF:** DE.CM-01 - Network monitoring

Successful login by 'ncancino' from 203.0.113.45 at 02:14, outside the 07:00-20:00 window.

Evidence (latest lines):

```
Jan  7 02:14:00 web01 sshd[2029]: Accepted password for ncancino from 203.0.113.45 port 51240 ssh2
```

## Recommended actions

1. Treat the affected account as compromised: reset credentials, revoke sessions and review what happened after the successful login.
1. Block or rate-limit the source addresses at the firewall and enable fail2ban-style lockouts for the targeted accounts.
1. Confirm that direct root login over SSH is disabled (PermitRootLogin no) and that only key-based authentication is accepted.
1. Validate off-hours logins with the account owners before closing the ticket; silent agreement from the user is a weak but useful signal.

---

*Generated by [authwatch](https://github.com/NicoLucian/authwatch) - detection rules, thresholds and mapping are documented in `docs/detections.md`.*
