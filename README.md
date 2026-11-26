# authwatch

**Triage Linux authentication logs from the terminal.** One log file in, ranked findings out, each one mapped to MITRE ATT&CK and NIST CSF so the result can go straight into a ticket.

[![tests](https://github.com/NicoLucian/authwatch/actions/workflows/tests.yml/badge.svg)](https://github.com/NicoLucian/authwatch/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

---

## Why this exists

Every internet-facing SSH server collects thousands of failed logins a day. Almost nobody reads them, because `grep "Failed password" auth.log` returns a wall of noise and says nothing about which source deserves attention.

The first real task in a SOC or an IT support desk is exactly that judgement call: **is this background noise, or is this an incident I have to escalate?** `authwatch` automates the mechanical part — parse, group, threshold, rank — and produces a report that answers three questions in order: what happened, how bad it is, and what to do next.

It is deliberately small. No agent, no database, no SIEM licence. One Python file set, one log file, one report.

## What it does

- Parses `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS) and `journalctl --output=short-iso` exports, ignoring everything that is not authentication.
- Applies five explainable detection rules: brute force, password spraying, successful login after failures, privileged-account targeting and off-hours logins.
- Ranks findings by severity and writes them as a console summary, a Markdown incident report or JSON.
- Returns a meaningful exit code (`--fail-on`), so it can gate a cron job or a CI pipeline.
- **Zero third-party dependencies** — standard library only. It runs on any machine with Python 3.9+, including a jump host where you cannot install anything.

## Quickstart

```bash
git clone https://github.com/NicoLucian/authwatch.git
cd authwatch

# console triage summary
python -m authwatch.cli data/sample_auth.log --year 2026

# incident report you can attach to a ticket
python -m authwatch.cli data/sample_auth.log --year 2026 --format md --out reports/incident.md

# machine-readable output for a pipeline
python -m authwatch.cli data/sample_auth.log --year 2026 --format json
```

Analysing a real machine:

```bash
sudo journalctl --output=short-iso -u ssh > /tmp/ssh.log
python -m authwatch.cli /tmp/ssh.log
```

## Sample output

Real output from the bundled sample log ([`data/sample_auth.log`](data/sample_auth.log), synthetic, RFC 5737 addresses):

```text
authwatch - authentication log triage
==============================================================
Window   : 2026-01-06 08:29 -> 2026-01-09 17:32
Events   : 44 parsed | 26 failures | 18 successes
Entities : 6 source IPs | 10 accounts
Findings : 7 (1 critical, 2 high, 2 medium, 2 low)

SEVERITY   IP                 COUNT  RULE / TARGET
--------------------------------------------------------------
[CRITICAL] 203.0.113.45          13  success_after_failure -> ncancino
[HIGH]     203.0.113.45          12  brute_force -> ncancino
[HIGH]     198.51.100.7           6  spraying -> admin, jperez, dmunoz (+3)
[MEDIUM]   192.0.2.99             7  root_targeting -> root, administrator
[MEDIUM]   198.51.100.7           6  root_targeting -> admin, jperez, dmunoz (+2)
[LOW]      10.0.0.42              1  off_hours -> svc_deploy
[LOW]      203.0.113.45           1  off_hours -> ncancino

Top offending sources:
  203.0.113.45       13 failed authentications
  192.0.2.99         7 failed authentications
  198.51.100.7       6 failed authentications
```

The Markdown output goes further: it adds the evidence lines, the ATT&CK technique, the NIST CSF function and a recommendation per finding. A full example is committed at [`reports/sample_incident_report.md`](reports/sample_incident_report.md).

## Detection rules

| Rule | Signal | Default threshold | Severity | MITRE ATT&CK | NIST CSF 2.0 |
|---|---|---|---|---|---|
| `success_after_failure` | Successful login from an IP that had already failed | 1 prior failure, 24 h lookback | CRITICAL | T1078 Valid Accounts | RS.AN-03 |
| `brute_force` | Repeated failures against the **same account** from one IP | 5 failures / 10 min | HIGH | T1110.001 Password Guessing | DE.AE-02 |
| `spraying` | One IP against **many accounts**, low and slow | 5 failures across 3+ accounts / 30 min | HIGH | T1110.003 Password Spraying | DE.AE-02 |
| `root_targeting` | Attempts on privileged or non-existent accounts | 3 attempts | MEDIUM | T1078.003 Local Accounts | DE.CM-01 |
| `off_hours` | Successful login outside the working window | outside 07:00–20:00 | LOW | T1078 Valid Accounts | DE.CM-01 |

All thresholds are configurable from the CLI — see [`docs/detections.md`](docs/detections.md) for the tuning rationale and the expected false positives of each rule.

## Project layout

```text
authwatch/
├── authwatch/
│   ├── parser.py        # log line -> Event dataclass (syslog, ISO, pam_unix)
│   ├── detect.py        # the five rules + severity sorting
│   ├── report.py        # console / Markdown / JSON renderers
│   └── cli.py           # argparse entry point and exit codes
├── data/sample_auth.log # synthetic fixture, safe to publish
├── reports/             # example report produced by the tool
├── docs/detections.md   # rule design, thresholds, false positives
├── tests/               # 27 unittest cases
└── tools/               # deterministic fixture generator
```

## Tests

```bash
python -m unittest discover -s tests -v
```

27 tests covering the parser (syslog, ISO, `pam_unix`, noise rejection) and every rule, including the negative cases that matter most: failures spread outside the window, a single account that must **not** be reported as spraying, and clean logins that must stay silent. CI runs the suite on Python 3.9, 3.11 and 3.12.

## Design notes and limitations

- **Explainable over clever.** Every finding can be read line by line and defended in a review. No scoring model, no ML.
- **Thresholds are environment-specific.** The defaults are a starting point. A CI/CD runner keying in 40 times an hour looks like an attack to a naive threshold — see the tuning notes in `docs/detections.md`.
- **Single-host view.** It does not correlate across servers; a distributed attack appears as several independent findings.
- **No geolocation or reputation lookup.** Deliberate: that requires network calls and a data source, which would break the "runs anywhere" property.
- **Log rotation is the caller's problem.** Point it at the file you want analysed.

## Roadmap

- [ ] `--baseline` to learn the normal login hours per account instead of a fixed window
- [ ] Correlate the same IP across multiple log files
- [ ] Optional MAXMIND GeoLite enrichment (opt-in, offline database)
- [ ] SARIF output for GitHub code scanning
- [ ] systemd journal reader (no export step)

## Español

`authwatch` es una herramienta de triaje de logs de autenticación de Linux: lee `auth.log`, `secure` o una exportación de `journalctl` y devuelve los hallazgos ordenados por severidad, cada uno mapeado a MITRE ATT&CK y NIST CSF. Sin dependencias externas y sin instalación: solo Python 3.9 o superior. Sirve para responder rápido a la pregunta que aparece en todo turno de SOC: *¿esto es ruido o es un incidente?*

```bash
python -m authwatch.cli data/sample_auth.log --year 2026
```

## License

MIT — see [LICENSE](LICENSE).
