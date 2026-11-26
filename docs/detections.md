# Detection rules: design, thresholds and false positives

Every rule in `authwatch` answers one question and produces one finding. This
document explains the reasoning behind each one, so the output can be defended
in a review instead of taken on faith.

---

## 1. `success_after_failure` — CRITICAL

**Signal.** A successful authentication from a source IP that had already failed
against the same host within the lookback window (24 hours by default).

**Why it is critical.** A failed-then-successful sequence is the shortest
description of a successful password attack. It is also the finding that most
often gets lost when an analyst greps only for `Failed password`: the successful
line looks perfectly normal in isolation.

```text
Jan  7 02:13:18 web01 sshd[2028]: Failed password for ncancino from 203.0.113.45 port 51011 ssh2
Jan  7 02:14:00 web01 sshd[2029]: Accepted password for ncancino from 203.0.113.45 port 51240 ssh2
```

**Expected false positives.** Users who mistype their password and then succeed
in the next attempt, especially after a VPN drop. That is why the recommended
action is verification, not automatic lockout: confirm the source IP with the
account owner before escalating.

**How to tune.** `--lookback` is currently fixed at 24 h in `detect.py`. Lower it
to 30–60 minutes in environments where users authenticate frequently.

---

## 2. `brute_force` — HIGH

**Signal.** At least `--threshold` failures (default 5) against the **same
account** from the **same IP** inside a sliding `--window` (default 10 minutes).

**Why same account matters.** Grouping by IP alone produces a misleading number:
a password-spraying run against 40 accounts is not a brute force against any of
them. The two patterns are separated on purpose because the response differs —
spraying implies a list of valid usernames, brute force implies one target.

**Expected false positives.**

- Automated deployment jobs reconnecting with a stale credential.
- Users who change devices and retry an old password.
- Monitoring probes with hardcoded credentials.

**How to tune.** Raise `--threshold` to 10 in environments with lots of
automation, and keep `--window` tight (5–10 min) so slow-and-low attempts are
carried by the `spraying` rule instead.

---

## 3. `spraying` — HIGH

**Signal.** One IP producing at least `--threshold` failures (default 5) against
at least `--spray-users` distinct accounts (default 3) within the window.

**Why it is separate.** Spraying stays under classic brute-force thresholds by
trying each account only a few times. Detecting it requires counting
**distinct accounts**, not failures per account.

**Expected false positives.**

- Vulnerability scanners with default credential lists (Nessus, OpenVAS).
- Load balancers or orchestrators failing health checks across service accounts.

**How to tune.** `--spray-users` is the knob. Three is aggressive and suitable
for a small server; in a corporate fleet with shared service accounts, raise it
to 5–10.

---

## 4. `root_targeting` — MEDIUM

**Signal.** At least three failures from one IP against privileged (`root`,
`admin`, `administrator`, `oracle`, `postgres`…) or non-existent accounts.

**Why it matters.** This is the enumeration phase. Seeing `root`, then
`administrator`, then `test` from the same address describes an automated scan
walking a username dictionary. It rarely succeeds, but it is a reliable
indicator of intent and a good early signal for blocking a range.

**Expected false positives.** Very low. Misconfigured backup scripts that try
`root` with an old key are the usual culprit.

---

## 5. `off_hours` — LOW

**Signal.** A successful login outside `--business-hours` (default `7-20`).

**Why LOW.** On its own it proves nothing — maintenance windows, on-call staff
and remote workers all break the window legitimately. It is a contextual signal
that only becomes interesting when it belongs to an account that never logs in
at night.

**How to tune.** Set the window to the organisation's real schedule, and expect
to ignore service accounts. A future `--baseline` mode will learn per-account
hours instead of applying a global rule.

---

## Severity model

| Severity | Meaning | Expected action |
|---|---|---|
| CRITICAL | Possible account compromise | Verify with the account owner and escalate now |
| HIGH | Automated attack in progress | Confirm and block the source |
| MEDIUM | Reconnaissance or enumeration | Block the range, review exposure |
| LOW | Contextual anomaly | Confirm during the shift |

Findings are sorted by severity, then by number of events, so the top of the
report is always the thing to look at first.

## Mapping

| Rule | MITRE ATT&CK | NIST CSF 2.0 |
|---|---|---|
| `success_after_failure` | T1078 Valid Accounts | RS.AN-03 Analysis of incident |
| `brute_force` | T1110.001 Password Guessing | DE.AE-02 Adverse event analysis |
| `spraying` | T1110.003 Password Spraying | DE.AE-02 Adverse event analysis |
| `root_targeting` | T1078.003 Local Accounts | DE.CM-01 Network monitoring |
| `off_hours` | T1078 Valid Accounts | DE.CM-01 Network monitoring |

The mapping is what makes the output usable outside the terminal: a finding can
be pasted into a ticket, into an incident record, or into a compliance report
without translation.
