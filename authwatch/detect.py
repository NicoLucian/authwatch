"""Detection rules.

Each rule returns :class:`Finding` objects. Rules are deliberately simple and
explainable: a SOC L1 analyst must be able to defend every alert in front of a
reviewer, so there is no machine learning and no hidden scoring here. Every
finding carries the MITRE ATT&CK technique and the NIST CSF function it maps
to, which is what turns an alert into a report.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Sequence

from .parser import SUCCESS, Event

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

ATTACK = {
    "brute_force": "T1110.001 - Brute Force: Password Guessing",
    "spraying": "T1110.003 - Brute Force: Password Spraying",
    "success_after_failure": "T1078 - Valid Accounts",
    "root_targeting": "T1078.003 - Valid Accounts: Local Accounts",
    "off_hours": "T1078 - Valid Accounts",
}

NIST = {
    "brute_force": "DE.AE-02 - Adverse event analysis",
    "spraying": "DE.AE-02 - Adverse event analysis",
    "success_after_failure": "RS.AN-03 - Analysis of incident",
    "root_targeting": "DE.CM-01 - Network monitoring",
    "off_hours": "DE.CM-01 - Network monitoring",
}


@dataclass
class Finding:
    """One detection result, ready to be written into a report."""

    rule: str
    title: str
    severity: str
    ip: str
    count: int
    users: List[str]
    start: datetime
    end: datetime
    detail: str
    evidence: List[Event] = field(default_factory=list)

    @property
    def attack(self) -> str:
        return ATTACK.get(self.rule, "")

    @property
    def nist(self) -> str:
        return NIST.get(self.rule, "")

    @property
    def duration_minutes(self) -> float:
        return round((self.end - self.start).total_seconds() / 60, 1)


def _group_by(events: Iterable[Event], key) -> Dict[str, List[Event]]:
    grouped: Dict[str, List[Event]] = {}
    for event in events:
        grouped.setdefault(key(event), []).append(event)
    for items in grouped.values():
        items.sort(key=lambda e: e.ts)
    return grouped


def _group_by_ip(events: Iterable[Event]) -> Dict[str, List[Event]]:
    return _group_by(events, lambda e: e.ip)


def _best_window(
    events: Sequence[Event],
    window: timedelta,
    score,
) -> Optional[Sequence[Event]]:
    """Return the densest windows worth of events, scored by ``score``."""
    best: Optional[Sequence[Event]] = None
    best_score = -1
    left = 0
    for right in range(len(events)):
        while events[right].ts - events[left].ts > window:
            left += 1
        candidate = events[left:right + 1]
        value = score(candidate)
        if value > best_score:
            best, best_score = candidate, value
    return best


def detect_brute_force(
    events: Sequence[Event], threshold: int = 5, window_minutes: int = 10
) -> List[Finding]:
    """Same source IP failing against the same account too often, too fast."""
    failures = [e for e in events if e.is_failure]
    findings: List[Finding] = []
    window = timedelta(minutes=window_minutes)

    for ip, items in _group_by_ip(failures).items():
        for user, targeted in _group_by(items, lambda e: e.user).items():
            windowed = _best_window(targeted, window, score=len)
            if not windowed or len(windowed) < threshold:
                continue
            findings.append(
                Finding(
                    rule="brute_force",
                    title=f"Brute force against '{user}'",
                    severity="high",
                    ip=ip,
                    count=len(windowed),
                    users=[user],
                    start=windowed[0].ts,
                    end=windowed[-1].ts,
                    detail=(
                        f"{len(windowed)} failed authentications for user '{user}' from {ip} "
                        f"within {window_minutes} minutes "
                        f"(threshold: {threshold})."
                    ),
                    evidence=list(windowed),
                )
            )
    return findings


def detect_spraying(
    events: Sequence[Event],
    threshold: int = 5,
    min_users: int = 3,
    window_minutes: int = 30,
) -> List[Finding]:
    """One source IP trying many accounts: the classic low-and-slow pattern."""
    failures = [e for e in events if e.is_failure]
    findings: List[Finding] = []
    window = timedelta(minutes=window_minutes)

    for ip, items in _group_by_ip(failures).items():
        windowed = _best_window(items, window, score=lambda w: len({e.user for e in w}))
        if not windowed:
            continue
        users = [u for u, _ in Counter(e.user for e in windowed).most_common()]
        if len(users) < min_users or len(windowed) < threshold:
            continue
        findings.append(
            Finding(
                rule="spraying",
                title="Password spraying",
                severity="high",
                ip=ip,
                count=len(windowed),
                users=users,
                start=windowed[0].ts,
                end=windowed[-1].ts,
                detail=(
                    f"{len(windowed)} failed authentications against {len(users)} distinct "
                    f"users from {ip} within {window_minutes} minutes "
                    f"(threshold: {min_users} users)."
                ),
                evidence=list(windowed),
            )
        )
    return findings


def detect_success_after_failure(
    events: Sequence[Event], lookback_minutes: int = 1440
) -> List[Finding]:
    """A successful login from an IP that had already been failing."""
    findings: List[Finding] = []
    by_ip = _group_by_ip(events)

    for ip, items in by_ip.items():
        successes = [e for e in items if e.kind == SUCCESS]
        if not successes:
            continue
        for success in successes:
            lookback = success.ts - timedelta(minutes=lookback_minutes)
            prior = [e for e in items if e.is_failure and lookback <= e.ts <= success.ts]
            if not prior:
                continue
            findings.append(
                Finding(
                    rule="success_after_failure",
                    title=f"Successful login after failures ({success.user})",
                    severity="critical",
                    ip=ip,
                    count=len(prior) + 1,
                    users=[success.user],
                    start=prior[0].ts,
                    end=success.ts,
                    detail=(
                        f"User '{success.user}' authenticated successfully from {ip} after "
                        f"{len(prior)} failed attempts from the same address. "
                        f"Treat as possible account compromise."
                    ),
                    evidence=prior[-5:] + [success],
                )
            )
    return findings


def detect_root_targeting(events: Sequence[Event], threshold: int = 3) -> List[Finding]:
    """Repeated attempts against privileged or non-existent accounts."""
    privileged = {"root", "admin", "administrator", "test", "ubuntu", "oracle", "postgres"}
    failures = [
        e for e in events if e.is_failure and (e.user.lower() in privileged or e.invalid_user)
    ]
    findings: List[Finding] = []

    for ip, items in _group_by_ip(failures).items():
        if len(items) < threshold:
            continue
        users = [u for u, _ in Counter(e.user for e in items).most_common(5)]
        findings.append(
            Finding(
                rule="root_targeting",
                title="Privileged / non-existent account enumeration",
                severity="medium",
                ip=ip,
                count=len(items),
                users=users,
                start=items[0].ts,
                end=items[-1].ts,
                detail=(
                    f"{len(items)} failed attempts from {ip} against privileged or invalid "
                    f"accounts (threshold: {threshold})."
                ),
                evidence=list(items[:5]),
            )
        )
    return findings


def detect_off_hours(
    events: Sequence[Event], start_hour: int = 7, end_hour: int = 20
) -> List[Finding]:
    """Successful logins outside the organisation's working window."""
    by_user: List[Event] = [
        e for e in events if e.kind == SUCCESS and not (start_hour <= e.ts.hour < end_hour)
    ]
    findings: List[Finding] = []

    for event in by_user:
        findings.append(
            Finding(
                rule="off_hours",
                title=f"Off-hours login ({event.user})",
                severity="low",
                ip=event.ip,
                count=1,
                users=[event.user],
                start=event.ts,
                end=event.ts,
                detail=(
                    f"Successful login by '{event.user}' from {event.ip} at "
                    f"{event.ts:%H:%M}, outside the {start_hour:02d}:00-{end_hour:02d}:00 window."
                ),
                evidence=[event],
            )
        )
    return findings


def run_all(
    events: Sequence[Event],
    threshold: int = 5,
    window_minutes: int = 10,
    spray_users: int = 3,
    business_start: int = 7,
    business_end: int = 20,
) -> List[Finding]:
    """Run every rule and return findings sorted by severity."""
    findings: List[Finding] = []
    findings += detect_success_after_failure(events)
    findings += detect_spraying(events, threshold=threshold, min_users=spray_users,
                                window_minutes=window_minutes * 3)
    findings += detect_brute_force(events, threshold=threshold, window_minutes=window_minutes)
    findings += detect_root_targeting(events, threshold=max(3, threshold // 2))
    findings += detect_off_hours(events, start_hour=business_start, end_hour=business_end)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.count, f.ip))
    return findings
