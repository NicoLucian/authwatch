"""Deterministic generator for ``data/sample_auth.log``.

The sample is synthetic: addresses come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and 10.0.0.0/24 for internal
hosts, so nothing here points at a real system. Run it only if you want to
regenerate the fixture:

    python tools/generate_sample_log.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

random.seed(20260106)

BASE = datetime(2026, 1, 6, 0, 0, 0)
HOST = "web01"

INTERNAL = ["10.0.0.12", "10.0.0.42", "10.0.0.77"]
ACCOUNTS = ["ncancino", "mgonzalez", "jperez", "dmunoz", "svc_deploy"]


def syslog(ts: datetime, proc: str, pid: int, message: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {proc}[{pid}]: {message}"


def noise(ts: datetime, i: int) -> list:
    return [
        syslog(ts, "CRON", 900 + i, f"(root) CMD (/usr/local/bin/backup.sh)"),
        syslog(ts, "systemd", 1, "Started Daily apt download activities."),
        syslog(ts, "sshd", 3100 + i,
               f"Connection closed by 10.0.0.12 port {41000 + i} [preauth]"),
    ]


def main() -> None:
    lines: list = []
    pid = 2000

    # 1. Ordinary working-day traffic.
    for day in range(0, 4):
        for hour in (8, 11, 14, 17):
            ts = BASE + timedelta(days=day, hours=hour, minutes=random.randint(0, 50))
            user = random.choice(ACCOUNTS)
            ip = random.choice(INTERNAL)
            pid += 1
            lines.append(syslog(
                ts, "sshd", pid,
                f"Accepted publickey for {user} from {ip} port {random.randint(40000, 60000)} ssh2: "
                f"RSA SHA256:abc{random.randint(100, 999)}",
            ))

    # 2. Brute force against a single account, then a successful login (compromise).
    start = BASE + timedelta(days=1, hours=2, minutes=10)
    for i in range(12):
        ts = start + timedelta(seconds=18 * i)
        pid += 1
        lines.append(syslog(
            ts, "sshd", pid,
            f"Failed password for ncancino from 203.0.113.45 port {51000 + i} ssh2",
        ))
    pid += 1
    lines.append(syslog(
        start + timedelta(seconds=240), "sshd", pid,
        "Accepted password for ncancino from 203.0.113.45 port 51240 ssh2",
    ))

    # 3. Password spraying: one source, many accounts, low and slow.
    spray_start = BASE + timedelta(days=2, hours=9, minutes=5)
    for i, account in enumerate(["admin", "jperez", "dmunoz", "mgonzalez", "test", "oracle"]):
        ts = spray_start + timedelta(minutes=4 * i)
        pid += 1
        lines.append(syslog(
            ts, "sshd", pid,
            f"Failed password for invalid user {account} from 198.51.100.7 port {33000 + i} ssh2",
        ))

    # 4. Root / privileged account targeting.
    root_start = BASE + timedelta(days=2, hours=21, minutes=30)
    for i in range(6):
        ts = root_start + timedelta(minutes=7 * i)
        pid += 1
        lines.append(syslog(
            ts, "sshd", pid,
            f"Failed password for root from 192.0.2.99 port {60000 + i} ssh2",
        ))
    pid += 1
    lines.append(syslog(
        root_start + timedelta(minutes=45), "sshd", pid,
        "Invalid user administrator from 192.0.2.99 port 60120",
    ))

    # 5. Off-hours login with valid credentials (insider or stolen session).
    pid += 1
    lines.append(syslog(
        BASE + timedelta(days=3, hours=3, minutes=12), "sshd", pid,
        "Accepted password for svc_deploy from 10.0.0.42 port 47011 ssh2",
    ))

    # 6. pam_unix style failure, as Debian writes it.
    pid += 1
    lines.append(syslog(
        BASE + timedelta(days=1, hours=22, minutes=3), "pam_unix", 2200 + pid,
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh "
        "ruser= rhost=203.0.113.45  user=ncancino",
    ))

    # 7. Background noise so the parser has to ignore things.
    for i in range(30):
        ts = BASE + timedelta(hours=2 * i, minutes=random.randint(0, 59))
        lines.extend(noise(ts, i))

    lines.sort()
    with open("data/sample_auth.log", "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    print(f"wrote data/sample_auth.log ({len(lines)} lines)")


if __name__ == "__main__":
    main()
