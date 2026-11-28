"""Parse Linux authentication logs into structured events.

Supports the two formats an analyst meets most often:

* classic syslog (``/var/log/auth.log``, ``/var/log/secure``)::

    Jan  6 14:02:11 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2

* ISO timestamps (``journalctl --output=short-iso``)::

    2026-01-06T14:02:11+0000 web01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2

Only sshd / pam_unix lines are interpreted; everything else is ignored, which
keeps the parser tolerant of real, noisy logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Optional

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Jan  6 14:02:11  -> two spaces before a single-digit day
SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[a-z_\-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[a-z_\-]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)

# --- message patterns -------------------------------------------------------
RE_FAILED = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+)(?: port (?P<port>\d+))?"
)
RE_PAM_FAIL = re.compile(
    r"authentication failure;.*?rhost=(?P<ip>\S+)\s+user=(?P<user>\S+)"
)
RE_DISCONNECT = re.compile(r"(?:Connection closed|Disconnected from|Received disconnect)")

FAILED = "failed"
SUCCESS = "success"
INVALID = "invalid"


@dataclass(frozen=True)
class Event:
    """A single authentication-related log line."""

    ts: datetime
    host: str
    user: str
    ip: str
    kind: str
    port: Optional[int] = None
    method: Optional[str] = None
    invalid_user: bool = False
    raw: str = field(default="", compare=False, repr=False)

    @property
    def is_failure(self) -> bool:
        return self.kind in (FAILED, INVALID)


def _parse_syslog_ts(
    mon: str, day: str, hms: str, year: Optional[int], offset_hours: Optional[float] = None
) -> Optional[datetime]:
    """Hora de pared tal como viene escrita: syslog no trae offset, así que es naive
    y representa el reloj local del host que escribió el log.

    Con ``offset_hours`` se asume que ese reloj está en ese offset y se normaliza a UTC,
    para que los eventos queden en el mismo eje que los timestamps ISO.
    """
    month = MONTHS.get(mon)
    if month is None:
        return None
    try:
        hour, minute, second = (int(x) for x in hms.split(":"))
        if year is None:
            now = datetime.now()
            year = now.year
            if month > now.month:
                year -= 1
        stamp = datetime(year, month, int(day), hour, minute, second)
    except ValueError:
        return None
    if offset_hours is None:
        return stamp
    return stamp - timedelta(hours=offset_hours)


def _parse_iso_ts(value: str) -> Optional[datetime]:
    """Normalizado a UTC y devuelto naive.

    Ojo: syslog entrega hora de pared y esto entrega UTC. Un archivo que mezcle ambos
    formatos compara dos convenciones distintas (desfase = offset local). Es a propósito,
    no un accidente: el test test_mixed_formats_keep_their_own_convention lo fija.
    """
    cleaned = value.replace(",", ".")
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    # journalctl writes +0000; fromisoformat only accepts +00:00 before 3.11
    cleaned = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", cleaned)
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(tzinfo=None)


def parse_line(
    line: str, year: Optional[int] = None, syslog_offset: Optional[float] = None
) -> Optional[Event]:
    """Parse one log line. Returns ``None`` when the line is not relevant."""
    line = line.rstrip("\n\r")
    if not line.strip():
        return None

    ts: Optional[datetime] = None
    host = ""
    proc = ""
    msg = ""

    match = ISO_RE.match(line)
    if match:
        ts = _parse_iso_ts(match.group("ts"))
        host = match.group("host")
        proc = match.group("proc")
        msg = match.group("msg")
    else:
        match = SYSLOG_RE.match(line)
        if not match:
            return None
        ts = _parse_syslog_ts(
            match.group("mon"), match.group("day"), match.group("hms"), year, syslog_offset
        )
        host = match.group("host")
        proc = match.group("proc")
        msg = match.group("msg")

    if ts is None:
        return None

    if proc not in ("sshd", "pam_unix", "sshd-session"):
        return None

    port: Optional[int] = None
    method: Optional[str] = None

    m = RE_ACCEPTED.search(msg)
    if m:
        return Event(
            ts=ts, host=host, user=m.group("user"), ip=m.group("ip"), kind=SUCCESS,
            port=int(m.group("port")), method=m.group("method"), raw=line,
        )

    m = RE_FAILED.search(msg)
    if m:
        invalid = bool(m.group("invalid"))
        return Event(
            ts=ts, host=host, user=m.group("user"), ip=m.group("ip"),
            kind=INVALID if invalid else FAILED, port=int(m.group("port")),
            invalid_user=invalid, raw=line,
        )

    m = RE_INVALID.search(msg)
    if m:
        port_raw = m.group("port")
        return Event(
            ts=ts, host=host, user=m.group("user"), ip=m.group("ip"), kind=INVALID,
            port=int(port_raw) if port_raw else None, invalid_user=True, raw=line,
        )

    m = RE_PAM_FAIL.search(msg)
    if m:
        return Event(
            ts=ts, host=host, user=m.group("user"), ip=m.group("ip"), kind=FAILED, raw=line,
        )

    if RE_DISCONNECT.search(msg):
        return None

    return None


def parse_lines(
    lines: Iterable[str], year: Optional[int] = None, syslog_offset: Optional[float] = None
) -> List[Event]:
    """Parse an iterable of log lines, keeping the relevant ones only."""
    events: List[Event] = []
    for line in lines:
        event = parse_line(line, year=year, syslog_offset=syslog_offset)
        if event is not None:
            events.append(event)
    return events


def parse_file(
    path: str, year: Optional[int] = None, syslog_offset: Optional[float] = None
) -> List[Event]:
    """Parse a log file. Invalid UTF-8 bytes are replaced, never raised."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle, year=year, syslog_offset=syslog_offset)


def count_time_bases(lines: Iterable[str]) -> dict:
    """Cuenta cuántas líneas traen timestamp ISO (con offset) y cuántas syslog (sin él).

    Sirve para avisar de un archivo que mezcla ejes: syslog es hora de pared del host e
    ISO se normaliza a UTC, así que compararlos sin declarar el offset desplaza los
    resultados por la diferencia entre ambos relojes.
    """
    iso = syslog = 0
    for line in lines:
        if ISO_RE.match(line):
            iso += 1
        elif SYSLOG_RE.match(line):
            syslog += 1
    return {"iso": iso, "syslog": syslog, "mixed": bool(iso and syslog)}
