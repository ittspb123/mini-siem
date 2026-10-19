"""Parse auth.log lines into event dicts.

Handles two timestamp styles:
  * ISO:    2026-10-12T09:14:03 srv1 sshd[2231]: Failed password for alice from 10.0.0.5 port 5 ssh2
  * syslog: Oct 12 09:14:03 srv1 sshd[2231]: Failed password for invalid user alice from 10.0.0.5 port 5 ssh2
    (syslog has no year — we assume the current year.)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator, TypedDict


class Event(TypedDict):
    timestamp: str  # ISO 8601
    username: str
    source_ip: str
    success: int  # 1 / 0


_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<verb>Accepted|Failed)\s+\S+\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.:a-fA-F]+)"
)


def parse_line(line: str, default_year: int | None = None) -> Event | None:
    """Return an Event or None if the line isn't a login success/failure."""
    m = _LINE.match(line.strip())
    if not m:
        return None
    raw_ts = m.group("ts")
    if "T" in raw_ts:
        ts = datetime.strptime(raw_ts, "%Y-%m-%dT%H:%M:%S")
    else:
        year = default_year or datetime.now().year
        ts = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
    return Event(
        timestamp=ts.isoformat(),
        username=m.group("user"),
        source_ip=m.group("ip"),
        success=1 if m.group("verb") == "Accepted" else 0,
    )


def parse_lines(lines: Iterable[str], default_year: int | None = None) -> Iterator[Event]:
    for line in lines:
        ev = parse_line(line, default_year)
        if ev is not None:
            yield ev


def parse_file(path: str, default_year: int | None = None) -> Iterator[Event]:
    """Stream a log file line by line (never loads the whole file into memory)."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from parse_lines(fh, default_year)
