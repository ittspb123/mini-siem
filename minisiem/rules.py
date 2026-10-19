"""Detection rules.

Every rule is a pure function: it walks events *sorted by time* once, keeps a small dict of
per-IP or per-user state (a sliding window), and returns a list of alert dicts. Writing the
alerts to SQLite is done separately in `run_all` so the rules stay easy to unit-test.

Alert dict shape:
    {"rule": str, "source": str, "username": str | None, "timestamp": str (ISO), "details": str}
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Iterable, Iterator

import pandas as pd

# ----------------------------------------------------------------------------- thresholds
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
BRUTE_FORCE_THRESHOLD = 20          # failures from one IP inside the window

STUFFING_WINDOW = timedelta(minutes=10)
STUFFING_THRESHOLD = 10             # distinct usernames tried (and failed) by one IP inside the window

OFF_HOURS_MIN_HISTORY = 10          # successes a user needs before we trust their baseline
OFF_HOURS_TOLERANCE_HOURS = 3       # a login within ±3h of the user's usual window is "normal"


# ----------------------------------------------------------------------------- helpers
def _normalize(events: Iterable[dict] | pd.DataFrame) -> Iterator[tuple[datetime, str, str, bool]]:
    """Yield (ts, username, source_ip, success) from a DataFrame or an iterable of dicts."""
    if isinstance(events, pd.DataFrame):
        ts_col = events["ts"] if "ts" in events.columns else pd.to_datetime(events["timestamp"])
        for ts, user, ip, ok in zip(ts_col, events["username"], events["source_ip"], events["success"]):
            yield ts.to_pydatetime(), user, ip, bool(ok)
        return
    for ev in events:
        ts = ev.get("ts") or ev["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        yield ts, ev["username"], ev["source_ip"], bool(ev["success"])


def _alert(rule: str, source: str, ts: datetime, details: str, username: str | None = None) -> dict:
    return {"rule": rule, "source": source, "username": username,
            "timestamp": ts.isoformat(), "details": details}


# ----------------------------------------------------------------------------- rule 1
def detect_brute_force(events, window: timedelta = BRUTE_FORCE_WINDOW,
                       threshold: int = BRUTE_FORCE_THRESHOLD) -> list[dict]:
    """One IP produces >= `threshold` failures inside a sliding `window`.

    State: per-IP deque of failure timestamps. Old ones are popped from the left as the
    window slides. One alert per IP per burst: after firing, that IP is suppressed for one
    window length, so a 50-failure burst produces one alert, not thirty.
    """
    alerts: list[dict] = []
    fails: dict[str, deque] = defaultdict(deque)
    suppressed_until: dict[str, datetime] = {}
    for ts, user, ip, ok in _normalize(events):
        if ok:
            continue
        if ip in suppressed_until and ts < suppressed_until[ip]:
            continue
        q = fails[ip]
        q.append(ts)
        while q and ts - q[0] > window:
            q.popleft()
        if len(q) >= threshold:
            alerts.append(_alert("brute_force", ip, ts,
                                 f"{len(q)} failed logins in {window.seconds}s (last target: {user})",
                                 username=user))
            q.clear()
            suppressed_until[ip] = ts + window
    return alerts


# ----------------------------------------------------------------------------- rule 2
def detect_credential_stuffing(events, window: timedelta = STUFFING_WINDOW,
                               threshold: int = STUFFING_THRESHOLD) -> list[dict]:
    """One IP fails against >= `threshold` *distinct* usernames inside a sliding `window`.

    State: per-IP deque of (ts, username) failures plus a per-IP Counter of usernames currently
    in the window, so "distinct users in window" is O(1) to read.
    """
    alerts: list[dict] = []
    hist: dict[str, deque] = defaultdict(deque)
    in_window: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    suppressed_until: dict[str, datetime] = {}
    for ts, user, ip, ok in _normalize(events):
        if ok:
            continue
        if ip in suppressed_until and ts < suppressed_until[ip]:
            continue
        q, counts = hist[ip], in_window[ip]
        q.append((ts, user))
        counts[user] += 1
        while q and ts - q[0][0] > window:
            _, old_user = q.popleft()
            counts[old_user] -= 1
            if counts[old_user] == 0:
                del counts[old_user]
        if len(counts) >= threshold:
            alerts.append(_alert("credential_stuffing", ip, ts,
                                 f"{len(counts)} distinct usernames tried in {window.seconds}s"))
            q.clear()
            counts.clear()
            suppressed_until[ip] = ts + window
    return alerts


# ----------------------------------------------------------------------------- rule 3
def detect_off_hours(events, min_history: int = OFF_HOURS_MIN_HISTORY,
                     tolerance_hours: int = OFF_HOURS_TOLERANCE_HOURS) -> list[dict]:
    """A user succeeds at an hour of day they have never logged in near before.

    There is no fixed "business hours" constant: each user's baseline is learned from their
    own prior successes (so a night-shift user who always logs in at 02:00 does not alert).
    The baseline is the smallest contiguous span of hours (on a 24h circle) covering every
    hour the user has succeeded at before, so a user seen at 08:00 and 17:00 is "normal" at
    12:00 even if they never logged in at noon. The event counts as off-hours once the user
    has >= `min_history` prior successes and the hour falls more than `tolerance_hours`
    outside that span. The hour is then added to the baseline so it fires once, not forever.
    """
    alerts: list[dict] = []
    seen_hours: dict[str, set[int]] = defaultdict(set)
    n_success: dict[str, int] = defaultdict(int)
    for ts, user, ip, ok in _normalize(events):
        if not ok:
            continue
        hour = ts.hour
        if n_success[user] >= min_history:
            start, end = _circular_span(seen_hours[user])
            if _hours_outside_span(hour, start, end) > tolerance_hours:
                alerts.append(_alert("off_hours_login", user, ts,
                                     f"success at {ts.strftime('%H:%M')} from {ip}; "
                                     f"usual hours {start:02d}:00-{end:02d}:59",
                                     username=user))
        seen_hours[user].add(hour)
        n_success[user] += 1
    return alerts


def _circular_span(hours: set[int]) -> tuple[int, int]:
    """Smallest arc on the 24h clock covering all `hours`; returned as (start, end) inclusive.

    The arc is found by locating the largest gap between consecutive seen hours (wrapping
    around midnight) — the span is everything *except* that gap. {22, 23, 1, 3} -> (22, 3).
    """
    hs = sorted(hours)
    if len(hs) == 1:
        return hs[0], hs[0]
    best_gap, best_i = -1, 0
    for i in range(len(hs)):
        nxt = hs[(i + 1) % len(hs)]
        gap = (nxt - hs[i]) % 24
        if gap > best_gap:
            best_gap, best_i = gap, i
    return hs[(best_i + 1) % len(hs)], hs[best_i]


def _hours_outside_span(hour: int, start: int, end: int) -> int:
    """0 if `hour` is inside the circular span, otherwise the distance to its nearest edge."""
    length = (end - start) % 24
    offset = (hour - start) % 24
    if offset <= length:
        return 0
    return min(offset - length, 24 - offset)


# ----------------------------------------------------------------------------- all
RULES = {
    "brute_force": detect_brute_force,
    "credential_stuffing": detect_credential_stuffing,
    "off_hours_login": detect_off_hours,
}


def run_all(events: pd.DataFrame | list[dict]) -> list[dict]:
    """Run every rule and return the combined alert list (sorted by time)."""
    alerts: list[dict] = []
    for fn in RULES.values():
        alerts.extend(fn(events))
    alerts.sort(key=lambda a: a["timestamp"])
    return alerts
