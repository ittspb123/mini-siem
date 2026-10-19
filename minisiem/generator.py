"""Synthetic auth-log generator with planted attacks and a ground-truth labels file.

Output format mirrors a real Linux auth.log line, but with an ISO timestamp so the year
is unambiguous:

    2026-10-12T09:14:03 srv1 sshd[2231]: Accepted password for alice from 10.0.0.5 port 51234 ssh2
    2026-10-12T09:14:09 srv1 sshd[2232]: Failed password for alice from 10.0.0.5 port 51235 ssh2

Usage:
    python -m minisiem.generator --out data/auth.log --labels data/labels.json --days 7 --seed 42
"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

BUSINESS_USERS = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    "ivan", "judy", "mallory", "niaj", "olivia", "peggy", "rupert", "sybil",
]
NIGHT_SHIFT_USERS = ["trent", "victor"]  # always log in overnight; must NOT trigger off-hours
ALL_USERS = BUSINESS_USERS + NIGHT_SHIFT_USERS

BRUTE_FORCE_IP = "203.0.113.50"
STUFFING_IP = "198.51.100.77"
OFF_HOURS_IP = "192.0.2.99"
OFF_HOURS_USER = "alice"


def _fmt(ts: datetime, user: str, ip: str, ok: bool, pid: int) -> str:
    verb = "Accepted" if ok else "Failed"
    port = random.randint(40000, 65000)
    return f"{ts.strftime('%Y-%m-%dT%H:%M:%S')} srv1 sshd[{pid}]: {verb} password for {user} from {ip} port {port} ssh2"


def generate(days: int = 7, seed: int = 42, start: datetime | None = None,
             logins_per_user_per_day: int = 6) -> tuple[list[str], list[dict]]:
    """Return (log_lines sorted by time, labels)."""
    random.seed(seed)
    start = start or datetime(2026, 10, 12, 0, 0, 0)  # a Monday
    events: list[tuple[datetime, str, str, bool]] = []

    # Each user has 1–2 home IPs.
    home_ips = {u: [f"10.0.{random.randint(1, 20)}.{random.randint(2, 250)}"
                    for _ in range(random.choice([1, 2]))] for u in ALL_USERS}

    for day in range(days):
        day_start = start + timedelta(days=day)
        for user in ALL_USERS:
            n = max(1, int(random.gauss(logins_per_user_per_day, 2)))
            for _ in range(n):
                if user in NIGHT_SHIFT_USERS:
                    hour = random.choice([22, 23, 0, 1, 2, 3, 4, 5])
                else:
                    hour = random.randint(8, 17)
                ts = day_start.replace(hour=hour, minute=random.randint(0, 59),
                                       second=random.randint(0, 59))
                ip = random.choice(home_ips[user])
                # Occasionally a typo: 1–2 failures then a success.
                if random.random() < 0.15:
                    for k in range(random.choice([1, 2])):
                        events.append((ts - timedelta(seconds=10 * (k + 1)), user, ip, False))
                events.append((ts, user, ip, True))

    labels: list[dict] = []

    # Attack 1: brute force — one IP fails 50 times in 2 minutes against one account.
    bf_start = start + timedelta(days=2, hours=14, minutes=7)
    for i in range(50):
        events.append((bf_start + timedelta(seconds=i * 2.3), "bob", BRUTE_FORCE_IP, False))
    labels.append({"rule": "brute_force", "source": BRUTE_FORCE_IP,
                   "start": bf_start.isoformat(),
                   "end": (bf_start + timedelta(seconds=50 * 2.3)).isoformat()})

    # Attack 2: credential stuffing — one IP cycles 40 distinct usernames, one failure each.
    cs_start = start + timedelta(days=4, hours=11, minutes=30)
    stuffing_users = ALL_USERS + [f"user{i:02d}" for i in range(40 - len(ALL_USERS))]
    random.shuffle(stuffing_users)
    # One attempt every 10s: 12 failures per 2-minute window, so this is below the brute-force
    # threshold and only the stuffing rule should fire. (At ~6s spacing both rules fire, which
    # is correct behaviour but makes the ground truth ambiguous.)
    for i, u in enumerate(stuffing_users[:40]):
        events.append((cs_start + timedelta(seconds=i * 10), u, STUFFING_IP, False))
    labels.append({"rule": "credential_stuffing", "source": STUFFING_IP,
                   "start": cs_start.isoformat(),
                   "end": (cs_start + timedelta(seconds=40 * 10)).isoformat()})

    # Attack 3: off-hours success — a business-hours-only user succeeds at 3 a.m. from a new IP.
    oh_ts = start + timedelta(days=5, hours=3, minutes=12, seconds=41)
    events.append((oh_ts, OFF_HOURS_USER, OFF_HOURS_IP, True))
    labels.append({"rule": "off_hours_login", "source": OFF_HOURS_USER,
                   "start": oh_ts.isoformat(), "end": oh_ts.isoformat()})

    events.sort(key=lambda e: e[0])
    lines = [_fmt(ts, u, ip, ok, 2000 + i) for i, (ts, u, ip, ok) in enumerate(events)]
    return lines, labels


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="data/auth.log")
    ap.add_argument("--labels", default="data/labels.json")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--per-day", type=int, default=6, help="mean logins per user per day")
    args = ap.parse_args()

    lines, labels = generate(days=args.days, seed=args.seed, logins_per_user_per_day=args.per_day)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n")
    Path(args.labels).write_text(json.dumps(labels, indent=2))
    print(f"wrote {len(lines)} events to {args.out} and {len(labels)} labels to {args.labels}")


if __name__ == "__main__":
    main()
