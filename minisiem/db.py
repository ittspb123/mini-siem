"""SQLite storage: `events` and `alerts` tables plus a few query helpers."""
from __future__ import annotations

import sqlite3
from typing import Iterable

import pandas as pd

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY,
    timestamp  TEXT    NOT NULL,
    username   TEXT    NOT NULL,
    source_ip  TEXT    NOT NULL,
    success    INTEGER NOT NULL CHECK (success IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY,
    rule       TEXT NOT NULL,
    source     TEXT NOT NULL,     -- offending IP or username
    username   TEXT,
    timestamp  TEXT NOT NULL,     -- time the threshold was crossed
    details    TEXT
);
"""


def connect(path: str = "data/siem.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    return conn


def reset(conn: sqlite3.Connection) -> None:
    conn.executescript("DELETE FROM events; DELETE FROM alerts;")
    conn.commit()


def insert_events(conn: sqlite3.Connection, events: Iterable[dict], batch: int = 5000) -> int:
    """Batch-insert events; returns the number inserted."""
    cur = conn.cursor()
    buf, n = [], 0
    for ev in events:
        buf.append((ev["timestamp"], ev["username"], ev["source_ip"], ev["success"]))
        if len(buf) >= batch:
            cur.executemany("INSERT INTO events (timestamp, username, source_ip, success) VALUES (?,?,?,?)", buf)
            n += len(buf)
            buf.clear()
    if buf:
        cur.executemany("INSERT INTO events (timestamp, username, source_ip, success) VALUES (?,?,?,?)", buf)
        n += len(buf)
    conn.commit()
    return n


def insert_alerts(conn: sqlite3.Connection, alerts: Iterable[dict]) -> int:
    rows = [(a["rule"], a["source"], a.get("username"), a["timestamp"], a.get("details")) for a in alerts]
    conn.executemany("INSERT INTO alerts (rule, source, username, timestamp, details) VALUES (?,?,?,?,?)", rows)
    conn.commit()
    return len(rows)


def load_events(conn: sqlite3.Connection) -> pd.DataFrame:
    """All events sorted by time, with a parsed datetime column."""
    df = pd.read_sql_query(
        "SELECT id, timestamp, username, source_ip, success FROM events ORDER BY timestamp, id", conn
    )
    df["ts"] = pd.to_datetime(df["timestamp"])
    return df


def load_alerts(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp", conn)


# --- A few SQL views the dashboard uses -------------------------------------------------

def events_per_hour(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        """
        SELECT substr(timestamp, 1, 13) || ':00' AS hour,
               SUM(success)     AS successes,
               SUM(1 - success) AS failures
        FROM events GROUP BY hour ORDER BY hour
        """,
        conn,
    )


def top_failing_ips(conn: sqlite3.Connection, limit: int = 10) -> pd.DataFrame:
    return pd.read_sql_query(
        """
        SELECT source_ip, COUNT(*) AS failures, COUNT(DISTINCT username) AS distinct_users
        FROM events WHERE success = 0
        GROUP BY source_ip ORDER BY failures DESC LIMIT ?
        """,
        conn, params=(limit,),
    )
