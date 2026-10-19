import sqlite3

from minisiem import db, parser
from minisiem.evaluate import evaluate
from minisiem.generator import generate


def test_parse_iso_line():
    ev = parser.parse_line(
        "2026-10-12T09:14:03 srv1 sshd[2231]: Failed password for alice from 10.0.0.5 port 51234 ssh2")
    assert ev == {"timestamp": "2026-10-12T09:14:03", "username": "alice",
                  "source_ip": "10.0.0.5", "success": 0}


def test_parse_syslog_line_with_invalid_user():
    ev = parser.parse_line(
        "Oct 12 09:14:03 srv1 sshd[2231]: Failed password for invalid user root from 1.2.3.4 port 5 ssh2",
        default_year=2026)
    assert ev["username"] == "root" and ev["source_ip"] == "1.2.3.4" and ev["success"] == 0
    assert ev["timestamp"] == "2026-10-12T09:14:03"


def test_parse_skips_noise():
    assert parser.parse_line("Oct 12 09:14:03 srv1 CRON[1]: pam_unix(cron:session): session opened") is None


def test_generator_plants_three_labeled_attacks():
    lines, labels = generate(days=2, seed=1)
    assert {l["rule"] for l in labels} == {"brute_force", "credential_stuffing", "off_hours_login"}
    events = list(parser.parse_lines(lines))
    assert len(events) == len(lines)  # every generated line parses


def test_db_roundtrip():
    conn = db.connect(":memory:")
    n = db.insert_events(conn, [
        {"timestamp": "2026-10-12T09:00:00", "username": "a", "source_ip": "1.1.1.1", "success": 0},
        {"timestamp": "2026-10-12T09:00:01", "username": "a", "source_ip": "1.1.1.1", "success": 1},
    ])
    assert n == 2
    assert len(db.load_events(conn)) == 2
    assert db.top_failing_ips(conn).iloc[0]["source_ip"] == "1.1.1.1"


def test_evaluate_recall_precision():
    labels = [{"rule": "brute_force", "source": "1.1.1.1",
               "start": "2026-10-12T09:00:00", "end": "2026-10-12T09:02:00"},
              {"rule": "off_hours_login", "source": "alice",
               "start": "2026-10-13T03:00:00", "end": "2026-10-13T03:00:00"}]
    alerts = [{"rule": "brute_force", "source": "1.1.1.1", "timestamp": "2026-10-12T09:01:00"},
              {"rule": "brute_force", "source": "9.9.9.9", "timestamp": "2026-10-12T09:01:00"}]
    r = evaluate(alerts, labels)
    assert r["recall"] == 0.5 and r["precision"] == 0.5
    assert len(r["missed"]) == 1 and len(r["false_positives"]) == 1
