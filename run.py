"""Full pipeline with timing: parse/load -> detect -> evaluate.

    python run.py --log data/auth.log --labels data/labels.json --db data/siem.db
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from minisiem import db, parser, rules
from minisiem.evaluate import evaluate, load_labels


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="data/auth.log")
    ap.add_argument("--labels", default="data/labels.json")
    ap.add_argument("--db", default="data/siem.db")
    ap.add_argument("--year", type=int, default=None, help="year to assume for syslog-style lines")
    ap.add_argument("--report", default="data/benchmark.json")
    args = ap.parse_args()

    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    conn = db.connect(args.db)
    db.reset(conn)

    t0 = time.perf_counter()
    n_events = db.insert_events(conn, parser.parse_file(args.log, args.year))
    t1 = time.perf_counter()

    events = db.load_events(conn)
    alerts = rules.run_all(events)
    db.insert_alerts(conn, alerts)
    t2 = time.perf_counter()

    load_s, detect_s, total_s = t1 - t0, t2 - t1, t2 - t0
    report = {
        "events": n_events,
        "alerts": len(alerts),
        "load_seconds": round(load_s, 4),
        "detect_seconds": round(detect_s, 4),
        "total_seconds": round(total_s, 4),
        "events_per_sec_load": round(n_events / load_s) if load_s else None,
        "events_per_sec_total": round(n_events / total_s) if total_s else None,
    }

    if Path(args.labels).exists():
        ev = evaluate(alerts, load_labels(args.labels))
        report.update({
            "labels": ev["labels"],
            "true_positives": ev["true_positives"],
            "false_positives": len(ev["false_positives"]),
            "missed": len(ev["missed"]),
            "recall": round(ev["recall"], 3),
            "precision": round(ev["precision"], 3),
        })
        fp, missed = ev["false_positives"], ev["missed"]
    else:
        fp, missed = [], []

    Path(args.report).write_text(json.dumps(report, indent=2))

    print(f"events loaded : {n_events:,}  ({report['events_per_sec_load']:,} ev/s parse+insert)")
    print(f"alerts        : {len(alerts)}")
    print(f"load  time    : {load_s:.3f}s")
    print(f"detect time   : {detect_s:.3f}s")
    print(f"total time    : {total_s:.3f}s  -> {report['events_per_sec_total']:,} events/sec end to end")
    if "recall" in report:
        print(f"recall        : {report['recall']:.0%}   precision: {report['precision']:.0%}"
              f"   (TP={report['true_positives']} FP={report['false_positives']} missed={report['missed']})")
    for a in alerts:
        print(f"  [{a['rule']:<20}] {a['timestamp']}  {a['source']:<16} {a['details']}")
    for a in fp:
        print(f"  FALSE POSITIVE: {a}")
    for m in missed:
        print(f"  MISSED: {m}")
    conn.close()


if __name__ == "__main__":
    main()
