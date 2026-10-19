"""Compare alerts against a labels file -> recall / precision.

An alert matches a label when the rule name and source agree and the alert fired inside the
label's [start, end] window (plus a little slack, since a threshold is crossed partway
through an attack, never exactly at its end).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta


def load_labels(path: str) -> list[dict]:
    with open(path) as fh:
        return json.load(fh)


def evaluate(alerts: list[dict], labels: list[dict], slack: timedelta = timedelta(minutes=2)) -> dict:
    matched_labels: set[int] = set()
    true_positive_alerts = 0
    false_positives: list[dict] = []

    for a in alerts:
        a_ts = datetime.fromisoformat(a["timestamp"])
        hit = False
        for i, lab in enumerate(labels):
            if lab["rule"] != a["rule"] or lab["source"] != a["source"]:
                continue
            start = datetime.fromisoformat(lab["start"]) - slack
            end = datetime.fromisoformat(lab["end"]) + slack
            if start <= a_ts <= end:
                matched_labels.add(i)
                hit = True
                break
        if hit:
            true_positive_alerts += 1
        else:
            false_positives.append(a)

    missed = [lab for i, lab in enumerate(labels) if i not in matched_labels]
    recall = len(matched_labels) / len(labels) if labels else 1.0
    precision = true_positive_alerts / len(alerts) if alerts else 1.0
    return {
        "labels": len(labels),
        "alerts": len(alerts),
        "true_positives": true_positive_alerts,
        "false_positives": false_positives,
        "missed": missed,
        "recall": recall,
        "precision": precision,
    }
