"""Streamlit dashboard.  Run:  streamlit run dashboard.py"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from minisiem import db

st.set_page_config(page_title="Mini SIEM", layout="wide")
st.title("Mini SIEM — Security Event Correlation")

db_path = st.sidebar.text_input("SQLite database", "data/siem.db")
if not Path(db_path).exists():
    st.warning(f"No database at `{db_path}`. Run `python run.py` first.")
    st.stop()

conn = db.connect(db_path)
events_hourly = db.events_per_hour(conn)
top_ips = db.top_failing_ips(conn)
alerts = db.load_alerts(conn)
n_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

# --- headline numbers
report_path = Path(db_path).with_name("benchmark.json")
c1, c2, c3, c4 = st.columns(4)
c1.metric("Events", f"{n_events:,}")
c2.metric("Alerts", len(alerts))
if report_path.exists():
    rep = json.loads(report_path.read_text())
    c3.metric("Events / sec", f"{rep.get('events_per_sec_total', 0):,}")
    if "recall" in rep:
        c4.metric("Recall / Precision", f"{rep['recall']:.0%} / {rep['precision']:.0%}")

# --- events over time
st.subheader("Events over time (per hour)")
if not events_hourly.empty:
    events_hourly["hour"] = pd.to_datetime(events_hourly["hour"])
    st.line_chart(events_hourly.set_index("hour")[["successes", "failures"]])

# --- top offending IPs
left, right = st.columns([1, 2])
with left:
    st.subheader("Top offending IPs (failures)")
    st.bar_chart(top_ips.set_index("source_ip")["failures"])
    st.dataframe(top_ips, hide_index=True, width="stretch")

# --- alerts
with right:
    st.subheader("Alerts")
    if alerts.empty:
        st.info("No alerts.")
    else:
        rule_filter = st.multiselect("Rule", sorted(alerts["rule"].unique()),
                                     default=sorted(alerts["rule"].unique()))
        st.dataframe(alerts[alerts["rule"].isin(rule_filter)].drop(columns=["id"]),
                     hide_index=True, width="stretch")
