from datetime import datetime, timedelta

from minisiem import rules


def ev(ts: datetime, user: str, ip: str, ok: bool) -> dict:
    return {"timestamp": ts.isoformat(), "username": user, "source_ip": ip, "success": int(ok)}


T0 = datetime(2026, 10, 12, 14, 0, 0)


# ------------------------------------------------------------------ brute force
def test_brute_force_fires_on_burst():
    events = [ev(T0 + timedelta(seconds=i * 2), "bob", "203.0.113.50", False) for i in range(50)]
    alerts = rules.detect_brute_force(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule"] == "brute_force"
    assert alerts[0]["source"] == "203.0.113.50"


def test_brute_force_quiet_when_failures_are_spread_out():
    # 50 failures, but one every 10 minutes -> never 20 inside a 2-minute window
    events = [ev(T0 + timedelta(minutes=10 * i), "bob", "203.0.113.50", False) for i in range(50)]
    assert rules.detect_brute_force(events) == []


def test_brute_force_ignores_successes():
    events = [ev(T0 + timedelta(seconds=i), "bob", "10.0.0.1", True) for i in range(100)]
    assert rules.detect_brute_force(events) == []


# ------------------------------------------------------------------ credential stuffing
def test_credential_stuffing_fires_on_many_usernames():
    events = [ev(T0 + timedelta(seconds=i * 6), f"user{i}", "198.51.100.77", False) for i in range(40)]
    alerts = rules.detect_credential_stuffing(events)
    assert len(alerts) >= 1
    assert alerts[0]["rule"] == "credential_stuffing"
    assert alerts[0]["source"] == "198.51.100.77"


def test_credential_stuffing_quiet_for_one_username():
    # Same IP, 40 failures, but always the same user -> brute force, not stuffing
    events = [ev(T0 + timedelta(seconds=i * 6), "bob", "198.51.100.77", False) for i in range(40)]
    assert rules.detect_credential_stuffing(events) == []


def test_credential_stuffing_window_slides():
    # 5 distinct users now, 5 different ones an hour later -> never 10 in one window
    events = [ev(T0 + timedelta(seconds=i), f"u{i}", "1.2.3.4", False) for i in range(5)]
    events += [ev(T0 + timedelta(hours=1, seconds=i), f"v{i}", "1.2.3.4", False) for i in range(5)]
    assert rules.detect_credential_stuffing(events) == []


# ------------------------------------------------------------------ off-hours
def _history(user: str, hours: list[int], days: int = 5) -> list[dict]:
    out = []
    for d in range(days):
        for h in hours:
            out.append(ev(T0.replace(hour=h) + timedelta(days=d), user, "10.0.0.5", True))
    return out


def test_off_hours_fires_for_3am_login_by_business_hours_user():
    events = _history("alice", [9, 11, 14, 16])          # 20 daytime successes
    events.append(ev(T0.replace(hour=3) + timedelta(days=6), "alice", "192.0.2.99", True))
    alerts = rules.detect_off_hours(events)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "off_hours_login"
    assert alerts[0]["source"] == "alice"
    assert alerts[0]["timestamp"].endswith("T03:00:00")


def test_off_hours_quiet_for_night_shift_user():
    events = _history("trent", [22, 23, 1, 3])          # always overnight
    events.append(ev(T0.replace(hour=2) + timedelta(days=6), "trent", "10.0.0.5", True))
    assert rules.detect_off_hours(events) == []


def test_off_hours_needs_history_before_judging():
    # Only 2 prior logins -> no baseline yet -> no alert even at 3am
    events = _history("newbie", [9, 10], days=1)
    events.append(ev(T0.replace(hour=3) + timedelta(days=1), "newbie", "10.0.0.5", True))
    assert rules.detect_off_hours(events) == []


# ------------------------------------------------------------------ run_all / dataframe input
def test_run_all_accepts_dataframe():
    import pandas as pd
    events = [ev(T0 + timedelta(seconds=i * 2), "bob", "203.0.113.50", False) for i in range(50)]
    df = pd.DataFrame(events)
    alerts = rules.run_all(df)
    assert any(a["rule"] == "brute_force" for a in alerts)
