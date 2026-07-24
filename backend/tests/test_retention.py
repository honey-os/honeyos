"""
Tests for services.retention -- daily aggregation and batched purging.
"""

import json
from datetime import datetime, timedelta, timezone

from models import DailyStat, Event, Session, db
from services.retention import aggregate_day, enforce_retention
from utils.helpers import generate_id


def _naive_utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _add_event(ts, protocol="ssh", event_type="connection",
               source_ip="10.0.0.1", details=None, severity="medium"):
    event = Event(
        id=generate_id(),
        event_type=event_type,
        protocol=protocol,
        source_ip=source_ip,
        timestamp=ts,
        severity=severity,
        details=json.dumps(details) if details else None,
    )
    db.session.add(event)
    return event


def _add_session(start_time, status="completed", source_ip="10.0.0.1"):
    session = Session(
        id=generate_id(),
        source_ip=source_ip,
        protocol="ssh",
        start_time=start_time,
        status=status,
    )
    db.session.add(session)
    return session


class TestEnforceRetention:
    def test_deletes_old_keeps_recent(self):
        now = _naive_utc_now()
        old = now - timedelta(days=10)
        recent = now - timedelta(hours=1)

        _add_event(old)
        _add_event(old + timedelta(minutes=5))
        _add_event(old, protocol="http")
        kept_event = _add_event(recent)

        _add_session(old, status="completed")
        stale_active = _add_session(old, status="active")
        kept_session = _add_session(recent, status="completed")
        db.session.commit()

        deleted_events, deleted_sessions = enforce_retention(retention_days=7)

        assert deleted_events == 3
        assert deleted_sessions == 1
        remaining_events = Event.query.all()
        assert [e.id for e in remaining_events] == [kept_event.id]
        remaining_ids = {s.id for s in Session.query.all()}
        # Active sessions are never purged, even if old
        assert remaining_ids == {stale_active.id, kept_session.id}

    def test_aggregates_before_deleting(self):
        now = _naive_utc_now()
        old = now - timedelta(days=10)

        _add_event(old, source_ip="10.0.0.1")
        _add_event(old + timedelta(minutes=1), source_ip="10.0.0.2")
        _add_event(
            old + timedelta(minutes=2),
            event_type="authentication",
            details={"username": "root", "password": "hunter2"},
        )
        db.session.commit()

        enforce_retention(retention_days=7)

        stat = DailyStat.query.filter_by(date=old.date(), protocol="ssh").one()
        assert stat.total_events == 3
        assert stat.auth_events == 1
        assert stat.unique_source_ips == 2
        top_ips = {entry["ip"] for entry in json.loads(stat.top_source_ips)}
        assert top_ips == {"10.0.0.1", "10.0.0.2"}
        assert json.loads(stat.top_usernames) == [{"username": "root", "count": 1}]
        assert json.loads(stat.top_passwords) == [{"password": "hunter2", "count": 1}]

    def test_delete_runs_in_batches(self):
        now = _naive_utc_now()
        old = now - timedelta(days=10)
        for i in range(7):
            _add_event(old + timedelta(seconds=i))
        db.session.commit()

        deleted_events, _ = enforce_retention(retention_days=7, batch_size=2)

        assert deleted_events == 7
        assert Event.query.count() == 0

    def test_empty_database(self):
        assert enforce_retention(retention_days=7) == (0, 0)

    def test_noop_run_still_logs(self, caplog):
        import logging

        with caplog.at_level(logging.INFO, logger="honeyos"):
            enforce_retention(retention_days=7)

        assert any("Retention: pruned 0 events" in r.message for r in caplog.records)

    def test_finalized_days_skip_aggregation(self, monkeypatch):
        import services.retention as retention_mod

        now = _naive_utc_now()
        old = now - timedelta(days=10)
        _add_event(old)
        # Fully finalized stat row for the old day
        db.session.add(DailyStat(
            id=generate_id(),
            date=old.date(),
            protocol="ssh",
            total_events=1,
            top_source_ips=json.dumps([{"ip": "10.0.0.1", "count": 1}]),
        ))
        db.session.commit()

        aggregated_days = []
        monkeypatch.setattr(
            retention_mod, "aggregate_day",
            lambda day: aggregated_days.append(day),
        )

        deleted_events, _ = enforce_retention(retention_days=7)

        # The finalized day was not re-scanned (days with no stat rows at
        # all, e.g. gap days, still get a cheap aggregate_day probe)
        assert old.date() not in aggregated_days
        assert deleted_events == 1

    def test_unfinalized_days_still_aggregate(self, monkeypatch):
        import services.retention as retention_mod

        now = _naive_utc_now()
        old = now - timedelta(days=10)
        _add_event(old)
        # Real-time row exists but top-N fields were never filled in
        db.session.add(DailyStat(
            id=generate_id(),
            date=old.date(),
            protocol="ssh",
            total_events=1,
        ))
        db.session.commit()

        aggregated_days = []
        monkeypatch.setattr(
            retention_mod, "aggregate_day",
            lambda day: aggregated_days.append(day),
        )

        enforce_retention(retention_days=7)

        assert old.date() in aggregated_days


class TestAggregateDay:
    def test_idempotent(self):
        now = _naive_utc_now()
        old = now - timedelta(days=10)
        _add_event(old)
        _add_event(old + timedelta(minutes=1))
        db.session.commit()

        aggregate_day(old.date())
        aggregate_day(old.date())

        stats = DailyStat.query.filter_by(date=old.date()).all()
        assert len(stats) == 1
        assert stats[0].total_events == 2

    def test_enriches_realtime_row_without_double_counting(self):
        now = _naive_utc_now()
        old = now - timedelta(days=10)
        _add_event(old, source_ip="10.9.9.9")
        # Simulate the row the event processor maintains in real time
        db.session.add(DailyStat(
            id=generate_id(),
            date=old.date(),
            protocol="ssh",
            total_events=1,
            connection_events=1,
        ))
        db.session.commit()

        aggregate_day(old.date())

        stat = DailyStat.query.filter_by(date=old.date(), protocol="ssh").one()
        assert stat.total_events == 1
        assert stat.unique_source_ips == 1
        assert json.loads(stat.top_source_ips) == [{"ip": "10.9.9.9", "count": 1}]
