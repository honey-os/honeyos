"""Tests for backend/api/dashboard.py"""

import json
from datetime import datetime, timezone

from models import Event, Honeypot, Session, db
from utils.helpers import generate_id


def _seed_events(app, count=5):
    with app.app_context():
        for i in range(count):
            event = Event(
                id=generate_id(),
                event_type="connection",
                protocol="ssh",
                source_ip=f"10.0.0.{i + 1}",
                source_port=12345 + i,
                destination_port=2222,
                timestamp=datetime.now(timezone.utc),
                severity="high",
            )
            db.session.add(event)
        db.session.commit()


class TestSummary:
    def test_empty_db_zeroes(self, client):
        resp = client.get("/api/dashboard/summary")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["total_events"] == 0
        assert data["active_sessions"] == 0
        assert data["active_honeypots"] == 0

    def test_response_structure(self, client):
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert "total_events" in data
        assert "active_sessions" in data
        assert "active_honeypots" in data
        assert "threat_level" in data
        assert "top_attackers" in data
        assert "protocol_breakdown" in data
        assert "recent_events" in data
        assert "connections_per_second" in data

    def test_counts_events(self, client, app):
        _seed_events(app, count=3)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["total_events"] == 3

    def test_counts_active_honeypots(self, client, app):
        with app.app_context():
            hp = Honeypot(
                id=generate_id(),
                name="SSH",
                protocol="ssh",
                port=2222,
                enabled=True,
            )
            db.session.add(hp)
            db.session.commit()
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["active_honeypots"] == 1

    def test_counts_active_sessions(self, client, app):
        with app.app_context():
            session = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="ssh",
                start_time=datetime.now(timezone.utc),
                status="active",
                commands_count=0,
            )
            db.session.add(session)
            db.session.commit()
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert data["active_sessions"] == 1

    def test_threat_level_structure(self, client):
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        tl = data["threat_level"]
        assert "level" in tl
        assert "score" in tl

    def test_hours_param(self, client):
        resp = client.get("/api/dashboard/summary?hours=48")
        assert resp.status_code == 200

    def test_top_attackers(self, client, app):
        _seed_events(app, count=3)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert isinstance(data["top_attackers"], list)

    def test_protocol_breakdown(self, client, app):
        _seed_events(app, count=2)
        resp = client.get("/api/dashboard/summary")
        data = resp.get_json()
        assert isinstance(data["protocol_breakdown"], list)


class TestTimeline:
    def test_empty_db(self, client):
        resp = client.get("/api/dashboard/timeline")
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        # All counts should be zero
        assert all(entry["count"] == 0 for entry in data)

    def test_bucket_structure(self, client):
        resp = client.get("/api/dashboard/timeline")
        data = resp.get_json()
        assert len(data) > 0
        for entry in data:
            assert "timestamp" in entry
            assert "count" in entry
            assert entry["timestamp"].endswith("Z")

    def test_hours_param(self, client):
        resp = client.get("/api/dashboard/timeline?hours=1")
        data = resp.get_json()
        # 1 hour / 10-min buckets = 6 buckets
        assert len(data) == 6

    def test_with_events(self, client, app):
        _seed_events(app, count=3)
        resp = client.get("/api/dashboard/timeline")
        data = resp.get_json()
        total = sum(entry["count"] for entry in data)
        assert total == 3
