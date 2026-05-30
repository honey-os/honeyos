"""Tests for backend/api/events.py"""

import json
from datetime import datetime, timezone

from models import Event, db
from utils.helpers import generate_id


def _seed_event(app, **overrides):
    with app.app_context():
        defaults = {
            "id": generate_id(),
            "event_type": "connection",
            "protocol": "ssh",
            "source_ip": "10.0.0.1",
            "source_port": 12345,
            "destination_port": 2222,
            "timestamp": datetime.now(timezone.utc),
            "severity": "high",
        }
        defaults.update(overrides)
        event = Event(**defaults)
        db.session.add(event)
        db.session.commit()
        return event.id


class TestListEvents:
    def test_empty_list(self, client):
        resp = client.get("/api/events")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_populated_list(self, client, app):
        _seed_event(app)
        _seed_event(app)
        resp = client.get("/api/events")
        data = resp.get_json()
        assert data["total"] == 2
        assert len(data["items"]) == 2

    def test_filter_by_protocol(self, client, app):
        _seed_event(app, protocol="ssh")
        _seed_event(app, protocol="telnet")
        resp = client.get("/api/events?protocol=ssh")
        data = resp.get_json()
        assert data["total"] == 1
        assert data["items"][0]["protocol"] == "ssh"

    def test_filter_by_event_type(self, client, app):
        _seed_event(app, event_type="authentication")
        _seed_event(app, event_type="command")
        resp = client.get("/api/events?event_type=command")
        data = resp.get_json()
        assert data["total"] == 1

    def test_filter_by_severity(self, client, app):
        _seed_event(app, severity="high")
        _seed_event(app, severity="low")
        resp = client.get("/api/events?severity=high")
        data = resp.get_json()
        assert data["total"] == 1

    def test_pagination(self, client, app):
        for _ in range(5):
            _seed_event(app)
        resp = client.get("/api/events?per_page=2&page=1")
        data = resp.get_json()
        assert len(data["items"]) == 2
        assert data["total"] == 5
        assert data["pages"] == 3

    def test_pagination_page_2(self, client, app):
        for _ in range(5):
            _seed_event(app)
        resp = client.get("/api/events?per_page=2&page=2")
        data = resp.get_json()
        assert len(data["items"]) == 2

    def test_response_structure(self, client, app):
        _seed_event(app)
        resp = client.get("/api/events")
        data = resp.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert "pages" in data


class TestGetEvent:
    def test_found(self, client, app):
        eid = _seed_event(app)
        resp = client.get(f"/api/events/{eid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == eid

    def test_not_found(self, client):
        resp = client.get("/api/events/nonexistent-id")
        assert resp.status_code == 404


class TestCreateEvent:
    def test_creates_event(self, client):
        resp = client.post(
            "/api/events",
            data=json.dumps({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
                "severity": "high",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["event_type"] == "connection"
        assert data["protocol"] == "ssh"


class TestExportEvents:
    def test_csv_export_empty(self, client):
        resp = client.get("/api/events/export")
        assert resp.status_code == 200
        assert resp.content_type.startswith("text/csv")
        lines = resp.data.decode().strip().split("\n")
        assert len(lines) == 1  # header only

    def test_csv_export_with_data(self, client, app):
        _seed_event(app)
        _seed_event(app)
        resp = client.get("/api/events/export")
        assert resp.status_code == 200
        lines = resp.data.decode().strip().split("\n")
        assert len(lines) == 3  # header + 2 rows

    def test_csv_has_disposition_header(self, client):
        resp = client.get("/api/events/export")
        assert "Content-Disposition" in resp.headers
        assert "honeyos-events" in resp.headers["Content-Disposition"]

    def test_csv_filter_applied(self, client, app):
        _seed_event(app, protocol="ssh")
        _seed_event(app, protocol="ftp")
        resp = client.get("/api/events/export?protocol=ssh")
        lines = resp.data.decode().strip().split("\n")
        assert len(lines) == 2  # header + 1 filtered row
