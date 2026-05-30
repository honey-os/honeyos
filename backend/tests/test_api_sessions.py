"""Tests for backend/api/sessions.py"""

import json
from datetime import datetime, timezone

from models import Session, db
from utils.helpers import generate_id


def _seed_session(app, **overrides):
    with app.app_context():
        defaults = {
            "id": generate_id(),
            "source_ip": "10.0.0.1",
            "protocol": "ssh",
            "start_time": datetime.now(timezone.utc),
            "status": "completed",
            "commands_count": 3,
            "commands": json.dumps([
                {"command": "whoami", "output": "root", "timestamp": datetime.now(timezone.utc).isoformat()},
            ]),
            "keystrokes": json.dumps([]),
            "file_transfers": json.dumps([]),
        }
        defaults.update(overrides)
        session = Session(**defaults)
        db.session.add(session)
        db.session.commit()
        return session.id


class TestListSessions:
    def test_empty_list(self, client):
        resp = client.get("/api/sessions")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_populated_list(self, client, app):
        _seed_session(app)
        _seed_session(app)
        resp = client.get("/api/sessions")
        data = resp.get_json()
        assert data["total"] == 2

    def test_filter_by_protocol(self, client, app):
        _seed_session(app, protocol="ssh")
        _seed_session(app, protocol="telnet")
        resp = client.get("/api/sessions?protocol=ssh")
        data = resp.get_json()
        assert data["total"] == 1

    def test_pagination(self, client, app):
        for _ in range(5):
            _seed_session(app)
        resp = client.get("/api/sessions?per_page=2&page=1")
        data = resp.get_json()
        assert len(data["items"]) == 2
        assert data["pages"] == 3


class TestGetSession:
    def test_found(self, client, app):
        sid = _seed_session(app)
        resp = client.get(f"/api/sessions/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["id"] == sid
        assert "events" in data

    def test_not_found(self, client):
        resp = client.get("/api/sessions/nonexistent")
        assert resp.status_code == 404


class TestReplaySession:
    def test_not_found(self, client):
        resp = client.get("/api/sessions/nonexistent/replay")
        assert resp.status_code == 404

    def test_found_returns_replay(self, client, app):
        sid = _seed_session(app, commands=json.dumps([
            {
                "command": "ls",
                "output": "Desktop Documents",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        ]))
        resp = client.get(f"/api/sessions/{sid}/replay")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["session_id"] == sid
        assert "entries" in data
