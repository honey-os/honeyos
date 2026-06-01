"""Tests for backend/api/honeypots.py"""

import json

from models import Honeypot, db
from utils.helpers import generate_id


def _seed_honeypot(app, **overrides):
    with app.app_context():
        defaults = {
            "id": generate_id(),
            "name": "SSH Honeypot",
            "protocol": "ssh",
            "port": 2222,
            "enabled": True,
            "total_interactions": 0,
        }
        defaults.update(overrides)
        hp = Honeypot(**defaults)
        db.session.add(hp)
        db.session.commit()
        return hp.id


class TestListHoneypots:
    def test_empty_list(self, client):
        resp = client.get("/api/honeypots")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data == []

    def test_populated_list(self, client, app):
        _seed_honeypot(app, name="SSH", protocol="ssh", port=2222)
        _seed_honeypot(app, name="Telnet", protocol="telnet", port=2323)
        resp = client.get("/api/honeypots")
        data = resp.get_json()
        assert len(data) == 2
        # Should be ordered by name
        names = [h["name"] for h in data]
        assert names == sorted(names)

    def test_honeypot_structure(self, client, app):
        _seed_honeypot(app)
        resp = client.get("/api/honeypots")
        hp = resp.get_json()[0]
        assert "id" in hp
        assert "name" in hp
        assert "protocol" in hp
        assert "port" in hp
        assert "enabled" in hp
