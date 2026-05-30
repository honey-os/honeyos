"""Tests for backend/api/alerts.py"""

import json

from models import Alert, db
from utils.helpers import generate_id


def _seed_alert(app, **overrides):
    with app.app_context():
        defaults = {
            "id": generate_id(),
            "name": "SSH Alert",
            "enabled": True,
            "alert_type": "webhook",
            "config": json.dumps({"url": "http://example.com/hook"}),
            "conditions": json.dumps({"protocol": "ssh"}),
            "send_count": 0,
        }
        defaults.update(overrides)
        alert = Alert(**defaults)
        db.session.add(alert)
        db.session.commit()
        return alert.id


class TestListAlerts:
    def test_empty_list(self, client):
        resp = client.get("/api/alerts")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data == []

    def test_populated_list(self, client, app):
        _seed_alert(app, name="Alert A")
        _seed_alert(app, name="Alert B")
        resp = client.get("/api/alerts")
        data = resp.get_json()
        assert len(data) == 2


class TestCreateAlert:
    def test_creates_alert(self, client):
        resp = client.post(
            "/api/alerts",
            data=json.dumps({
                "name": "New Alert",
                "alert_type": "webhook",
                "config": {"url": "http://hook.example.com"},
                "conditions": {"protocol": "ssh"},
            }),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["name"] == "New Alert"
        assert data["alert_type"] == "webhook"
        assert data["send_count"] == 0

    def test_missing_name_returns_400(self, client):
        resp = client.post(
            "/api/alerts",
            data=json.dumps({"alert_type": "webhook"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "name" in resp.get_json()["error"]

    def test_missing_alert_type_returns_400(self, client):
        resp = client.post(
            "/api/alerts",
            data=json.dumps({"name": "Test"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "alert_type" in resp.get_json()["error"]


class TestUpdateAlert:
    def test_updates_name(self, client, app):
        aid = _seed_alert(app)
        resp = client.put(
            f"/api/alerts/{aid}",
            data=json.dumps({"name": "Updated Name"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["name"] == "Updated Name"

    def test_updates_enabled(self, client, app):
        aid = _seed_alert(app)
        resp = client.put(
            f"/api/alerts/{aid}",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert resp.get_json()["enabled"] is False

    def test_updates_conditions(self, client, app):
        aid = _seed_alert(app)
        resp = client.put(
            f"/api/alerts/{aid}",
            data=json.dumps({"conditions": {"protocol": "ftp"}}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["conditions"]["protocol"] == "ftp"

    def test_not_found(self, client):
        resp = client.put(
            "/api/alerts/nonexistent",
            data=json.dumps({"name": "X"}),
            content_type="application/json",
        )
        assert resp.status_code == 404
