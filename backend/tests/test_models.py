"""Tests for backend/models/__init__.py"""

import json
from datetime import datetime, timezone

from models import Event, Session, Honeypot, Alert, _utcnow, _iso_utc, _json_col_to_python, db
from utils.helpers import generate_id


class TestUtcnow:
    def test_returns_aware_datetime(self):
        result = _utcnow()
        assert result.tzinfo is not None

    def test_is_utc(self):
        result = _utcnow()
        assert result.tzinfo == timezone.utc


class TestIsoUtc:
    def test_none_returns_none(self):
        assert _iso_utc(None) is None

    def test_naive_datetime_treated_as_utc(self):
        dt = datetime(2024, 1, 15, 12, 0, 0)
        result = _iso_utc(dt)
        assert result.endswith("Z")

    def test_aware_datetime_z_suffix(self):
        dt = datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _iso_utc(dt)
        assert result.endswith("Z")
        assert "+00:00" not in result


class TestJsonColToPython:
    def test_dict_passthrough(self):
        d = {"key": "val"}
        assert _json_col_to_python(d) is d

    def test_list_passthrough(self):
        lst = [1, 2]
        assert _json_col_to_python(lst) is lst

    def test_json_string(self):
        assert _json_col_to_python('{"a": 1}') == {"a": 1}

    def test_none(self):
        assert _json_col_to_python(None) is None

    def test_invalid_string(self):
        assert _json_col_to_python("bad") is None


class TestEventToDict:
    def test_serialization(self, app):
        with app.app_context():
            event = Event(
                id=generate_id(),
                event_type="connection",
                protocol="ssh",
                source_ip="10.0.0.1",
                source_port=12345,
                destination_port=2222,
                timestamp=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
                severity="high",
                details=json.dumps({"username": "root"}),
            )
            db.session.add(event)
            db.session.commit()

            d = event.to_dict()
            assert d["id"] == event.id
            assert d["event_type"] == "connection"
            assert d["protocol"] == "ssh"
            assert d["source_ip"] == "10.0.0.1"
            assert d["severity"] == "high"
            assert d["details"] == {"username": "root"}
            assert d["timestamp"].endswith("Z")


class TestSessionToDict:
    def test_serialization(self, app):
        with app.app_context():
            session = Session(
                id=generate_id(),
                source_ip="10.0.0.2",
                protocol="telnet",
                start_time=datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
                status="active",
                commands_count=3,
                commands=json.dumps([{"command": "ls"}]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(session)
            db.session.commit()

            d = session.to_dict()
            assert d["source_ip"] == "10.0.0.2"
            assert d["protocol"] == "telnet"
            assert d["commands_count"] == 3
            assert d["commands"] == [{"command": "ls"}]
            assert d["status"] == "active"


class TestHoneypotToDict:
    def test_serialization(self, app):
        with app.app_context():
            hp = Honeypot(
                id=generate_id(),
                name="SSH Honeypot",
                protocol="ssh",
                port=2222,
                enabled=True,
                description="Fake SSH server",
                config=json.dumps({"banner": "SSH-2.0-OpenSSH_8.9"}),
                total_interactions=42,
            )
            db.session.add(hp)
            db.session.commit()

            d = hp.to_dict()
            assert d["name"] == "SSH Honeypot"
            assert d["protocol"] == "ssh"
            assert d["port"] == 2222
            assert d["enabled"] is True
            assert d["config"] == {"banner": "SSH-2.0-OpenSSH_8.9"}
            assert d["total_interactions"] == 42


class TestAlertToDict:
    def test_serialization(self, app):
        with app.app_context():
            alert = Alert(
                id=generate_id(),
                name="SSH Alert",
                enabled=True,
                alert_type="webhook",
                config=json.dumps({"url": "http://example.com"}),
                conditions=json.dumps({"protocol": "ssh"}),
                send_count=5,
            )
            db.session.add(alert)
            db.session.commit()

            d = alert.to_dict()
            assert d["name"] == "SSH Alert"
            assert d["alert_type"] == "webhook"
            assert d["config"] == {"url": "http://example.com"}
            assert d["conditions"] == {"protocol": "ssh"}
            assert d["send_count"] == 5
