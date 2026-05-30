"""Tests for backend/services/alert_service.py"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from models import Alert, Event, db
from services.alert_service import AlertService
from utils.helpers import generate_id


def _make_event(**kwargs) -> Event:
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
    defaults.update(kwargs)
    return Event(**defaults)


class TestMatches:
    def test_empty_conditions_always_matches(self):
        service = AlertService()
        event = _make_event()
        assert service._matches({}, event) is True

    def test_event_type_match(self):
        service = AlertService()
        event = _make_event(event_type="authentication")
        assert service._matches({"event_type": "authentication"}, event) is True
        assert service._matches({"event_type": "connection"}, event) is False

    def test_protocol_case_insensitive(self):
        service = AlertService()
        event = _make_event(protocol="SSH")
        assert service._matches({"protocol": "ssh"}, event) is True
        assert service._matches({"protocol": "SSH"}, event) is True

    def test_severity_list(self):
        service = AlertService()
        event = _make_event(severity="high")
        assert service._matches({"severity": ["high", "critical"]}, event) is True
        assert service._matches({"severity": ["low"]}, event) is False

    def test_severity_string(self):
        service = AlertService()
        event = _make_event(severity="medium")
        assert service._matches({"severity": "medium"}, event) is True
        assert service._matches({"severity": "high"}, event) is False

    def test_source_ip_match(self):
        service = AlertService()
        event = _make_event(source_ip="192.168.1.1")
        assert service._matches({"source_ip": "192.168.1.1"}, event) is True
        assert service._matches({"source_ip": "10.0.0.1"}, event) is False

    def test_multiple_conditions_all_must_match(self):
        service = AlertService()
        event = _make_event(
            event_type="authentication",
            protocol="ssh",
            severity="high",
        )
        conditions = {
            "event_type": "authentication",
            "protocol": "ssh",
            "severity": ["high", "critical"],
        }
        assert service._matches(conditions, event) is True

    def test_multiple_conditions_partial_fails(self):
        service = AlertService()
        event = _make_event(event_type="connection", protocol="ssh")
        conditions = {"event_type": "authentication", "protocol": "ssh"}
        assert service._matches(conditions, event) is False


class TestCooldown:
    def test_no_last_sent_allows(self):
        service = AlertService()
        alert = MagicMock()
        alert.last_sent = None
        assert service._cooldown_ok(alert) is True

    def test_within_cooldown_blocks(self):
        service = AlertService()
        service.cooldown_seconds = 300
        alert = MagicMock()
        alert.last_sent = datetime.now(timezone.utc) - timedelta(seconds=60)
        assert service._cooldown_ok(alert) is False

    def test_past_cooldown_allows(self):
        service = AlertService()
        service.cooldown_seconds = 300
        alert = MagicMock()
        alert.last_sent = datetime.now(timezone.utc) - timedelta(seconds=600)
        assert service._cooldown_ok(alert) is True


class TestBuildPayload:
    def test_payload_structure(self):
        alert = MagicMock()
        alert.id = "alert-1"
        alert.name = "SSH Alert"

        event = _make_event(
            event_type="authentication",
            protocol="ssh",
            source_ip="10.0.0.5",
            severity="high",
        )

        payload = AlertService._build_payload(alert, event)
        assert "subject" in payload
        assert "body" in payload
        assert "SSH Alert" in payload["subject"]
        assert "10.0.0.5" in payload["subject"]
        assert payload["alert_name"] == "SSH Alert"
        assert payload["event_type"] == "authentication"
        assert payload["source_ip"] == "10.0.0.5"
        assert payload["protocol"] == "ssh"


class TestCheckConditions:
    def test_matching_alert_triggers_send(self, app):
        with app.app_context():
            alert = Alert(
                id=generate_id(),
                name="All Events",
                enabled=True,
                alert_type="webhook",
                config=json.dumps({"url": "http://example.com/hook"}),
                conditions=json.dumps({}),
                send_count=0,
            )
            db.session.add(alert)
            db.session.commit()

            service = AlertService()
            service.send_alert = MagicMock(return_value=True)
            event = _make_event()
            service.check_conditions(event)
            service.send_alert.assert_called_once()

    def test_disabled_alert_skipped(self, app):
        with app.app_context():
            alert = Alert(
                id=generate_id(),
                name="Disabled",
                enabled=False,
                alert_type="webhook",
                config=json.dumps({}),
                conditions=json.dumps({}),
                send_count=0,
            )
            db.session.add(alert)
            db.session.commit()

            service = AlertService()
            service.send_alert = MagicMock()
            event = _make_event()
            service.check_conditions(event)
            service.send_alert.assert_not_called()

    def test_non_matching_conditions_skipped(self, app):
        with app.app_context():
            alert = Alert(
                id=generate_id(),
                name="SSH Only",
                enabled=True,
                alert_type="webhook",
                config=json.dumps({}),
                conditions=json.dumps({"protocol": "ftp"}),
                send_count=0,
            )
            db.session.add(alert)
            db.session.commit()

            service = AlertService()
            service.send_alert = MagicMock()
            event = _make_event(protocol="ssh")
            service.check_conditions(event)
            service.send_alert.assert_not_called()
