"""Tests for backend/services/event_processor.py"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from models import DailyStat, Event, Honeypot, Session, db
from services.event_processor import EventProcessor
from utils.helpers import generate_id


class TestProcessEvent:
    def test_persists_event(self, app):
        with app.app_context():
            processor = EventProcessor()
            event = processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "192.168.1.100",
                "destination_port": 2222,
                "severity": "high",
            })
            assert event.id is not None
            assert Event.query.get(event.id) is not None

    def test_event_fields(self, app):
        with app.app_context():
            processor = EventProcessor()
            event = processor.process_event({
                "event_type": "authentication",
                "protocol": "telnet",
                "source_ip": "10.0.0.5",
                "source_port": 45000,
                "destination_port": 2323,
                "severity": "medium",
                "details": {"username": "admin"},
            })
            assert event.event_type == "authentication"
            assert event.protocol == "telnet"
            assert event.source_ip == "10.0.0.5"
            assert event.source_port == 45000
            assert event.destination_port == 2323
            assert json.loads(event.details) == {"username": "admin"}

    def test_sanitizes_inputs(self, app):
        with app.app_context():
            processor = EventProcessor()
            event = processor.process_event({
                "event_type": "<script>alert(1)</script>",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 22,
            })
            assert "<script>" not in event.event_type
            assert "&lt;" in event.event_type

    def test_correlates_active_session(self, app):
        with app.app_context():
            session = Session(
                id=generate_id(),
                source_ip="10.0.0.50",
                protocol="ssh",
                status="active",
                start_time=datetime.now(timezone.utc),
                commands_count=0,
                commands=json.dumps([]),
                keystrokes=json.dumps([]),
                file_transfers=json.dumps([]),
            )
            db.session.add(session)
            db.session.commit()

            processor = EventProcessor()
            event = processor.process_event({
                "event_type": "command",
                "protocol": "ssh",
                "source_ip": "10.0.0.50",
                "destination_port": 2222,
            })
            assert event.session_id == session.id

    def test_increments_honeypot_interaction_count(self, app):
        with app.app_context():
            hp = Honeypot(
                id=generate_id(),
                name="SSH",
                protocol="ssh",
                port=2222,
                total_interactions=0,
            )
            db.session.add(hp)
            db.session.commit()

            processor = EventProcessor()
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })

            db.session.refresh(hp)
            assert hp.total_interactions == 1

    def test_records_to_connection_throttler(self, app):
        with app.app_context():
            throttler = MagicMock()
            throttler.is_blocked.return_value = False
            processor = EventProcessor(connection_throttler=throttler)
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })
            throttler.record_event.assert_called_once_with("10.0.0.1", "ssh")

    def test_triggers_alert_check(self, app):
        with app.app_context():
            alert_service = MagicMock()
            processor = EventProcessor(alert_service=alert_service)
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })
            alert_service.check_conditions.assert_called_once()

    @patch("services.event_processor.Config")
    def test_geoip_disabled_skips_lookup(self, mock_config, app):
        mock_config.GEOIP_ENABLED = False
        with app.app_context():
            processor = EventProcessor()
            processor.geoip_service = MagicMock()
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "8.8.8.8",
                "destination_port": 2222,
            })
            processor.geoip_service.lookup.assert_not_called()


class TestCorrelateSession:
    def test_returns_none_when_no_session(self, app):
        with app.app_context():
            processor = EventProcessor()
            event = Event(
                id=generate_id(),
                event_type="connection",
                protocol="ssh",
                source_ip="10.0.0.1",
            )
            assert processor.correlate_session(event) is None

    def test_returns_active_session(self, app):
        with app.app_context():
            session = Session(
                id=generate_id(),
                source_ip="10.0.0.1",
                protocol="ssh",
                status="active",
                start_time=datetime.now(timezone.utc),
                commands_count=0,
            )
            db.session.add(session)
            db.session.commit()

            processor = EventProcessor()
            event = Event(
                id=generate_id(),
                event_type="command",
                protocol="ssh",
                source_ip="10.0.0.1",
            )
            result = processor.correlate_session(event)
            assert result is not None
            assert result.id == session.id


class TestGetThreatLevel:
    def test_empty_db_returns_low(self, app):
        with app.app_context():
            processor = EventProcessor()
            result = processor.get_threat_level()
            assert result["level"] == "low"
            assert result["score"] == 0
            assert result["recent_events"] == 0

    def test_returns_expected_keys(self, app):
        with app.app_context():
            processor = EventProcessor()
            result = processor.get_threat_level()
            assert "level" in result
            assert "score" in result
            assert "recent_events" in result
            assert "unique_attackers" in result
            assert "unique_protocols" in result


class TestIncrementDailyStat:
    def test_creates_row_on_first_event(self, app):
        with app.app_context():
            processor = EventProcessor()
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })
            today = datetime.now(timezone.utc).date()
            stat = DailyStat.query.filter_by(date=today, protocol="ssh").first()
            assert stat is not None
            assert stat.total_events == 1
            assert stat.connection_events == 1
            assert stat.blocked_events == 0

    def test_increments_existing_row(self, app):
        with app.app_context():
            processor = EventProcessor()
            for _ in range(3):
                processor.process_event({
                    "event_type": "connection",
                    "protocol": "ssh",
                    "source_ip": "10.0.0.1",
                    "destination_port": 2222,
                })
            today = datetime.now(timezone.utc).date()
            stat = DailyStat.query.filter_by(date=today, protocol="ssh").first()
            assert stat.total_events == 3
            assert stat.connection_events == 3

    def test_tracks_auth_and_severity(self, app):
        with app.app_context():
            processor = EventProcessor()
            processor.process_event({
                "event_type": "authentication",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
                "severity": "high",
            })
            today = datetime.now(timezone.utc).date()
            stat = DailyStat.query.filter_by(date=today, protocol="ssh").first()
            assert stat.auth_events == 1
            assert stat.high_severity_events == 1
            assert stat.connection_events == 0

    def test_blocked_ip_increments_blocked_counter(self, app):
        with app.app_context():
            throttler = MagicMock()
            throttler.is_blocked.return_value = True
            processor = EventProcessor(connection_throttler=throttler)
            result = processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })
            assert result is None  # event not persisted
            today = datetime.now(timezone.utc).date()
            stat = DailyStat.query.filter_by(date=today, protocol="ssh").first()
            assert stat is not None
            assert stat.blocked_events == 1
            assert stat.total_events == 0  # not counted as a real event

    def test_separates_protocols(self, app):
        with app.app_context():
            processor = EventProcessor()
            processor.process_event({
                "event_type": "connection",
                "protocol": "ssh",
                "source_ip": "10.0.0.1",
                "destination_port": 2222,
            })
            processor.process_event({
                "event_type": "connection",
                "protocol": "telnet",
                "source_ip": "10.0.0.1",
                "destination_port": 2323,
            })
            today = datetime.now(timezone.utc).date()
            ssh_stat = DailyStat.query.filter_by(date=today, protocol="ssh").first()
            telnet_stat = DailyStat.query.filter_by(date=today, protocol="telnet").first()
            assert ssh_stat.total_events == 1
            assert telnet_stat.total_events == 1
