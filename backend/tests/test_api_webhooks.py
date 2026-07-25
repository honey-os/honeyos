"""
Tests for the canarytokens.org webhook endpoint.
"""

import json

import pytest

from api.webhooks import WEBHOOK_SECRET_CONFIG_KEY, get_webhook_secret
from models import Event, SystemConfig, db
from services import deception
from services.event_processor import EventProcessor
from services.webhook_server import CanaryWebhookServer


SAMPLE_TRIGGER = {
    "manage_url": "https://canarytokens.org/manage?token=abc123",
    "memo": "AWS key planted in honeypot .env",
    "channel": "HTTP",
    "time": "2026-07-25 14:00:00 (UTC)",
    "additional_data": {
        "src_ip": "198.51.100.99",
        "useragent": "aws-cli/2.15.0",
        "geo_info": {"country": "NL"},
    },
}


def _server(app):
    return CanaryWebhookServer(
        port=7779, app=app, event_processor=EventProcessor(),
    )


class TestWebhookSecret:
    def test_generated_once_and_persisted(self, app):
        with app.app_context():
            first = get_webhook_secret()
            assert len(first) >= 24
            assert get_webhook_secret() == first
            row = db.session.get(SystemConfig, WEBHOOK_SECRET_CONFIG_KEY)
            assert row.value == first

    def test_info_endpoint_returns_url(self, app, client):
        resp = client.get("/api/webhooks/canarytokens")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["enabled"] is True
        assert body["port"] == 7779
        with app.app_context():
            assert get_webhook_secret() in body["webhook_url"]


class TestCanarytokenTrigger:
    def test_valid_trigger_creates_critical_event(self, app):
        with app.app_context():
            secret = get_webhook_secret()

        code, body = _server(app).dispatch(
            f"/canarytokens/{secret}", json.dumps(SAMPLE_TRIGGER).encode(),
        )
        assert code == 200
        assert body == {"status": "ok"}

        with app.app_context():
            event = Event.query.filter_by(protocol="canary").one()
            assert event.event_type == "canarytoken_triggered"
            assert event.severity == "critical"
            assert event.source_ip == "198.51.100.99"
            assert event.user_agent == "aws-cli/2.15.0"
            details = json.loads(event.details)
            assert details["memo"] == "AWS key planted in honeypot .env"
            assert details["channel"] == "HTTP"

    def test_wrong_secret_rejected_without_event(self, app):
        with app.app_context():
            get_webhook_secret()

        code, _ = _server(app).dispatch(
            "/canarytokens/not-the-secret", json.dumps(SAMPLE_TRIGGER).encode(),
        )
        assert code == 404
        with app.app_context():
            assert Event.query.filter_by(protocol="canary").count() == 0

    def test_non_webhook_path_is_404(self, app):
        code, _ = _server(app).dispatch("/", b"")
        assert code == 404

    def test_empty_payload_still_accepted(self, app):
        """canarytokens.org payload shape isn't contractual -- never bounce."""
        with app.app_context():
            secret = get_webhook_secret()

        code, _ = _server(app).dispatch(f"/canarytokens/{secret}", b"")
        assert code == 200
        with app.app_context():
            event = Event.query.filter_by(protocol="canary").one()
            assert event.source_ip == "0.0.0.0"

    def test_malformed_json_still_accepted(self, app):
        with app.app_context():
            secret = get_webhook_secret()

        code, _ = _server(app).dispatch(f"/canarytokens/{secret}", b"not json{{")
        assert code == 200
        with app.app_context():
            assert Event.query.filter_by(protocol="canary").count() == 1


class TestCanaryAwsPlanting:
    @pytest.fixture(autouse=True)
    def _fresh_secrets(self):
        deception.reset_cache()
        yield
        deception.reset_cache()

    def test_env_has_no_aws_block_by_default(self):
        site = deception.build_site()
        assert "AWS_ACCESS_KEY_ID" not in site["/.env"][0]

    def test_configured_canary_creds_appear_in_env(self):
        db.session.add(SystemConfig(
            key=deception.CANARY_AWS_KEY_ID_CONFIG,
            value="AKIAIOSFODNN7EXAMPLE",
        ))
        db.session.add(SystemConfig(
            key=deception.CANARY_AWS_SECRET_CONFIG,
            value="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ))
        db.session.commit()

        env = deception.build_site()["/.env"][0]
        assert "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" in env
        assert "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in env
        assert "AWS_DEFAULT_REGION" in env
