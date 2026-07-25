"""
Tests for services.deception -- planted secrets, bait content, and
honeytoken replay detection.
"""

import json

import pytest

from config import Config
from models import SystemConfig, db
from services import deception
from services.event_processor import EventProcessor


@pytest.fixture(autouse=True)
def _fresh_secrets():
    """Each test starts with no cached secrets."""
    deception.reset_cache()
    yield
    deception.reset_cache()


class TestPlantedSecrets:
    def test_generated_once_and_persisted(self):
        first = deception.get_secrets()
        assert first["db_password"]
        assert first["app_key"].startswith("base64:")
        assert "FAKE" not in first["app_key"]

        # Persisted to system_config
        row = db.session.get(SystemConfig, deception.SECRETS_CONFIG_KEY)
        assert row is not None
        assert json.loads(row.value) == first

        # Stable across cache resets (i.e. across restarts/workers)
        deception.reset_cache()
        assert deception.get_secrets() == first

    def test_installs_differ(self):
        # Two independent generations must not collide (per-install variance)
        assert (
            deception._generate_secrets()["db_password"]
            != deception._generate_secrets()["db_password"]
        )


class TestBaitSite:
    def test_planted_creds_are_consistent_across_files(self):
        s = deception.get_secrets()
        site = deception.build_site()

        env = site["/.env"][0]
        assert f"DB_PASSWORD={s['db_password']}" in env
        assert f"DB_USERNAME={s['db_username']}" in env
        assert s["app_key"] in env

        for path in ("/config.php", "/wp-config.php"):
            assert s["db_password"] in site[path][0]
            assert s["db_username"] in site[path][0]

        assert s["db_password"] in site["/backup/db_backup.sql"][0]

    def test_env_points_at_mysql_honeypot_external_port(self):
        site = deception.build_site()
        expected = Config.EXTERNAL_PORT.get("mysql", 3306)
        assert f"DB_PORT={expected}" in site["/.env"][0]

    def test_every_advertised_path_is_served(self):
        """The fiction stays consistent: everything the index page and
        robots.txt point at (and every sensitive path) actually resolves."""
        site = deception.build_site()
        for path in ("/docs/", "/images/", "/backup/", "/config.php", "/.env"):
            assert path in site
        for path in deception.SENSITIVE_PATHS:
            assert path in site

    def test_build_site_for_without_app_falls_back(self):
        site = deception.build_site_for(None)
        assert "DB_PASSWORD=" in site["/.env"][0]


class TestHoneytokenDetection:
    def test_password_field_match(self):
        s = deception.get_secrets()
        assert deception.check_event_for_honeytoken(
            {"username": "anything", "password": s["db_password"]}
        )

    def test_body_substring_match(self):
        s = deception.get_secrets()
        body = f"username=webapp&password={s['db_password']}"
        assert deception.check_event_for_honeytoken({"body": body})

    def test_raw_payload_match(self):
        s = deception.get_secrets()
        assert deception.check_event_for_honeytoken({}, raw_payload=s["db_password"])

    def test_no_match_on_other_creds(self):
        deception.get_secrets()
        assert not deception.check_event_for_honeytoken(
            {"username": "root", "password": "admin123"}
        )

    def test_username_alone_does_not_match(self):
        s = deception.get_secrets()
        assert not deception.check_event_for_honeytoken(
            {"username": s["db_username"], "password": "wrong"}
        )


class TestEventProcessorIntegration:
    def test_replayed_honeytoken_escalates_event(self):
        s = deception.get_secrets()
        processor = EventProcessor()

        event = processor.process_event({
            "event_type": "authentication",
            "protocol": "mysql",
            "source_ip": "203.0.113.7",
            "destination_port": 3307,
            "severity": "medium",
            "details": {"username": s["db_username"], "password": s["db_password"]},
        })

        assert event.severity == "critical"
        assert json.loads(event.details)["honeytoken"] is True

    def test_normal_auth_event_unchanged(self):
        deception.get_secrets()
        processor = EventProcessor()

        event = processor.process_event({
            "event_type": "authentication",
            "protocol": "ssh",
            "source_ip": "203.0.113.8",
            "destination_port": 2222,
            "severity": "medium",
            "details": {"username": "root", "password": "toor"},
        })

        assert event.severity == "medium"
        assert "honeytoken" not in json.loads(event.details)
