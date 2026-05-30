"""
Shared test fixtures for HoneyOS backend tests.
"""

import os
import sys

# Ensure the backend directory is on sys.path so imports work like production.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import pytest
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO

from models import db


class TestConfig:
    """Minimal config for test runs -- in-memory SQLite, no port binding."""

    SECRET_KEY = "test-secret"
    DEBUG = False
    READ_ONLY = False
    DATABASE_URL = "sqlite://"
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {}
    GEOIP_ENABLED = False
    ALERT_COOLDOWN_SECONDS = 300
    THROTTLE_EVENT_THRESHOLD = 5
    THROTTLE_BLOCK_SECONDS = 60
    MAX_CONNECTIONS_PER_IP = 3
    LOG_LEVEL = "WARNING"
    SESSION_TIMEOUT_HOURS = 168
    ABUSECH_API_KEY = ""
    CENSYS_API_TOKEN = ""
    PUBLIC_IP = ""

    # Honeypot ports (never actually bound in tests)
    SSH_HONEYPOT_PORT = 2222
    HTTP_HONEYPOT_PORT = 8080
    HTTPS_HONEYPOT_PORT = 8443
    TELNET_HONEYPOT_PORT = 2323
    FTP_HONEYPOT_PORT = 2121
    MYSQL_HONEYPOT_PORT = 3307
    POSTGRESQL_HONEYPOT_PORT = 5433
    DNS_HONEYPOT_PORT = 5353
    SMB_HONEYPOT_PORT = 4450
    RDP_HONEYPOT_PORT = 3390

    HONEYPOT_ENABLED: dict[str, bool] = {
        p: False for p in (
            "ssh", "http", "https", "telnet", "ftp",
            "mysql", "postgresql", "dns", "smb", "rdp",
        )
    }

    EXTERNAL_PORT: dict[str, int] = {
        "ssh": 22, "http": 80, "https": 443, "telnet": 23,
        "ftp": 21, "mysql": 3306, "postgresql": 5432, "dns": 53,
        "smb": 445, "rdp": 3389,
    }

    # SMTP / Slack (unused in tests)
    SMTP_HOST = ""
    SMTP_PORT = 587
    SMTP_USERNAME = ""
    SMTP_PASSWORD = ""
    SMTP_USE_TLS = False
    SMTP_FROM_ADDRESS = "test@localhost"
    SLACK_WEBHOOK_URL = ""


def _create_test_app(config_class=TestConfig) -> Flask:
    """Build a lightweight Flask app with all blueprints but no listeners."""
    application = Flask(__name__)
    application.config.from_object(config_class)

    db.init_app(application)
    CORS(application)
    SocketIO().init_app(application, async_mode="threading")

    # Register blueprints
    from api.events import events_bp
    from api.sessions import sessions_bp
    from api.honeypots import honeypots_bp
    from api.alerts import alerts_bp
    from api.network_scans import network_scans_bp
    from api.dashboard import dashboard_bp
    from api.config import config_bp
    from api.attackers import attackers_bp
    from api.credentials import credentials_bp
    from api.auth import auth_bp
    from api.throttle import throttle_bp
    from api.perimeter import perimeter_bp

    for bp in (
        events_bp, sessions_bp, honeypots_bp, alerts_bp,
        network_scans_bp, dashboard_bp, config_bp, attackers_bp,
        credentials_bp, auth_bp, throttle_bp, perimeter_bp,
    ):
        application.register_blueprint(bp)

    # Health endpoint
    from flask import jsonify

    @application.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "honeyos-backend"})

    return application


@pytest.fixture(scope="session")
def app():
    """Session-scoped Flask application for tests."""
    application = _create_test_app()
    with application.app_context():
        db.create_all()
    yield application


@pytest.fixture(autouse=True)
def db_session(app):
    """Per-test database isolation: create tables, yield, then drop."""
    with app.app_context():
        db.create_all()
        yield db.session
        db.session.remove()
        db.drop_all()
        db.create_all()


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()
