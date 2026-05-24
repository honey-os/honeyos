"""
HoneyOS -- Main Flask application entry point.

Run directly:   python app.py
Via gunicorn:    gunicorn -k eventlet -w 1 app:app
"""

import json
import logging
import os
import sys

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Ensure the backend directory is on sys.path so that ``models``, ``services``
# etc. can be imported without package prefix regardless of working directory.
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from config import Config
from models import Alert, Honeypot, SystemConfig, db
from utils.helpers import generate_id

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("honeyos")

# ---------------------------------------------------------------------------
# App factory-ish (but we also expose a module-level ``app`` for gunicorn)
# ---------------------------------------------------------------------------

socketio = SocketIO()


def create_app(config_class=Config) -> Flask:
    """Create and configure the Flask application."""
    application = Flask(__name__)
    application.config.from_object(config_class)

    # --- Extensions -------------------------------------------------------
    db.init_app(application)
    CORS(application, resources={r"/api/*": {"origins": "*"}})
    socketio.init_app(application, cors_allowed_origins="*", async_mode="threading")

    # --- Blueprints -------------------------------------------------------
    from api.events import events_bp
    from api.sessions import sessions_bp
    from api.honeypots import honeypots_bp
    from api.alerts import alerts_bp
    from api.network_scans import network_scans_bp
    from api.dashboard import dashboard_bp
    from api.config import config_bp

    application.register_blueprint(events_bp)
    application.register_blueprint(sessions_bp)
    application.register_blueprint(honeypots_bp)
    application.register_blueprint(alerts_bp)
    application.register_blueprint(network_scans_bp)
    application.register_blueprint(dashboard_bp)
    application.register_blueprint(config_bp)

    # --- Health check -----------------------------------------------------
    @application.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "healthy", "service": "honeyos-backend"})

    # --- SocketIO events --------------------------------------------------
    @socketio.on("connect")
    def handle_connect():
        logger.debug("SocketIO client connected")

    @socketio.on("disconnect")
    def handle_disconnect():
        logger.debug("SocketIO client disconnected")

    # --- Database initialisation ------------------------------------------
    with application.app_context():
        db.create_all()
        _seed_defaults()

    # --- Start honeypot listeners -----------------------------------------
    from services.event_processor import EventProcessor
    from services.session_recorder import SessionRecorder
    from services.honeypot_manager import HoneypotManager

    event_processor = EventProcessor()
    session_recorder = SessionRecorder()
    manager = HoneypotManager(
        app=application,
        event_processor=event_processor,
        session_recorder=session_recorder,
    )
    application.honeypot_manager = manager

    with application.app_context():
        manager.start_all_enabled()

    return application


# ---------------------------------------------------------------------------
# Seed defaults
# ---------------------------------------------------------------------------

def _seed_defaults() -> None:
    """Populate default honeypot configs and system settings if the tables
    are empty (first run)."""

    # Default honeypots
    if Honeypot.query.count() == 0:
        defaults = [
            {
                "name": "SSH Honeypot",
                "protocol": "ssh",
                "port": Config.SSH_HONEYPOT_PORT,
                "description": "Fake SSH server capturing credentials and commands",
                "config": {"banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"},
            },
            {
                "name": "HTTP Honeypot",
                "protocol": "http",
                "port": Config.HTTP_HONEYPOT_PORT,
                "description": "Fake web server with login pages and directory listings",
                "config": {"server_header": "Apache/2.4.52 (Ubuntu)"},
            },
            {
                "name": "Telnet Honeypot",
                "protocol": "telnet",
                "port": Config.TELNET_HONEYPOT_PORT,
                "description": "Fake telnet server capturing credentials and commands",
                "config": {},
            },
            {
                "name": "FTP Honeypot",
                "protocol": "ftp",
                "port": Config.FTP_HONEYPOT_PORT,
                "description": "Fake FTP server logging credentials and file access attempts",
                "config": {},
            },
            {
                "name": "MySQL Honeypot",
                "protocol": "mysql",
                "port": Config.MYSQL_HONEYPOT_PORT,
                "description": "Fake MySQL server capturing authentication and queries",
                "config": {"version_string": "5.7.38-log"},
            },
        ]
        for hp_data in defaults:
            hp = Honeypot(
                id=generate_id(),
                name=hp_data["name"],
                protocol=hp_data["protocol"],
                port=hp_data["port"],
                enabled=True,
                description=hp_data["description"],
                config=json.dumps(hp_data["config"]),
                total_interactions=0,
            )
            db.session.add(hp)
        db.session.commit()
        logger.info("Seeded %d default honeypots", len(defaults))

    # Default system config entries
    if SystemConfig.query.count() == 0:
        settings = [
            ("retention_days", str(Config.RETENTION_DAYS), "Days to retain events", "int"),
            ("alert_cooldown_seconds", str(Config.ALERT_COOLDOWN_SECONDS),
             "Minimum seconds between repeated alerts", "int"),
            ("log_level", Config.LOG_LEVEL, "Application log level", "string"),
            ("network_interface", Config.NETWORK_INTERFACE,
             "Primary network interface for scanning", "string"),
            ("geoip_enabled", str(Config.GEOIP_ENABLED).lower(),
             "Enable GeoIP lookups for source IPs", "bool"),
        ]
        for key, value, description, config_type in settings:
            sc = SystemConfig(
                key=key,
                value=value,
                description=description,
                config_type=config_type,
            )
            db.session.add(sc)
        db.session.commit()
        logger.info("Seeded %d default config entries", len(settings))


# ---------------------------------------------------------------------------
# Module-level app for ``gunicorn app:app``
# ---------------------------------------------------------------------------

app = create_app()

# ---------------------------------------------------------------------------
# Direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting HoneyOS backend on %s:%d", Config.BIND_HOST, Config.API_PORT)
    socketio.run(
        app,
        host=Config.BIND_HOST,
        port=Config.API_PORT,
        debug=Config.DEBUG,
        use_reloader=False,
    )
