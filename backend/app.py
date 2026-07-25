"""
HoneyOS -- Main Flask application entry point.

Run directly:   python app.py
Via gunicorn:    gunicorn -k eventlet -w 1 app:app
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request
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
from models import Honeypot, db
from utils.helpers import generate_id

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
_log_level = getattr(logging, Config.LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
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

    # Trust X-Forwarded-* headers from Caddy (TLS termination proxy)
    from werkzeug.middleware.proxy_fix import ProxyFix
    application.wsgi_app = ProxyFix(application.wsgi_app, x_proto=1)

    # --- Extensions -------------------------------------------------------
    db.init_app(application)
    CORS(application, resources={r"/api/*": {"origins": r".*"}}, supports_credentials=True)
    socketio.init_app(application, cors_allowed_origins=r".*", async_mode="threading")

    # --- Blueprints -------------------------------------------------------
    from api.events import events_bp
    from api.sessions import sessions_bp
    from api.honeypots import honeypots_bp
    from api.alerts import alerts_bp
    from api.network_scans import network_scans_bp
    from api.dashboard import dashboard_bp
    from api.config import config_bp
    from api.attackers import attackers_bp
    from api.credentials import credentials_bp
    from api.auth import auth_bp, has_admin, is_authenticated, SESSION_COOKIE_NAME
    from api.throttle import throttle_bp
    from api.perimeter import perimeter_bp
    from api.webhooks import webhooks_bp

    application.register_blueprint(events_bp)
    application.register_blueprint(sessions_bp)
    application.register_blueprint(honeypots_bp)
    application.register_blueprint(alerts_bp)
    application.register_blueprint(network_scans_bp)
    application.register_blueprint(dashboard_bp)
    application.register_blueprint(config_bp)
    application.register_blueprint(attackers_bp)
    application.register_blueprint(credentials_bp)
    application.register_blueprint(auth_bp)
    application.register_blueprint(throttle_bp)
    application.register_blueprint(perimeter_bp)
    application.register_blueprint(webhooks_bp)

    # --- Auth middleware --------------------------------------------------
    AUTH_ALLOWLIST = {"/health", "/api/auth/status", "/api/auth/setup",
                     "/api/auth/login", "/api/auth/logout"}

    @application.before_request
    def check_auth():
        if request.method == "OPTIONS":
            return None
        if request.path in AUTH_ALLOWLIST:
            return None
        if not has_admin():
            return None
        cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
        if not is_authenticated(cookie_token):
            return jsonify({
                "error": "unauthorized",
                "message": "Authentication required",
            }), 401

    # --- Read-only guard --------------------------------------------------
    READ_ONLY_ALLOWLIST = {"/api/auth/setup", "/api/auth/login", "/api/auth/logout"}

    @application.before_request
    def check_read_only():
        if not Config.READ_ONLY:
            return None
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        if request.path in READ_ONLY_ALLOWLIST:
            return None
        if request.path.endswith("/identify-malware"):
            return None
        return jsonify({
            "error": "read_only",
            "message": "This instance is in read-only mode",
        }), 403

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
        # Enable WAL mode for SQLite — allows concurrent reads during writes
        # and dramatically reduces "database is locked" under heavy bot traffic.
        if config_class.DATABASE_URL.startswith("sqlite"):
            from sqlalchemy import event as sa_event

            @sa_event.listens_for(db.engine, "connect")
            def _set_sqlite_pragma(dbapi_connection, connection_record):
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

        db.create_all()
        _run_migrations()
        _seed_defaults()

    # --- Start honeypot listeners -----------------------------------------
    from services.event_processor import EventProcessor
    from services.session_recorder import SessionRecorder
    from services.honeypot_manager import HoneypotManager
    from services.alert_service import AlertService
    from services.connection_throttle import ConnectionThrottler
    from services.perimeter import PerimeterService

    alert_service = AlertService(config=config_class)
    connection_throttler = ConnectionThrottler(app=application)
    event_processor = EventProcessor(
        alert_service=alert_service,
        connection_throttler=connection_throttler,
    )
    session_recorder = SessionRecorder()
    manager = HoneypotManager(
        app=application,
        event_processor=event_processor,
        session_recorder=session_recorder,
        connection_throttler=connection_throttler,
    )
    application.honeypot_manager = manager
    application.connection_throttler = connection_throttler
    application.event_processor = event_processor

    perimeter_service = PerimeterService(app=application)
    application.perimeter_service = perimeter_service

    # Standalone canarytokens.org webhook listener (own port, no admin auth)
    if Config.WEBHOOK_ENABLED:
        from services.webhook_server import CanaryWebhookServer
        webhook_server = CanaryWebhookServer(
            port=Config.WEBHOOK_PORT,
            app=application,
            event_processor=event_processor,
        )
        webhook_server.start()
        application.webhook_server = webhook_server
        logger.info("Canary webhook enabled on port %d", Config.WEBHOOK_PORT)

    with application.app_context():
        # Clean up leaked sessions from previous runs / crashes
        session_recorder.reap_stale_sessions(max_age_seconds=300)
        perimeter_service.sync_honeypot_ports()
        manager.start_all_enabled()

    # --- Periodic maintenance ------------------------------------------------
    import threading
    from config import Config as _config
    from services.retention import enforce_retention

    def _maintenance_loop():
        """Background maintenance: session reaper (5 min) + retention (hourly).

        Retention also runs once when the thread starts.  It runs here in the
        daemon thread rather than synchronously during create_app so a large
        purge backlog cannot stall boot past gunicorn's worker timeout.
        """
        try:
            with application.app_context():
                enforce_retention(_config.RETENTION_DAYS)
        except Exception:
            logger.warning("Startup retention run failed", exc_info=True)

        cycle = 0
        while True:
            threading.Event().wait(300)  # 5 minutes
            cycle += 1
            try:
                with application.app_context():
                    session_recorder.reap_stale_sessions(max_age_seconds=300)
                    # Run retention every 12 cycles (1 hour)
                    if cycle % 12 == 0:
                        enforce_retention(_config.RETENTION_DAYS)
            except Exception:
                logger.warning("Maintenance cycle failed", exc_info=True)

    threading.Thread(target=_maintenance_loop, daemon=True, name="maintenance").start()

    return application


# ---------------------------------------------------------------------------
# Seed defaults
# ---------------------------------------------------------------------------

def _run_migrations() -> None:
    """Apply schema migrations that db.create_all() cannot handle
    (e.g. adding columns to existing tables)."""
    import sqlalchemy

    with db.engine.connect() as conn:
        # Check if sessions.threat_intel column exists
        result = conn.execute(sqlalchemy.text("PRAGMA table_info(sessions)"))
        columns = {row[1] for row in result}
        if "threat_intel" not in columns:
            conn.execute(sqlalchemy.text("ALTER TABLE sessions ADD COLUMN threat_intel TEXT"))
            conn.commit()
            logger.info("Migration: added threat_intel column to sessions table")

        # Add blocked_events column to daily_stats (if table exists already)
        result = conn.execute(sqlalchemy.text("PRAGMA table_info(daily_stats)"))
        columns = {row[1] for row in result}
        if columns and "blocked_events" not in columns:
            conn.execute(sqlalchemy.text(
                "ALTER TABLE daily_stats ADD COLUMN blocked_events INTEGER DEFAULT 0"
            ))
            conn.commit()
            logger.info("Migration: added blocked_events column to daily_stats table")

        # Add throttled column to events
        result = conn.execute(sqlalchemy.text("PRAGMA table_info(events)"))
        columns = {row[1] for row in result}
        if "throttled" not in columns:
            conn.execute(sqlalchemy.text(
                "ALTER TABLE events ADD COLUMN throttled BOOLEAN DEFAULT 0"
            ))
            conn.execute(sqlalchemy.text(
                "CREATE INDEX IF NOT EXISTS ix_events_throttled ON events (throttled)"
            ))
            conn.commit()
            logger.info("Migration: added throttled column to events table")


def _seed_defaults() -> None:
    """Populate default honeypot configs and system settings if the tables
    are empty (first run)."""

    # Default honeypots -- seed missing protocols into existing installs
    existing_protocols = {hp.protocol for hp in Honeypot.query.with_entities(Honeypot.protocol).all()}
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
                "name": "HTTPS Honeypot",
                "protocol": "https",
                "port": Config.HTTPS_HONEYPOT_PORT,
                "description": "Fake HTTPS server with TLS and login pages",
                "config": {"server_header": "Apache/2.4.52 (Ubuntu)"},
            },
            {
                "name": "Telnet Honeypot",
                "protocol": "telnet",
                "port": Config.TELNET_HONEYPOT_PORT,
                "description": "Fake telnet server capturing credentials and commands",
                "config": {"banner": "Welcome to Gateway Management Console"},
            },
            {
                "name": "FTP Honeypot",
                "protocol": "ftp",
                "port": Config.FTP_HONEYPOT_PORT,
                "description": "Fake FTP server logging credentials and file access attempts",
                "config": {"banner": "220 (vsFTPd 3.0.5)"},
            },
            {
                "name": "MySQL Honeypot",
                "protocol": "mysql",
                "port": Config.MYSQL_HONEYPOT_PORT,
                "description": "Fake MySQL server capturing authentication and queries",
                "config": {"version_string": "5.7.38-log"},
            },
            {
                "name": "PostgreSQL Honeypot",
                "protocol": "postgresql",
                "port": Config.POSTGRESQL_HONEYPOT_PORT,
                "description": "Fake PostgreSQL server capturing authentication and queries",
                "config": {"version_string": "14.5"},
            },
            {
                "name": "DNS Honeypot",
                "protocol": "dns",
                "port": Config.DNS_HONEYPOT_PORT,
                "description": "Fake DNS server logging reconnaissance and zone transfer attempts",
                "config": {"domain": "corp.local", "version": "dnsmasq-2.90"},
            },
            {
                "name": "SMB Honeypot",
                "protocol": "smb",
                "port": Config.SMB_HONEYPOT_PORT,
                "description": "Fake SMB/CIFS file server capturing authentication and share access attempts",
                "config": {"server_name": "FILESERVER", "domain": "WORKGROUP"},
            },
            {
                "name": "RDP Honeypot",
                "protocol": "rdp",
                "port": Config.RDP_HONEYPOT_PORT,
                "description": "Fake RDP server capturing connection and authentication attempts",
                "config": {"server_name": "DESKTOP-HOS7890"},
            },
        ]
    new_honeypots = [hp for hp in defaults if hp["protocol"] not in existing_protocols]
    for hp_data in new_honeypots:
        hp = Honeypot(
            id=generate_id(),
            name=hp_data["name"],
            protocol=hp_data["protocol"],
            port=hp_data["port"],
            enabled=Config.HONEYPOT_ENABLED.get(hp_data["protocol"], True),
            description=hp_data["description"],
            config=json.dumps(hp_data["config"]),
            total_interactions=0,
        )
        db.session.add(hp)
    if new_honeypots:
        db.session.commit()
        logger.info("Seeded %d default honeypots", len(new_honeypots))

    # Backfill missing banner keys for protocols that were seeded with empty
    # configs in older versions.
    _banner_backfill: dict[str, dict[str, str]] = {
        "ftp": {"banner": "220 (vsFTPd 3.0.5)"},
        "telnet": {"banner": "Welcome to Gateway Management Console"},
    }
    for proto, patch in _banner_backfill.items():
        hp = Honeypot.query.filter_by(protocol=proto).first()
        if not hp:
            continue
        cfg = json.loads(hp.config) if isinstance(hp.config, str) else (hp.config or {})
        if any(k in cfg for k in ("banner", "server_header", "version_string", "version")):
            continue  # already has a banner key — don't overwrite
        cfg.update(patch)
        hp.config = json.dumps(cfg)
    db.session.commit()


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
        allow_unsafe_werkzeug=True,
    )
