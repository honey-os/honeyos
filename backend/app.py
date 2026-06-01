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

    perimeter_service = PerimeterService(app=application)
    application.perimeter_service = perimeter_service

    with application.app_context():
        # Clean up leaked sessions from previous runs / crashes
        session_recorder.reap_stale_sessions(max_age_seconds=300)
        perimeter_service.sync_honeypot_ports()
        manager.start_all_enabled()

    # --- Periodic maintenance ------------------------------------------------
    import threading
    from config import Config as _config

    def _aggregate_day(target_date):
        """Finalize daily stats for a given date.

        Counters (total_events, connection_events, etc.) are maintained in
        real-time by EventProcessor._increment_daily_stat().  This function
        only fills in the fields that require a full-day GROUP BY scan:
        unique_source_ips, top_source_ips, top_usernames, top_passwords.
        """
        import json as _json
        from models import DailyStat, Event

        day_start = datetime(target_date.year, target_date.month, target_date.day, tzinfo=timezone.utc)
        day_end = day_start + timedelta(days=1)

        # Get all stat rows for this date (created in real-time)
        existing_rows = DailyStat.query.filter_by(date=target_date).all()
        existing_map = {row.protocol: row for row in existing_rows}

        # Also discover protocols from events (in case real-time missed any)
        protocols = [
            row[0] for row in
            db.session.query(db.distinct(Event.protocol))
            .filter(Event.timestamp >= day_start, Event.timestamp < day_end)
            .all()
            if row[0]
        ]

        for protocol in protocols:
            stat = existing_map.get(protocol)

            # If no real-time row exists (e.g. old data from before this feature),
            # create one with counts computed from events.
            if not stat:
                base = Event.query.filter(
                    Event.timestamp >= day_start,
                    Event.timestamp < day_end,
                    Event.protocol == protocol,
                )
                total = base.count()
                if total == 0:
                    continue
                stat = DailyStat(
                    id=generate_id(),
                    date=target_date,
                    protocol=protocol,
                    total_events=total,
                    connection_events=base.filter(Event.event_type == "connection").count(),
                    auth_events=base.filter(Event.event_type == "authentication").count(),
                    high_severity_events=base.filter(Event.severity.in_(["high", "critical"])).count(),
                    blocked_events=0,
                )
                db.session.add(stat)

            # Skip if top-N data already computed (idempotent)
            if stat.top_source_ips is not None:
                continue

            # Compute unique IPs
            unique_ips = db.session.query(
                db.func.count(db.distinct(Event.source_ip))
            ).filter(
                Event.timestamp >= day_start, Event.timestamp < day_end,
                Event.protocol == protocol,
            ).scalar() or 0
            stat.unique_source_ips = unique_ips

            # Top 10 source IPs
            top_ips = (
                db.session.query(Event.source_ip, db.func.count().label("cnt"))
                .filter(Event.timestamp >= day_start, Event.timestamp < day_end, Event.protocol == protocol)
                .group_by(Event.source_ip)
                .order_by(db.text("cnt DESC"))
                .limit(10)
                .all()
            )
            stat.top_source_ips = _json.dumps([{"ip": ip, "count": c} for ip, c in top_ips])

            # Top 10 usernames (auth events only)
            username_expr = db.func.json_extract(Event.details, "$.username")
            top_users = (
                db.session.query(username_expr.label("u"), db.func.count().label("cnt"))
                .filter(
                    Event.timestamp >= day_start, Event.timestamp < day_end,
                    Event.protocol == protocol, Event.event_type == "authentication",
                    username_expr.isnot(None), username_expr != "",
                )
                .group_by(username_expr)
                .order_by(db.text("cnt DESC"))
                .limit(10)
                .all()
            )
            stat.top_usernames = _json.dumps([{"username": u, "count": c} for u, c in top_users])

            # Top 10 passwords
            password_expr = db.func.json_extract(Event.details, "$.password")
            top_passwords = (
                db.session.query(password_expr.label("p"), db.func.count().label("cnt"))
                .filter(
                    Event.timestamp >= day_start, Event.timestamp < day_end,
                    Event.protocol == protocol, Event.event_type == "authentication",
                    password_expr.isnot(None), password_expr != "",
                )
                .group_by(password_expr)
                .order_by(db.text("cnt DESC"))
                .limit(10)
                .all()
            )
            stat.top_passwords = _json.dumps([{"password": p, "count": c} for p, c in top_passwords])

        db.session.commit()

    def _enforce_retention():
        """Aggregate then delete events and sessions older than RETENTION_DAYS."""
        from models import Event, Session as SessionModel

        cutoff = datetime.now(timezone.utc) - timedelta(days=_config.RETENTION_DAYS)

        # Aggregate each day that's about to be purged (that hasn't been yet)
        oldest_event = db.session.query(db.func.min(Event.timestamp)).scalar()
        if oldest_event:
            if oldest_event.tzinfo is None:
                oldest_event = oldest_event.replace(tzinfo=timezone.utc)
            day = oldest_event.date()
            cutoff_date = cutoff.date()
            while day < cutoff_date:
                try:
                    _aggregate_day(day)
                except Exception:
                    logger.debug("Failed to aggregate day %s", day, exc_info=True)
                day += timedelta(days=1)

        deleted_events = Event.query.filter(Event.timestamp < cutoff).delete()
        deleted_sessions = SessionModel.query.filter(
            SessionModel.status != "active",
            SessionModel.start_time < cutoff,
        ).delete()
        db.session.commit()

        if deleted_events or deleted_sessions:
            logger.info(
                "Retention: pruned %d events and %d sessions older than %d days",
                deleted_events, deleted_sessions, _config.RETENTION_DAYS,
            )

    def _maintenance_loop():
        """Background maintenance: session reaper (5 min) + retention (1 hour)."""
        cycle = 0
        while True:
            threading.Event().wait(300)  # 5 minutes
            cycle += 1
            try:
                with application.app_context():
                    session_recorder.reap_stale_sessions(max_age_seconds=300)
                    # Run retention every 12 cycles (1 hour)
                    if cycle % 12 == 0:
                        _enforce_retention()
            except Exception:
                logger.debug("Maintenance cycle failed", exc_info=True)

    # Run retention once on startup
    with application.app_context():
        _enforce_retention()

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
