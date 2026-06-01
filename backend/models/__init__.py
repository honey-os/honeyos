"""
HoneyOS SQLAlchemy models.

All tables are defined here and exported alongside the shared `db` instance.
"""

import json
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime | None) -> str | None:
    """Serialise a datetime as an ISO-8601 string with a Z suffix."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _json_col_to_python(value):
    """Deserialise a JSON text column into a Python object."""
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Text, primary_key=True)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    protocol = db.Column(db.String(32), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=_utcnow, index=True)
    severity = db.Column(db.String(16), default="medium", index=True)
    details = db.Column(db.Text)  # stored as JSON text
    session_id = db.Column(db.Text, db.ForeignKey("sessions.id"), nullable=True)
    user_agent = db.Column(db.Text)
    raw_payload = db.Column(db.Text)
    geolocation = db.Column(db.Text)  # stored as JSON text
    throttled = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=_utcnow)
    updated_at = db.Column(db.DateTime, default=_utcnow, onupdate=_utcnow)

    session = db.relationship("Session", backref=db.backref("events", lazy="dynamic"))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "timestamp": _iso_utc(self.timestamp),
            "severity": self.severity,
            "details": _json_col_to_python(self.details),
            "session_id": self.session_id,
            "user_agent": self.user_agent,
            "raw_payload": self.raw_payload,
            "geolocation": _json_col_to_python(self.geolocation),
            "created_at": _iso_utc(self.created_at),
            "updated_at": _iso_utc(self.updated_at),
        }


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session(db.Model):
    __tablename__ = "sessions"

    id = db.Column(db.Text, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    protocol = db.Column(db.String(32), nullable=False)
    start_time = db.Column(db.DateTime, default=_utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    duration_seconds = db.Column(db.Float, nullable=True)
    commands_count = db.Column(db.Integer, default=0)
    keystrokes = db.Column(db.Text)  # JSON
    commands = db.Column(db.Text)  # JSON
    file_transfers = db.Column(db.Text)  # JSON
    status = db.Column(db.String(16), default="active", index=True)
    threat_intel = db.Column(db.Text)  # JSON

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_ip": self.source_ip,
            "protocol": self.protocol,
            "start_time": _iso_utc(self.start_time),
            "end_time": _iso_utc(self.end_time),
            "duration_seconds": self.duration_seconds,
            "commands_count": self.commands_count,
            "keystrokes": _json_col_to_python(self.keystrokes),
            "commands": _json_col_to_python(self.commands),
            "file_transfers": _json_col_to_python(self.file_transfers),
            "status": self.status,
            "threat_intel": _json_col_to_python(self.threat_intel),
        }


# ---------------------------------------------------------------------------
# Honeypot
# ---------------------------------------------------------------------------

class Honeypot(db.Model):
    __tablename__ = "honeypots"

    id = db.Column(db.Text, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    protocol = db.Column(db.String(32), nullable=False)
    port = db.Column(db.Integer, unique=True, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    description = db.Column(db.Text)
    config = db.Column(db.Text)  # JSON
    last_activity = db.Column(db.DateTime, nullable=True)
    total_interactions = db.Column(db.Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol,
            "port": self.port,
            "enabled": self.enabled,
            "description": self.description,
            "config": _json_col_to_python(self.config),
            "last_activity": _iso_utc(self.last_activity),
            "total_interactions": self.total_interactions,
        }


# ---------------------------------------------------------------------------
# Alert
# ---------------------------------------------------------------------------

class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Text, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    alert_type = db.Column(db.String(32), nullable=False)  # email, webhook, slack
    config = db.Column(db.Text)  # JSON
    conditions = db.Column(db.Text)  # JSON
    last_sent = db.Column(db.DateTime, nullable=True)
    send_count = db.Column(db.Integer, default=0)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "alert_type": self.alert_type,
            "config": _json_col_to_python(self.config),
            "conditions": _json_col_to_python(self.conditions),
            "last_sent": _iso_utc(self.last_sent),
            "send_count": self.send_count,
        }


# ---------------------------------------------------------------------------
# NetworkScan
# ---------------------------------------------------------------------------

class NetworkScan(db.Model):
    __tablename__ = "network_scans"

    id = db.Column(db.Text, primary_key=True)
    target_host = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(32), nullable=False, default="tcp")
    discovered_ports = db.Column(db.Text)  # JSON
    scan_duration_ms = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=_utcnow)
    changes_detected = db.Column(db.Boolean, default=False)
    previous_scan_id = db.Column(db.Text, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "target_host": self.target_host,
            "scan_type": self.scan_type,
            "discovered_ports": _json_col_to_python(self.discovered_ports),
            "scan_duration_ms": self.scan_duration_ms,
            "timestamp": _iso_utc(self.timestamp),
            "changes_detected": self.changes_detected,
            "previous_scan_id": self.previous_scan_id,
        }


# ---------------------------------------------------------------------------
# SystemConfig
# ---------------------------------------------------------------------------

class SystemConfig(db.Model):
    __tablename__ = "system_config"

    key = db.Column(db.String(128), primary_key=True)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    config_type = db.Column(db.String(32), default="string")  # string, int, bool, json

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "value": self.value,
            "description": self.description,
            "config_type": self.config_type,
        }


# ---------------------------------------------------------------------------
# AuthSession
# ---------------------------------------------------------------------------

class AuthSession(db.Model):
    __tablename__ = "auth_sessions"
    token = db.Column(db.String(64), primary_key=True)
    created_at = db.Column(db.DateTime, default=_utcnow)


# ---------------------------------------------------------------------------
# IPGeoCache
# ---------------------------------------------------------------------------

class ThrottleBlock(db.Model):
    __tablename__ = "throttle_blocks"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    protocol = db.Column(db.String(32), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)
    reason = db.Column(db.String(32), default="event_threshold")

    __table_args__ = (
        db.UniqueConstraint("ip", "protocol", name="uq_throttle_ip_protocol"),
    )


# ---------------------------------------------------------------------------
# IPGeoCache
# ---------------------------------------------------------------------------

class IPGeoCache(db.Model):
    __tablename__ = "ip_geo_cache"

    ip = db.Column(db.String(45), primary_key=True)
    country = db.Column(db.String(128))
    country_code = db.Column(db.String(8))
    region = db.Column(db.String(128))
    city = db.Column(db.String(128))
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    isp = db.Column(db.String(256))
    org = db.Column(db.String(256))
    asn = db.Column(db.String(64))
    looked_up_at = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
        }


# ---------------------------------------------------------------------------
# DeclaredPort
# ---------------------------------------------------------------------------

class DeclaredPort(db.Model):
    __tablename__ = "declared_ports"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    port = db.Column(db.Integer, nullable=False)
    transport = db.Column(db.String(8), default="tcp")
    label = db.Column(db.String(128), nullable=False)
    source = db.Column(db.String(16), default="user")
    created_at = db.Column(db.DateTime, default=_utcnow)

    __table_args__ = (
        db.UniqueConstraint("port", "transport", name="uq_declared_port_transport"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "port": self.port,
            "transport": self.transport,
            "label": self.label,
            "source": self.source,
            "created_at": _iso_utc(self.created_at),
        }


# ---------------------------------------------------------------------------
# PerimeterScan
# ---------------------------------------------------------------------------

class PerimeterScan(db.Model):
    __tablename__ = "perimeter_scans"

    id = db.Column(db.Text, primary_key=True)
    public_ip = db.Column(db.String(45))
    scan_source = db.Column(db.String(16))
    declared_snapshot = db.Column(db.Text)  # JSON
    actual_ports = db.Column(db.Text)       # JSON
    unexpected_ports = db.Column(db.Text)   # JSON
    missing_ports = db.Column(db.Text)      # JSON
    drift_detected = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "public_ip": self.public_ip,
            "scan_source": self.scan_source,
            "declared_snapshot": _json_col_to_python(self.declared_snapshot),
            "actual_ports": _json_col_to_python(self.actual_ports),
            "unexpected_ports": _json_col_to_python(self.unexpected_ports),
            "missing_ports": _json_col_to_python(self.missing_ports),
            "drift_detected": self.drift_detected,
            "timestamp": _iso_utc(self.timestamp),
        }


# ---------------------------------------------------------------------------
# CensysSnapshot
# ---------------------------------------------------------------------------

class CensysSnapshot(db.Model):
    __tablename__ = "censys_snapshots"

    id = db.Column(db.Text, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    ports_data = db.Column(db.Text)      # JSON
    tags = db.Column(db.Text)            # JSON
    honeypot_flagged = db.Column(db.Boolean, default=False)
    vulns = db.Column(db.Text)           # JSON
    hostnames = db.Column(db.Text)       # JSON
    org = db.Column(db.String(256))
    isp = db.Column(db.String(256))
    os_name = db.Column(db.String(128))
    censys_updated = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ip": self.ip,
            "ports_data": _json_col_to_python(self.ports_data),
            "tags": _json_col_to_python(self.tags),
            "honeypot_flagged": self.honeypot_flagged,
            "vulns": _json_col_to_python(self.vulns),
            "hostnames": _json_col_to_python(self.hostnames),
            "org": self.org,
            "isp": self.isp,
            "os_name": self.os_name,
            "censys_updated": self.censys_updated,
            "timestamp": _iso_utc(self.timestamp),
        }


# ---------------------------------------------------------------------------
# DailyStat -- aggregated daily summary preserved beyond raw event retention
# ---------------------------------------------------------------------------

class DailyStat(db.Model):
    __tablename__ = "daily_stats"

    id = db.Column(db.Text, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    protocol = db.Column(db.String(32), nullable=False)
    total_events = db.Column(db.Integer, default=0)
    connection_events = db.Column(db.Integer, default=0)
    auth_events = db.Column(db.Integer, default=0)
    unique_source_ips = db.Column(db.Integer, default=0)
    high_severity_events = db.Column(db.Integer, default=0)
    blocked_events = db.Column(db.Integer, default=0)
    top_source_ips = db.Column(db.Text)     # JSON: [{ip, count}, ...]
    top_usernames = db.Column(db.Text)      # JSON: [{username, count}, ...]
    top_passwords = db.Column(db.Text)      # JSON: [{password, count}, ...]

    __table_args__ = (
        db.UniqueConstraint("date", "protocol", name="uq_daily_stats_date_protocol"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "date": self.date.isoformat() if self.date else None,
            "protocol": self.protocol,
            "total_events": self.total_events,
            "connection_events": self.connection_events,
            "auth_events": self.auth_events,
            "unique_source_ips": self.unique_source_ips,
            "high_severity_events": self.high_severity_events,
            "blocked_events": self.blocked_events,
            "top_source_ips": _json_col_to_python(self.top_source_ips),
            "top_usernames": _json_col_to_python(self.top_usernames),
            "top_passwords": _json_col_to_python(self.top_passwords),
        }
