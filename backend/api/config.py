"""
System Configuration API blueprint.

Provides a read-only settings endpoint that returns current Config values
grouped by section. All configuration is managed via .env file.
"""

import time

from flask import Blueprint, jsonify

from config import Config

config_bp = Blueprint("config", __name__)

# App start time for uptime calculation
_start_time = time.time()

# Keys whose values should be masked in the response
_SENSITIVE_KEYS = {"SECRET_KEY", "SMTP_PASSWORD", "SLACK_WEBHOOK_URL"}

_MASK = "\u2022" * 8  # ••••••••

# Sections define how settings are grouped and labeled in the UI
_SECTIONS = [
    {
        "id": "notifications",
        "label": "Notifications",
        "settings": [
            ("SMTP_HOST", "SMTP Server", "string"),
            ("SMTP_PORT", "SMTP Port", "int"),
            ("SMTP_USERNAME", "SMTP Username", "string"),
            ("SMTP_PASSWORD", "SMTP Password", "string"),
            ("SMTP_USE_TLS", "SMTP TLS", "bool"),
            ("SMTP_FROM_ADDRESS", "From Address", "string"),
            ("SLACK_WEBHOOK_URL", "Slack Webhook URL", "string"),
            ("ALERT_COOLDOWN_SECONDS", "Alert Cooldown (seconds)", "int"),
        ],
    },
    {
        "id": "network",
        "label": "Network",
        "settings": [
            ("NETWORK_INTERFACE", "Network Interface", "string"),
            ("BIND_HOST", "Bind Host", "string"),
            ("API_PORT", "API Port", "int"),
            ("GEOIP_ENABLED", "GeoIP Lookups", "bool"),
        ],
    },
    {
        "id": "data",
        "label": "Data",
        "settings": [
            ("RETENTION_DAYS", "Retention (days)", "int"),
            ("LOG_LEVEL", "Log Level", "string"),
        ],
    },
    {
        "id": "honeypot_ports",
        "label": "Honeypot Ports",
        "settings": [
            ("SSH_HONEYPOT_PORT", "SSH", "int"),
            ("HTTP_HONEYPOT_PORT", "HTTP", "int"),
            ("HTTPS_HONEYPOT_PORT", "HTTPS", "int"),
            ("TELNET_HONEYPOT_PORT", "Telnet", "int"),
            ("FTP_HONEYPOT_PORT", "FTP", "int"),
            ("MYSQL_HONEYPOT_PORT", "MySQL", "int"),
            ("POSTGRESQL_HONEYPOT_PORT", "PostgreSQL", "int"),
            ("DNS_HONEYPOT_PORT", "DNS", "int"),
            ("SMB_HONEYPOT_PORT", "SMB", "int"),
        ],
    },
    {
        "id": "security",
        "label": "Security",
        "settings": [
            ("SESSION_TIMEOUT_HOURS", "Session Timeout (hours)", "int"),
        ],
    },
]


def _format_value(key: str, raw_value: object) -> str:
    """Return a display-safe string for a config value."""
    if key in _SENSITIVE_KEYS:
        # Show mask if set, "Not configured" if empty
        if raw_value in (None, ""):
            return "Not configured"
        return _MASK
    if raw_value is None or (isinstance(raw_value, str) and raw_value == ""):
        return "Not configured"
    if isinstance(raw_value, bool):
        return str(raw_value).lower()
    return str(raw_value)


@config_bp.route("/api/settings", methods=["GET"])
def get_settings():
    """Return current configuration grouped by section (read-only)."""
    sections = []
    for section_def in _SECTIONS:
        settings = []
        for key, label, value_type in section_def["settings"]:
            raw = getattr(Config, key, None)
            settings.append({
                "key": key,
                "label": label,
                "value": _format_value(key, raw),
                "type": value_type,
            })
        sections.append({
            "id": section_def["id"],
            "label": section_def["label"],
            "settings": settings,
        })

    uptime = int(time.time() - _start_time)

    return jsonify({
        "sections": sections,
        "system": {
            "version": "0.1.0",
            "database": "SQLite",
            "uptime_seconds": uptime,
        },
    })
