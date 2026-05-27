"""
HoneyOS configuration module.

Loads settings from environment variables with sensible defaults
for running on Docker or Raspberry Pi.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration loaded from environment variables."""

    # --- Core ---
    SECRET_KEY = os.getenv("SECRET_KEY", "honeyos-default-secret-change-me")
    DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    READ_ONLY = os.getenv("READ_ONLY", "false").lower() in ("true", "1", "yes")

    # --- Database ---
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///honeyos.db")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # SQLite connections are cheap file handles — use NullPool to avoid the
    # QueuePool size limit that causes timeouts under heavy bot traffic.
    if DATABASE_URL.startswith("sqlite"):
        from sqlalchemy.pool import NullPool
        SQLALCHEMY_ENGINE_OPTIONS: dict = {
            "poolclass": NullPool,
            "connect_args": {"timeout": 10},
        }
    else:
        SQLALCHEMY_ENGINE_OPTIONS: dict = {}

    # --- Network ---
    NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
    PORT_RANGE_START = int(os.getenv("PORT_RANGE_START", "1"))
    PORT_RANGE_END = int(os.getenv("PORT_RANGE_END", "1024"))
    BIND_HOST = os.getenv("BIND_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "7778"))

    # --- SMTP / Email Alerts ---
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")
    SMTP_FROM_ADDRESS = os.getenv("SMTP_FROM_ADDRESS", "honeyos@localhost")

    # --- Slack ---
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

    # --- Logging ---
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

    # --- Data Retention ---
    RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))

    # --- Rate Limiting ---
    ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "300"))

    # --- Honeypot Defaults ---
    SSH_HONEYPOT_PORT = int(os.getenv("SSH_HONEYPOT_PORT", "2222"))
    HTTP_HONEYPOT_PORT = int(os.getenv("HTTP_HONEYPOT_PORT", "8080"))
    HTTPS_HONEYPOT_PORT = int(os.getenv("HTTPS_HONEYPOT_PORT", "8443"))
    TELNET_HONEYPOT_PORT = int(os.getenv("TELNET_HONEYPOT_PORT", "2323"))
    FTP_HONEYPOT_PORT = int(os.getenv("FTP_HONEYPOT_PORT", "2121"))
    MYSQL_HONEYPOT_PORT = int(os.getenv("MYSQL_HONEYPOT_PORT", "3307"))
    POSTGRESQL_HONEYPOT_PORT = int(os.getenv("POSTGRESQL_HONEYPOT_PORT", "5433"))
    DNS_HONEYPOT_PORT = int(os.getenv("DNS_HONEYPOT_PORT", "5353"))
    SMB_HONEYPOT_PORT = int(os.getenv("SMB_HONEYPOT_PORT", "4450"))

    # --- Honeypot Enable/Disable ---
    SSH_HONEYPOT_ENABLED = os.getenv("SSH_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    HTTP_HONEYPOT_ENABLED = os.getenv("HTTP_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    HTTPS_HONEYPOT_ENABLED = os.getenv("HTTPS_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    TELNET_HONEYPOT_ENABLED = os.getenv("TELNET_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    FTP_HONEYPOT_ENABLED = os.getenv("FTP_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    MYSQL_HONEYPOT_ENABLED = os.getenv("MYSQL_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    POSTGRESQL_HONEYPOT_ENABLED = os.getenv("POSTGRESQL_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    DNS_HONEYPOT_ENABLED = os.getenv("DNS_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")
    SMB_HONEYPOT_ENABLED = os.getenv("SMB_HONEYPOT_ENABLED", "true").lower() in ("true", "1", "yes")

    HONEYPOT_ENABLED: dict[str, bool] = {
        "ssh": SSH_HONEYPOT_ENABLED,
        "http": HTTP_HONEYPOT_ENABLED,
        "https": HTTPS_HONEYPOT_ENABLED,
        "telnet": TELNET_HONEYPOT_ENABLED,
        "ftp": FTP_HONEYPOT_ENABLED,
        "mysql": MYSQL_HONEYPOT_ENABLED,
        "postgresql": POSTGRESQL_HONEYPOT_ENABLED,
        "dns": DNS_HONEYPOT_ENABLED,
        "smb": SMB_HONEYPOT_ENABLED,
    }

    # --- Authentication ---
    SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "168"))

    # --- Geolocation ---
    GEOIP_ENABLED = os.getenv("GEOIP_ENABLED", "true").lower() in ("true", "1", "yes")

    # --- Threat Intelligence ---
    ABUSECH_API_KEY = os.getenv("ABUSECH_API_KEY", "")
