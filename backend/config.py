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

    # --- Database ---
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///honeyos.db")
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

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

    # --- Authentication ---
    SESSION_TIMEOUT_HOURS = int(os.getenv("SESSION_TIMEOUT_HOURS", "168"))

    # --- Geolocation ---
    GEOIP_ENABLED = os.getenv("GEOIP_ENABLED", "true").lower() in ("true", "1", "yes")
