"""
AlertService -- evaluates alert conditions, dispatches notifications.
"""

import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText

import requests

from models import Alert, db
from utils.helpers import parse_json_field

logger = logging.getLogger(__name__)


class AlertService:
    """Evaluate alert rules and dispatch notifications."""

    def __init__(self, config=None):
        self.config = config or {}
        self.cooldown_seconds = int(
            getattr(config, "ALERT_COOLDOWN_SECONDS", 300)
            if config
            else 300
        )

    # ------------------------------------------------------------------
    # Condition evaluation
    # ------------------------------------------------------------------

    def check_conditions(self, event) -> None:
        """
        Iterate over all enabled alerts and evaluate their conditions
        against *event*.  If matched, dispatch the alert (respecting
        cooldown).
        """
        alerts = Alert.query.filter_by(enabled=True).all()

        for alert in alerts:
            conditions = parse_json_field(alert.conditions) or {}
            if self._matches(conditions, event):
                if self._cooldown_ok(alert):
                    self.send_alert(alert, event)

    def _matches(self, conditions: dict, event) -> bool:
        """
        Return True if the event satisfies every condition key.

        Supported condition keys:
        - event_type : exact match
        - protocol   : exact match (case-insensitive)
        - severity   : list of acceptable severities
        - source_ip  : exact match or CIDR (simplified to prefix)
        """
        if not conditions:
            return True  # no conditions = always fire

        if "event_type" in conditions:
            if event.event_type != conditions["event_type"]:
                return False

        if "protocol" in conditions:
            if event.protocol.lower() != conditions["protocol"].lower():
                return False

        if "severity" in conditions:
            allowed = conditions["severity"]
            if isinstance(allowed, str):
                allowed = [allowed]
            if event.severity not in allowed:
                return False

        if "source_ip" in conditions:
            if event.source_ip != conditions["source_ip"]:
                return False

        return True

    def _cooldown_ok(self, alert: Alert) -> bool:
        """Return True if enough time has elapsed since the last send."""
        if alert.last_sent is None:
            return True
        now = datetime.now(timezone.utc)
        last = alert.last_sent
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        elapsed = (now - last).total_seconds()
        return elapsed >= self.cooldown_seconds

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def send_alert(self, alert: Alert, event) -> bool:
        """Route the alert to the correct channel and update bookkeeping."""
        alert_config = parse_json_field(alert.config) or {}
        payload = self._build_payload(alert, event)
        success = False

        try:
            if alert.alert_type == "email":
                success = self.send_email(alert_config, payload["subject"], payload["body"])
            elif alert.alert_type == "webhook":
                success = self.send_webhook(alert_config, payload)
            elif alert.alert_type == "slack":
                success = self.send_slack(alert_config, payload)
            else:
                logger.warning("Unknown alert type: %s", alert.alert_type)
        except Exception:
            logger.exception("Failed to send alert %s", alert.id)

        if success:
            alert.last_sent = datetime.now(timezone.utc)
            alert.send_count = (alert.send_count or 0) + 1
            db.session.commit()
            logger.info("Alert %s (%s) sent successfully", alert.name, alert.alert_type)

        return success

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------

    def send_email(self, config: dict, subject: str, body: str) -> bool:
        """Send an alert email via SMTP."""
        smtp_host = config.get("smtp_host") or getattr(self.config, "SMTP_HOST", "")
        smtp_port = int(config.get("smtp_port") or getattr(self.config, "SMTP_PORT", 587))
        smtp_user = config.get("smtp_username") or getattr(self.config, "SMTP_USERNAME", "")
        smtp_pass = config.get("smtp_password") or getattr(self.config, "SMTP_PASSWORD", "")
        use_tls = config.get("smtp_use_tls", getattr(self.config, "SMTP_USE_TLS", True))
        from_addr = config.get("from_address") or getattr(self.config, "SMTP_FROM_ADDRESS", "honeyos@localhost")
        to_addrs = config.get("to_addresses", [])

        if not smtp_host or not to_addrs:
            logger.warning("Email alert skipped -- SMTP not configured")
            return False

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs

        try:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
            if use_tls:
                server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            return True
        except Exception:
            logger.exception("SMTP send failed")
            return False

    def send_webhook(self, config: dict, payload: dict) -> bool:
        """POST a JSON payload to the configured webhook URL."""
        url = config.get("url", "")
        if not url:
            logger.warning("Webhook alert skipped -- no URL configured")
            return False

        headers = config.get("headers", {"Content-Type": "application/json"})
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=10)
            resp.raise_for_status()
            return True
        except Exception:
            logger.exception("Webhook send failed")
            return False

    def send_slack(self, config: dict, payload: dict) -> bool:
        """Send a message to Slack via incoming webhook."""
        url = config.get("webhook_url") or getattr(self.config, "SLACK_WEBHOOK_URL", "")
        if not url:
            logger.warning("Slack alert skipped -- no webhook URL configured")
            return False

        slack_payload = {
            "text": payload.get("subject", "HoneyOS Alert"),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{payload.get('subject', 'Alert')}*\n"
                            f"{payload.get('body', '')}"
                        ),
                    },
                }
            ],
        }

        try:
            resp = requests.post(url, json=slack_payload, timeout=10)
            resp.raise_for_status()
            return True
        except Exception:
            logger.exception("Slack send failed")
            return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_payload(alert: Alert, event) -> dict:
        """Create a unified alert payload dict."""
        return {
            "subject": f"[HoneyOS] {alert.name} - {event.event_type} from {event.source_ip}",
            "body": (
                f"Alert: {alert.name}\n"
                f"Event Type: {event.event_type}\n"
                f"Protocol: {event.protocol}\n"
                f"Source IP: {event.source_ip}\n"
                f"Destination Port: {event.destination_port}\n"
                f"Severity: {event.severity}\n"
                f"Timestamp: {event.timestamp}\n"
            ),
            "alert_id": alert.id,
            "alert_name": alert.name,
            "event_id": event.id,
            "event_type": event.event_type,
            "source_ip": event.source_ip,
            "protocol": event.protocol,
            "severity": event.severity,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        }
