"""
Webhook support for canarytokens.org triggers.

The actual receiver runs as a standalone listener on ``Config.WEBHOOK_PORT``
(see ``services/webhook_server.py``) so it never touches the admin API's auth
middleware and never collides with a honeypot port.  This module holds the
shared pieces: the per-install path secret, the trigger-to-event logic, and
an admin-facing info endpoint that shows the URL to paste into
canarytokens.org.
"""

import logging
import secrets

from flask import Blueprint, jsonify, request

from config import Config
from models import SystemConfig, db

logger = logging.getLogger(__name__)

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/webhooks")

WEBHOOK_SECRET_CONFIG_KEY = "canary_webhook_secret"


def get_webhook_secret() -> str:
    """Return this install's webhook path secret, generating it on first use.
    Requires an app context."""
    row = db.session.get(SystemConfig, WEBHOOK_SECRET_CONFIG_KEY)
    if row is None:
        row = SystemConfig(
            key=WEBHOOK_SECRET_CONFIG_KEY,
            value=secrets.token_urlsafe(24),
            description="Path secret for the canarytokens.org webhook endpoint",
            config_type="string",
        )
        db.session.add(row)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            row = db.session.get(SystemConfig, WEBHOOK_SECRET_CONFIG_KEY)
    return row.value


def record_canary_trigger(payload: dict, event_processor) -> None:
    """Turn a canarytokens.org trigger payload into a critical event.

    Requires an app context.  ``payload`` shape is not contractual, so every
    field is treated as optional.
    """
    additional = payload.get("additional_data") or {}
    src_ip = additional.get("src_ip") or payload.get("src_ip") or "0.0.0.0"

    event_processor.process_event({
        "event_type": "canarytoken_triggered",
        "protocol": "canary",
        "source_ip": src_ip,
        "severity": "critical",
        "user_agent": additional.get("useragent"),
        "details": {
            "memo": payload.get("memo"),
            "channel": payload.get("channel"),
            "token_time": payload.get("time"),
            "manage_url": payload.get("manage_url"),
            "additional_data": additional,
        },
    })
    logger.warning(
        "CANARYTOKEN triggered: memo=%r src=%s channel=%s",
        payload.get("memo"), src_ip, payload.get("channel"),
    )


@webhooks_bp.route("/canarytokens", methods=["GET"])
def canarytokens_info():
    """Show the URL to paste into canarytokens.org (admin dashboard use)."""
    if not Config.WEBHOOK_ENABLED:
        return jsonify({"enabled": False, "webhook_url": None})

    secret = get_webhook_secret()
    if Config.WEBHOOK_PUBLIC_URL:
        base = Config.WEBHOOK_PUBLIC_URL.rstrip("/")
    else:
        host = request.host.split(":")[0]
        base = f"http://{host}:{Config.WEBHOOK_PORT}"
    return jsonify({
        "enabled": True,
        "port": Config.WEBHOOK_PORT,
        "webhook_url": f"{base}/canarytokens/{secret}",
    })
