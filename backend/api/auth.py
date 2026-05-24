"""
Authentication API blueprint.

Provides Pi-hole-style single-admin authentication:
- First-run setup (create password)
- Login / logout
- Change password
"""

import secrets
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from models import SystemConfig, db

auth_bp = Blueprint("auth", __name__)

# Keys stored in SystemConfig for auth state
_KEY_PASSWORD_HASH = "admin_password_hash"
_KEY_TOKEN = "auth_token"
_KEY_TOKEN_CREATED = "auth_token_created_at"

AUTH_INTERNAL_KEYS = {_KEY_PASSWORD_HASH, _KEY_TOKEN, _KEY_TOKEN_CREATED}

SESSION_COOKIE_NAME = "honeyos_session"


def _get_session_timeout_hours() -> int:
    from config import Config
    return Config.SESSION_TIMEOUT_HOURS


def _get_config_value(key: str) -> str | None:
    row = SystemConfig.query.get(key)
    return row.value if row else None


def _set_config_value(key: str, value: str) -> None:
    row = SystemConfig.query.get(key)
    if row:
        row.value = value
    else:
        row = SystemConfig(key=key, value=value, description="", config_type="string")
        db.session.add(row)


def _delete_config_value(key: str) -> None:
    row = SystemConfig.query.get(key)
    if row:
        db.session.delete(row)


def _store_token(token: str) -> None:
    """Store a session token and its creation timestamp in SystemConfig."""
    _set_config_value(_KEY_TOKEN, token)
    _set_config_value(_KEY_TOKEN_CREATED, datetime.now(timezone.utc).isoformat())
    db.session.commit()


def _is_token_expired(created_at_iso: str) -> bool:
    """Check whether a token has exceeded the session timeout."""
    try:
        created = datetime.fromisoformat(created_at_iso)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - created).total_seconds() / 3600
        return age_hours > _get_session_timeout_hours()
    except (ValueError, TypeError):
        return True


def _set_session_cookie(response, token: str):
    """Set the httpOnly session cookie on a response."""
    max_age = _get_session_timeout_hours() * 3600
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="Lax",
        secure=False,
        path="/",
        max_age=max_age,
    )
    return response


def has_admin() -> bool:
    """Return True if an admin password has been configured."""
    return _get_config_value(_KEY_PASSWORD_HASH) is not None


def is_authenticated(cookie_token: str | None) -> bool:
    """Check whether the given cookie token matches the stored session."""
    if not cookie_token:
        return False
    stored_token = _get_config_value(_KEY_TOKEN)
    if not stored_token or stored_token != cookie_token:
        return False
    created_at = _get_config_value(_KEY_TOKEN_CREATED)
    if not created_at or _is_token_expired(created_at):
        return False
    return True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@auth_bp.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Public. Returns whether an admin exists and whether the caller is
    authenticated."""
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    return jsonify({
        "has_admin": has_admin(),
        "authenticated": is_authenticated(cookie_token),
    })


@auth_bp.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    """Public, one-time. Create the admin password."""
    if has_admin():
        return jsonify({"error": "forbidden", "message": "Admin already configured"}), 403

    data = request.get_json(force=True)
    password = data.get("password", "")

    if len(password) < 8:
        return jsonify({
            "error": "validation",
            "message": "Password must be at least 8 characters",
        }), 400

    _set_config_value(_KEY_PASSWORD_HASH, generate_password_hash(password))
    token = secrets.token_hex(32)
    _store_token(token)

    resp = make_response(jsonify({"message": "Admin account created"}), 201)
    _set_session_cookie(resp, token)
    return resp


@auth_bp.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Public. Validate password and issue a session cookie."""
    data = request.get_json(force=True)
    password = data.get("password", "")

    stored_hash = _get_config_value(_KEY_PASSWORD_HASH)
    if not stored_hash or not check_password_hash(stored_hash, password):
        return jsonify({"error": "unauthorized", "message": "Invalid password"}), 401

    token = secrets.token_hex(32)
    _store_token(token)

    resp = make_response(jsonify({"message": "Logged in"}))
    _set_session_cookie(resp, token)
    return resp


@auth_bp.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Clear the stored token and delete the session cookie."""
    _delete_config_value(_KEY_TOKEN)
    _delete_config_value(_KEY_TOKEN_CREATED)
    db.session.commit()

    resp = make_response(jsonify({"message": "Logged out"}))
    resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return resp


@auth_bp.route("/api/auth/change-password", methods=["POST"])
def auth_change_password():
    """Protected. Change the admin password (requires current password)."""
    data = request.get_json(force=True)
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    stored_hash = _get_config_value(_KEY_PASSWORD_HASH)
    if not stored_hash or not check_password_hash(stored_hash, current_password):
        return jsonify({"error": "unauthorized", "message": "Current password is incorrect"}), 401

    if len(new_password) < 8:
        return jsonify({
            "error": "validation",
            "message": "New password must be at least 8 characters",
        }), 400

    _set_config_value(_KEY_PASSWORD_HASH, generate_password_hash(new_password))
    token = secrets.token_hex(32)
    _store_token(token)

    resp = make_response(jsonify({"message": "Password changed"}))
    _set_session_cookie(resp, token)
    return resp
