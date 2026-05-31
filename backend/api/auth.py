"""
Authentication API blueprint.

Provides Pi-hole-style single-admin authentication:
- First-run setup (create password)
- Login / logout
- Change password

Supports multiple concurrent sessions (e.g. phone + laptop) by storing
each session as a row in the AuthSession table.
"""

import secrets
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from models import SystemConfig, AuthSession, db

auth_bp = Blueprint("auth", __name__)

# Key stored in SystemConfig for the admin password hash
_KEY_PASSWORD_HASH = "admin_password_hash"

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


def _add_token(token: str) -> None:
    """Add a new session token and prune expired sessions."""
    from datetime import timedelta
    db.session.add(AuthSession(token=token))
    # Prune expired sessions
    timeout = _get_session_timeout_hours()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=timeout)
    AuthSession.query.filter(AuthSession.created_at < cutoff).delete()
    db.session.commit()


def _remove_token(token: str) -> None:
    """Remove a specific session token (logout)."""
    AuthSession.query.filter_by(token=token).delete()
    db.session.commit()


def _set_session_cookie(response, token: str):
    """Set the httpOnly session cookie on a response."""
    max_age = _get_session_timeout_hours() * 3600
    # Mark cookie Secure when served behind TLS (Caddy, etc.) so browsers
    # send it back on subsequent HTTPS requests.
    is_https = (
        request.is_secure
        or request.headers.get("X-Forwarded-Proto") == "https"
    )
    response.set_cookie(
        SESSION_COOKIE_NAME,
        token,
        httponly=True,
        samesite="Lax",
        secure=is_https,
        path="/",
        max_age=max_age,
    )
    return response


def has_admin() -> bool:
    """Return True if an admin password has been configured."""
    return _get_config_value(_KEY_PASSWORD_HASH) is not None


def is_authenticated(cookie_token: str | None) -> bool:
    """Check whether the given cookie token matches any active session."""
    if not cookie_token:
        return False
    session_row = AuthSession.query.get(cookie_token)
    if session_row is None:
        return False
    timeout = _get_session_timeout_hours()
    now = datetime.now(timezone.utc)
    created = session_row.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_hours = (now - created).total_seconds() / 3600
    return age_hours <= timeout


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@auth_bp.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Public. Returns whether an admin exists and whether the caller is
    authenticated."""
    from config import Config
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    resp: dict = {
        "has_admin": has_admin(),
        "authenticated": is_authenticated(cookie_token),
        "read_only": Config.READ_ONLY,
    }
    if Config.READ_ONLY and Config.READONLY_PASSWORD:
        resp["readonly_password"] = Config.READONLY_PASSWORD
    return jsonify(resp)


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
    _add_token(token)

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
    _add_token(token)

    resp = make_response(jsonify({"message": "Logged in"}))
    _set_session_cookie(resp, token)
    return resp


@auth_bp.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Remove this session's token and delete the cookie."""
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        _remove_token(cookie_token)

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
    _add_token(token)

    resp = make_response(jsonify({"message": "Password changed"}))
    _set_session_cookie(resp, token)
    return resp
