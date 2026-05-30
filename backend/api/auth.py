"""
Authentication API blueprint.

Provides Pi-hole-style single-admin authentication:
- First-run setup (create password)
- Login / logout
- Change password

Supports multiple concurrent sessions (e.g. phone + laptop) by storing
tokens as a JSON list rather than a single value.
"""

import json
import secrets
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from models import SystemConfig, db

auth_bp = Blueprint("auth", __name__)

# Keys stored in SystemConfig for auth state
_KEY_PASSWORD_HASH = "admin_password_hash"
_KEY_TOKENS = "auth_tokens"  # JSON list of {token, created_at}

AUTH_INTERNAL_KEYS = {_KEY_PASSWORD_HASH, _KEY_TOKENS}

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


def _get_tokens() -> list[dict]:
    """Load the token list from SystemConfig, pruning expired entries."""
    raw = _get_config_value(_KEY_TOKENS)
    if not raw:
        # Migrate from old single-token format if present
        old_token = _get_config_value("auth_token")
        old_created = _get_config_value("auth_token_created_at")
        if old_token and old_created:
            tokens = [{"token": old_token, "created_at": old_created}]
            _delete_config_value("auth_token")
            _delete_config_value("auth_token_created_at")
            _set_config_value(_KEY_TOKENS, json.dumps(tokens))
            db.session.commit()
            return tokens
        return []
    try:
        tokens = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    return tokens


def _save_tokens(tokens: list[dict]) -> None:
    """Persist the token list, removing any expired entries first."""
    timeout = _get_session_timeout_hours()
    now = datetime.now(timezone.utc)
    live = []
    for entry in tokens:
        try:
            created = datetime.fromisoformat(entry["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_hours = (now - created).total_seconds() / 3600
            if age_hours <= timeout:
                live.append(entry)
        except (ValueError, TypeError, KeyError):
            continue
    _set_config_value(_KEY_TOKENS, json.dumps(live))
    db.session.commit()


def _add_token(token: str) -> None:
    """Add a new session token."""
    tokens = _get_tokens()
    tokens.append({
        "token": token,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    _save_tokens(tokens)


def _remove_token(token: str) -> None:
    """Remove a specific session token (logout)."""
    tokens = _get_tokens()
    tokens = [t for t in tokens if t.get("token") != token]
    _save_tokens(tokens)


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
    tokens = _get_tokens()
    timeout = _get_session_timeout_hours()
    now = datetime.now(timezone.utc)
    for entry in tokens:
        if entry.get("token") != cookie_token:
            continue
        try:
            created = datetime.fromisoformat(entry["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_hours = (now - created).total_seconds() / 3600
            if age_hours <= timeout:
                return True
        except (ValueError, TypeError, KeyError):
            continue
    return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@auth_bp.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Public. Returns whether an admin exists and whether the caller is
    authenticated."""
    from config import Config
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    return jsonify({
        "has_admin": has_admin(),
        "authenticated": is_authenticated(cookie_token),
        "read_only": Config.READ_ONLY,
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
