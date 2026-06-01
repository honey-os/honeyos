"""
Throttle API blueprint -- exposes currently blocked IP/protocol pairs.
"""

from flask import Blueprint, current_app, jsonify

throttle_bp = Blueprint("throttle", __name__)


@throttle_bp.route("/api/throttle/blocked", methods=["GET"])
def list_blocked():
    """Return all currently active per-IP, per-protocol blocks."""
    throttler = getattr(current_app, "connection_throttler", None)
    if throttler is None:
        return jsonify({"items": []})

    return jsonify({"items": throttler.get_all_blocked()})
