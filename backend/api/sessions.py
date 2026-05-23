"""
Sessions API blueprint.
"""

from flask import Blueprint, jsonify, request

from models import Session, db
from services.session_recorder import SessionRecorder
from utils.helpers import parse_json_field

sessions_bp = Blueprint("sessions", __name__)


@sessions_bp.route("/api/sessions", methods=["GET"])
def list_sessions():
    """
    List sessions with pagination and filters.

    Query params:
        limit       (int)  default 50
        offset      (int)  default 0
        protocol    (str)
        active_only (bool) default false
    """
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))

    query = Session.query

    protocol = request.args.get("protocol")
    if protocol:
        query = query.filter(Session.protocol == protocol)

    active_only = request.args.get("active_only", "false").lower() in ("true", "1", "yes")
    if active_only:
        query = query.filter(Session.status == "active")

    total = query.count()
    sessions = (
        query
        .order_by(Session.start_time.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "sessions": [s.to_dict() for s in sessions],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@sessions_bp.route("/api/sessions/<session_id>", methods=["GET"])
def get_session(session_id: str):
    """Get a session with full data."""
    session = Session.query.get(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    result = session.to_dict()
    # Include related events
    result["events"] = [e.to_dict() for e in session.events.order_by("timestamp").all()]
    return jsonify(result)


@sessions_bp.route("/api/sessions/<session_id>/replay", methods=["GET"])
def replay_session(session_id: str):
    """
    Get formatted replay data with timestamped entries for the
    frontend replay player.
    """
    recorder = SessionRecorder()
    replay = recorder.get_replay_data(session_id)
    if replay is None:
        return jsonify({"error": "Session not found"}), 404

    return jsonify(replay)
