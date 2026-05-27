"""
Sessions API blueprint.
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from config import Config
from models import Session, db
from services.session_recorder import SessionRecorder
from services.threatfox import ThreatFoxService, extract_iocs
from services.urlhaus import UrlhausService
from utils.helpers import parse_json_field

sessions_bp = Blueprint("sessions", __name__)


@sessions_bp.route("/api/features", methods=["GET"])
def get_features():
    """Return feature flags based on available configuration."""
    return jsonify({
        "threatfox": bool(Config.ABUSECH_API_KEY),
    })


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
    per_page = min(int(request.args.get("per_page", request.args.get("limit", 50))), 500)
    page = max(int(request.args.get("page", 1)), 1)
    offset = (page - 1) * per_page

    query = Session.query

    protocol = request.args.get("protocol")
    if protocol:
        query = query.filter(Session.protocol == protocol)

    status = request.args.get("status")
    if status:
        query = query.filter(Session.status == status)

    active_only = request.args.get("active_only", "false").lower() in ("true", "1", "yes")
    if active_only and not status:
        query = query.filter(Session.status == "active")

    total = query.count()
    pages = max((total + per_page - 1) // per_page, 1)
    sessions = (
        query
        .order_by(Session.start_time.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    return jsonify({
        "items": [s.to_dict() for s in sessions],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
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


@sessions_bp.route("/api/sessions/<session_id>/identify-malware", methods=["POST"])
def identify_malware(session_id: str):
    """Query ThreatFox and URLhaus for IOCs extracted from the session."""
    session = Session.query.get(session_id)
    if not session:
        return jsonify({"error": "Session not found"}), 404

    if not Config.ABUSECH_API_KEY:
        return jsonify({"error": "abuse.ch API key not configured"}), 503

    iocs = extract_iocs(session)

    threatfox = ThreatFoxService(Config.ABUSECH_API_KEY)
    urlhaus = UrlhausService(Config.ABUSECH_API_KEY)

    all_matches: list[dict] = []
    for ioc in iocs:
        all_matches.extend(threatfox.search_ioc(ioc))
    all_matches.extend(urlhaus.analyze_iocs(iocs))

    result = {
        "iocs_searched": iocs,
        "matches": all_matches,
        "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }

    session.threat_intel = json.dumps(result)
    db.session.commit()

    return jsonify(result)
