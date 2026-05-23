"""
Events API blueprint.
"""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from models import Event, db
from services.event_processor import EventProcessor
from utils.helpers import generate_id

events_bp = Blueprint("events", __name__)


@events_bp.route("/api/events", methods=["GET"])
def list_events():
    """
    List events with pagination and optional filters.

    Query params:
        limit      (int)  default 50
        offset     (int)  default 0
        event_type (str)
        protocol   (str)
        severity   (str)
        start_date (ISO-8601)
        end_date   (ISO-8601)
    """
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))

    query = Event.query

    event_type = request.args.get("event_type")
    if event_type:
        query = query.filter(Event.event_type == event_type)

    protocol = request.args.get("protocol")
    if protocol:
        query = query.filter(Event.protocol == protocol)

    severity = request.args.get("severity")
    if severity:
        query = query.filter(Event.severity == severity)

    start_date = request.args.get("start_date")
    if start_date:
        try:
            dt = datetime.fromisoformat(start_date)
            query = query.filter(Event.timestamp >= dt)
        except ValueError:
            pass

    end_date = request.args.get("end_date")
    if end_date:
        try:
            dt = datetime.fromisoformat(end_date)
            query = query.filter(Event.timestamp <= dt)
        except ValueError:
            pass

    total = query.count()
    events = (
        query
        .order_by(Event.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "events": [e.to_dict() for e in events],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@events_bp.route("/api/events", methods=["POST"])
def create_event():
    """Create a new event."""
    data = request.get_json(force=True)

    processor = EventProcessor()
    event = processor.process_event(data)

    return jsonify(event.to_dict()), 201


@events_bp.route("/api/events/<event_id>", methods=["GET"])
def get_event(event_id: str):
    """Get a single event by ID, including its related session."""
    event = Event.query.get(event_id)
    if event is None:
        return jsonify({"error": "Event not found"}), 404

    result = event.to_dict()
    if event.session:
        result["session"] = event.session.to_dict()

    return jsonify(result)
