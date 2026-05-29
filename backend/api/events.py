"""
Events API blueprint.
"""

import csv
import io
import json
from datetime import datetime, timezone

from flask import Blueprint, Response, current_app, jsonify, request

from models import Event, db
from services.event_processor import EventProcessor
from utils.helpers import generate_id

events_bp = Blueprint("events", __name__)


def _apply_event_filters(query):
    """Apply standard event filters from request.args to a query."""
    event_type = request.args.get("event_type")
    if event_type:
        query = query.filter(Event.event_type == event_type)

    source_ip = request.args.get("source_ip")
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)

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

    return query


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
    per_page = min(int(request.args.get("per_page", request.args.get("limit", 50))), 500)
    page = max(int(request.args.get("page", 1)), 1)
    offset = (page - 1) * per_page

    query = _apply_event_filters(Event.query)

    total = query.count()
    pages = max((total + per_page - 1) // per_page, 1)
    events = (
        query
        .order_by(Event.timestamp.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    return jsonify({
        "items": [e.to_dict() for e in events],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    })


@events_bp.route("/api/events/export", methods=["GET"])
def export_events():
    """Export all matching events as a CSV file."""
    query = _apply_event_filters(Event.query)
    events = query.order_by(Event.timestamp.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ID", "Timestamp", "Event Type", "Protocol", "Source IP",
        "Source Port", "Destination Port", "Severity", "Details",
        "Session ID", "User Agent",
    ])
    for e in events:
        details = e.details or ""
        if isinstance(details, dict):
            details = json.dumps(details)
        writer.writerow([
            e.id,
            e.timestamp.isoformat() + "Z" if e.timestamp else "",
            e.event_type,
            e.protocol,
            e.source_ip,
            e.source_port or "",
            e.destination_port or "",
            e.severity,
            details,
            e.session_id or "",
            e.user_agent or "",
        ])

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="honeyos-events-{today}.csv"',
        },
    )


@events_bp.route("/api/events", methods=["POST"])
def create_event():
    """Create a new event."""
    data = request.get_json(force=True)

    processor = EventProcessor(
        connection_throttler=getattr(current_app, "connection_throttler", None),
    )
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
