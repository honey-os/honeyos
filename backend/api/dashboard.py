"""
Dashboard API blueprint -- summary and timeline data.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from models import Event, Session, db
from services.event_processor import EventProcessor

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/dashboard/summary", methods=["GET"])
def summary():
    """
    Return a high-level dashboard summary.

    Response:
        total_events, active_sessions, top_attackers,
        protocol_breakdown, recent_activity, threat_level
    """
    total_events = Event.query.count()
    active_sessions = Session.query.filter_by(status="active").count()

    # Top attackers (top 10 source IPs by event count)
    top_attackers_q = (
        db.session.query(Event.source_ip, db.func.count(Event.id).label("count"))
        .group_by(Event.source_ip)
        .order_by(db.text("count DESC"))
        .limit(10)
        .all()
    )
    top_attackers = [{"ip": ip, "count": count} for ip, count in top_attackers_q]

    # Protocol breakdown
    protocol_q = (
        db.session.query(Event.protocol, db.func.count(Event.id).label("count"))
        .group_by(Event.protocol)
        .all()
    )
    protocol_breakdown = {proto: count for proto, count in protocol_q}

    # Recent activity (last 10 events)
    recent = (
        Event.query
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_activity = [e.to_dict() for e in recent]

    # Threat level
    processor = EventProcessor()
    threat_level = processor.get_threat_level()

    return jsonify({
        "total_events": total_events,
        "active_sessions": active_sessions,
        "top_attackers": top_attackers,
        "protocol_breakdown": protocol_breakdown,
        "recent_activity": recent_activity,
        "threat_level": threat_level,
    })


@dashboard_bp.route("/api/dashboard/timeline", methods=["GET"])
def timeline():
    """
    Return time-series event counts for charting.

    Query params:
        hours  (int) default 24 -- how many hours of history
    """
    hours = int(request.args.get("hours", 24))
    hours = max(1, min(hours, 720))  # 1 hour to 30 days

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    events = (
        Event.query
        .filter(Event.timestamp >= start)
        .order_by(Event.timestamp.asc())
        .all()
    )

    # Bucket events into hourly slots
    buckets: dict[str, int] = {}
    for h in range(hours):
        bucket_time = start + timedelta(hours=h)
        key = bucket_time.strftime("%Y-%m-%dT%H:00:00Z")
        buckets[key] = 0

    for event in events:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        if key in buckets:
            buckets[key] += 1

    timeline_data = [{"time": k, "count": v} for k, v in buckets.items()]

    return jsonify({
        "timeline": timeline_data,
        "hours": hours,
        "total_events": len(events),
    })
