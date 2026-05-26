"""
Dashboard API blueprint -- summary and timeline data.
"""

from collections import Counter
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from models import Event, Honeypot, IPGeoCache, Session, db, _iso_utc
from services.event_processor import EventProcessor

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/dashboard/summary", methods=["GET"])
def summary():
    """
    Return a high-level dashboard summary.

    Response:
        total_events, active_sessions, active_honeypots, threat_level,
        top_attackers, protocol_breakdown, recent_events
    """
    total_events = Event.query.count()
    active_sessions = Session.query.filter_by(status="active").count()
    active_honeypots = Honeypot.query.filter_by(enabled=True).count()

    # Top attackers (top 10 source IPs by event count)
    top_attackers_q = (
        db.session.query(
            Event.source_ip,
            db.func.count(Event.id).label("count"),
            db.func.max(Event.timestamp).label("last_seen"),
        )
        .group_by(Event.source_ip)
        .order_by(db.text("count DESC"))
        .limit(10)
        .all()
    )
    # Batch-fetch geo data for all top attacker IPs
    attacker_ips = [ip for ip, _, _ in top_attackers_q]
    geo_cache: dict[str, IPGeoCache] = {}
    if attacker_ips:
        cached = IPGeoCache.query.filter(IPGeoCache.ip.in_(attacker_ips)).all()
        geo_cache = {g.ip: g for g in cached}

    top_attackers = []
    for ip, count, last_seen in top_attackers_q:
        entry: dict = {
            "ip": ip,
            "count": count,
            "last_seen": _iso_utc(last_seen),
        }
        geo = geo_cache.get(ip)
        if geo:
            entry["country"] = geo.country
            entry["country_code"] = geo.country_code
            entry["org"] = geo.org
        top_attackers.append(entry)

    # Protocol breakdown as array of { protocol, count }
    protocol_q = (
        db.session.query(Event.protocol, db.func.count(Event.id).label("count"))
        .group_by(Event.protocol)
        .all()
    )
    protocol_breakdown = [
        {"protocol": proto, "count": count} for proto, count in protocol_q
    ]

    # Recent events (last 10)
    recent = (
        Event.query
        .order_by(Event.timestamp.desc())
        .limit(10)
        .all()
    )
    recent_events = [e.to_dict() for e in recent]

    # Threat level -- full breakdown
    processor = EventProcessor()
    threat_info = processor.get_threat_level()

    return jsonify({
        "total_events": total_events,
        "active_sessions": active_sessions,
        "active_honeypots": active_honeypots,
        "threat_level": threat_info,
        "top_attackers": top_attackers,
        "protocol_breakdown": protocol_breakdown,
        "recent_events": recent_events,
    })


@dashboard_bp.route("/api/dashboard/timeline", methods=["GET"])
def timeline():
    """
    Return time-series event counts for charting.

    Query params:
        hours  (int) default 24 -- how many hours of history

    Returns a plain array of { timestamp, count } objects.
    """
    hours = int(request.args.get("hours", 24))
    hours = max(1, min(hours, 720))  # 1 hour to 30 days
    bucket_minutes = 10

    now = datetime.now(timezone.utc)
    # Floor to the current 10-minute boundary
    current_bucket = now.replace(
        minute=(now.minute // bucket_minutes) * bucket_minutes,
        second=0,
        microsecond=0,
    )
    total_buckets = (hours * 60) // bucket_minutes
    start = current_bucket - timedelta(minutes=bucket_minutes * (total_buckets - 1))

    events = (
        Event.query
        .filter(Event.timestamp >= start)
        .order_by(Event.timestamp.asc())
        .all()
    )

    # Bucket events into 10-minute slots
    buckets: dict[str, int] = {}
    for i in range(total_buckets):
        bucket_time = start + timedelta(minutes=bucket_minutes * i)
        key = bucket_time.strftime("%Y-%m-%dT%H:%M:00Z")
        buckets[key] = 0

    for event in events:
        ts = event.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        floored = ts.replace(
            minute=(ts.minute // bucket_minutes) * bucket_minutes,
            second=0,
            microsecond=0,
        )
        key = floored.strftime("%Y-%m-%dT%H:%M:00Z")
        if key in buckets:
            buckets[key] += 1

    timeline_data = [{"timestamp": k, "count": v} for k, v in buckets.items()]

    return jsonify(timeline_data)
