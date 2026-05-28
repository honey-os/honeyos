"""
Attackers API blueprint -- paginated list of unique attacker IPs with
aggregated data.
"""

from flask import Blueprint, current_app, jsonify, request

from models import Event, IPGeoCache, db, _iso_utc

attackers_bp = Blueprint("attackers", __name__)


@attackers_bp.route("/api/attackers", methods=["GET"])
def list_attackers():
    """
    Paginated list of unique attacker IPs with aggregated data.

    Query params:
        page         (int)  default 1
        per_page     (int)  default 25
        protocol     (str)  filter by protocol
        country_code (str)  filter by country code (post-query)
        search       (str)  IP substring match
        sort_by      (str)  'count' | 'last_seen', default 'last_seen'
    """
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(int(request.args.get("per_page", 25)), 100)
    protocol = request.args.get("protocol")
    country_code = request.args.get("country_code")
    search = request.args.get("search")
    sort_by = request.args.get("sort_by", "last_seen")

    # Base query: group by source_ip with aggregates
    query = db.session.query(
        Event.source_ip,
        db.func.count(Event.id).label("event_count"),
        db.func.max(Event.timestamp).label("last_seen"),
        db.func.min(Event.timestamp).label("first_seen"),
    )

    # Apply filters before grouping
    if protocol:
        query = query.filter(Event.protocol == protocol)
    if search:
        query = query.filter(Event.source_ip.contains(search))

    query = query.group_by(Event.source_ip)

    # Sort
    if sort_by == "last_seen":
        query = query.order_by(db.text("last_seen DESC"))
    else:
        query = query.order_by(db.text("event_count DESC"))

    # Execute full query for post-filtering and pagination
    all_results = query.all()

    # Collect distinct protocols per IP
    protocol_query = (
        db.session.query(Event.source_ip, Event.protocol)
        .distinct()
    )
    if protocol:
        protocol_query = protocol_query.filter(Event.protocol == protocol)
    if search:
        protocol_query = protocol_query.filter(Event.source_ip.contains(search))

    ip_protocols: dict[str, list[str]] = {}
    for ip, proto in protocol_query.all():
        ip_protocols.setdefault(ip, []).append(proto)

    # Batch-fetch geo data
    all_ips = [row.source_ip for row in all_results]
    geo_cache: dict[str, IPGeoCache] = {}
    if all_ips:
        cached = IPGeoCache.query.filter(IPGeoCache.ip.in_(all_ips)).all()
        geo_cache = {g.ip: g for g in cached}

    # Build throttle lookup: ip -> [{protocol, expires_in}]
    throttle_by_ip: dict[str, list[dict]] = {}
    throttler = getattr(current_app, "connection_throttler", None)
    if throttler is not None:
        for entry in throttler.get_all_blocked():
            throttle_by_ip.setdefault(entry["ip"], []).append({
                "protocol": entry["protocol"],
                "expires_in": entry["expires_in"],
            })

    # Build items with geo data, applying country_code filter post-query
    items = []
    for row in all_results:
        geo = geo_cache.get(row.source_ip)

        # Country filter applied post-query against geo cache
        if country_code:
            if not geo or (geo.country_code or "").upper() != country_code.upper():
                continue

        entry = {
            "ip": row.source_ip,
            "event_count": row.event_count,
            "first_seen": _iso_utc(row.first_seen),
            "last_seen": _iso_utc(row.last_seen),
            "protocols": sorted(ip_protocols.get(row.source_ip, [])),
            "country": geo.country if geo else None,
            "country_code": geo.country_code if geo else None,
            "city": geo.city if geo else None,
            "org": geo.org if geo else None,
            "isp": geo.isp if geo else None,
            "lat": geo.lat if geo else None,
            "lon": geo.lon if geo else None,
            "throttled": throttle_by_ip.get(row.source_ip, []),
        }
        items.append(entry)

    # Sort by blocked status if requested
    if sort_by == "blocked":
        items.sort(key=lambda x: (len(x["throttled"]) > 0, x["throttled"][0]["expires_in"] if x["throttled"] else 0), reverse=True)

    # Paginate the filtered results
    total = len(items)
    pages = max((total + per_page - 1) // per_page, 1)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_items = items[start:end]

    return jsonify({
        "items": paginated_items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    })


@attackers_bp.route("/api/attackers/<path:ip>", methods=["GET"])
def get_attacker(ip: str):
    """Return aggregated data for a single attacker IP."""
    row = (
        db.session.query(
            Event.source_ip,
            db.func.count(Event.id).label("event_count"),
            db.func.max(Event.timestamp).label("last_seen"),
            db.func.min(Event.timestamp).label("first_seen"),
        )
        .filter(Event.source_ip == ip)
        .group_by(Event.source_ip)
        .first()
    )

    if row is None:
        return jsonify({"error": "not_found", "message": f"No events for IP {ip}"}), 404

    protocols = sorted(
        p
        for (p,) in db.session.query(Event.protocol)
        .filter(Event.source_ip == ip)
        .distinct()
        .all()
    )

    geo = IPGeoCache.query.filter_by(ip=ip).first()

    throttle_list: list[dict] = []
    throttler = getattr(current_app, "connection_throttler", None)
    if throttler is not None:
        for entry in throttler.get_all_blocked():
            if entry["ip"] == ip:
                throttle_list.append({
                    "protocol": entry["protocol"],
                    "expires_in": entry["expires_in"],
                })

    return jsonify({
        "ip": row.source_ip,
        "event_count": row.event_count,
        "first_seen": _iso_utc(row.first_seen),
        "last_seen": _iso_utc(row.last_seen),
        "protocols": protocols,
        "country": geo.country if geo else None,
        "country_code": geo.country_code if geo else None,
        "city": geo.city if geo else None,
        "org": geo.org if geo else None,
        "isp": geo.isp if geo else None,
        "lat": geo.lat if geo else None,
        "lon": geo.lon if geo else None,
        "throttled": throttle_list,
    })
