"""
Credentials API blueprint -- aggregated top usernames, passwords, and
username+password combinations from authentication events.
"""

from flask import Blueprint, jsonify, request

from models import Event, db

credentials_bp = Blueprint("credentials", __name__)

CREDENTIAL_PROTOCOLS = ("ssh", "telnet", "ftp", "mysql", "postgresql", "rdp")


@credentials_bp.route("/api/credentials", methods=["GET"])
def get_credentials():
    """
    Return top-N aggregated usernames, passwords, and combos extracted
    from authentication event details JSON.

    Query params:
        protocol  (str)  optional – filter to a single protocol
        limit     (int)  default 50, max 200
    """
    protocol = request.args.get("protocol")
    limit = min(int(request.args.get("limit", 50)), 200)

    # --- Base filters common to all three queries -------------------------
    base_filters = [
        Event.event_type == "authentication",
        Event.protocol.in_(CREDENTIAL_PROTOCOLS),
        Event.details.isnot(None),
    ]
    if protocol and protocol in CREDENTIAL_PROTOCOLS:
        base_filters.append(Event.protocol == protocol)

    username_expr = db.func.json_extract(Event.details, "$.username")
    password_expr = db.func.json_extract(Event.details, "$.password")

    # --- Total attempts ---------------------------------------------------
    total_attempts = (
        db.session.query(db.func.count(Event.id))
        .filter(*base_filters)
        .scalar()
    ) or 0

    # --- Top usernames ----------------------------------------------------
    top_usernames_q = (
        db.session.query(
            username_expr.label("username"),
            db.func.count(Event.id).label("cnt"),
            db.func.group_concat(db.distinct(Event.protocol)).label("protocols"),
        )
        .filter(*base_filters, username_expr.isnot(None), username_expr != "")
        .group_by(username_expr)
        .order_by(db.text("cnt DESC"))
        .limit(limit)
        .all()
    )
    top_usernames = [
        {
            "username": row.username,
            "count": row.cnt,
            "protocols": sorted(row.protocols.split(",")) if row.protocols else [],
        }
        for row in top_usernames_q
    ]

    # --- Top passwords (exclude MySQL – no password field) ----------------
    password_filters = base_filters + [
        password_expr.isnot(None),
        password_expr != "",
    ]
    top_passwords_q = (
        db.session.query(
            password_expr.label("password"),
            db.func.count(Event.id).label("cnt"),
        )
        .filter(*password_filters)
        .group_by(password_expr)
        .order_by(db.text("cnt DESC"))
        .limit(limit)
        .all()
    )
    top_passwords = [
        {"password": row.password, "count": row.cnt}
        for row in top_passwords_q
    ]

    # --- Top combos -------------------------------------------------------
    top_combos_q = (
        db.session.query(
            username_expr.label("username"),
            password_expr.label("password"),
            db.func.count(Event.id).label("cnt"),
            db.func.group_concat(db.distinct(Event.protocol)).label("protocols"),
        )
        .filter(
            *password_filters,
            username_expr.isnot(None),
            username_expr != "",
        )
        .group_by(username_expr, password_expr)
        .order_by(db.text("cnt DESC"))
        .limit(limit)
        .all()
    )
    top_combos = [
        {
            "username": row.username,
            "password": row.password,
            "count": row.cnt,
            "protocols": sorted(row.protocols.split(",")) if row.protocols else [],
        }
        for row in top_combos_q
    ]

    return jsonify({
        "total_attempts": total_attempts,
        "top_usernames": top_usernames,
        "top_passwords": top_passwords,
        "top_combos": top_combos,
    })
