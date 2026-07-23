"""
Data retention service.

Aggregates old event data into ``daily_stats`` rows, then deletes events and
sessions older than the retention window.  Deletes run in small batches so a
run interrupted mid-way (worker restart, timeout) still makes durable
progress instead of rolling back one giant transaction.

All functions expect an active Flask application context.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from models import DailyStat, Event, db
from utils.helpers import generate_id

logger = logging.getLogger("honeyos")

# Rows deleted per transaction.  Small enough to commit in a few seconds on
# slow disks, large enough to clear millions of rows in a bounded number of
# batches.
DELETE_BATCH_SIZE = 50_000


def _fmt(dt: datetime) -> str:
    """Format a datetime the way SQLAlchemy stores DATETIME in SQLite
    (space-separated, microseconds, no timezone suffix) so string
    comparisons in raw SQL match stored values."""
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def aggregate_day(target_date) -> None:
    """Finalize daily stats for a given date.

    Counters (total_events, connection_events, etc.) are maintained in
    real-time by EventProcessor._increment_daily_stat().  This function
    only fills in the fields that require a full-day GROUP BY scan:
    unique_source_ips, top_source_ips, top_usernames, top_passwords.
    Idempotent: rows that already have top_source_ips are skipped.
    """
    day_start = datetime(
        target_date.year, target_date.month, target_date.day, tzinfo=timezone.utc
    )
    day_end = day_start + timedelta(days=1)

    # Get all stat rows for this date (created in real-time)
    existing_rows = DailyStat.query.filter_by(date=target_date).all()
    existing_map = {row.protocol: row for row in existing_rows}

    # Also discover protocols from events (in case real-time missed any)
    protocols = [
        row[0] for row in
        db.session.query(db.distinct(Event.protocol))
        .filter(Event.timestamp >= day_start, Event.timestamp < day_end)
        .all()
        if row[0]
    ]

    for protocol in protocols:
        stat = existing_map.get(protocol)

        # If no real-time row exists (e.g. old data from before this feature),
        # create one with counts computed from events.
        if not stat:
            base = Event.query.filter(
                Event.timestamp >= day_start,
                Event.timestamp < day_end,
                Event.protocol == protocol,
            )
            total = base.count()
            if total == 0:
                continue
            stat = DailyStat(
                id=generate_id(),
                date=target_date,
                protocol=protocol,
                total_events=total,
                connection_events=base.filter(Event.event_type == "connection").count(),
                auth_events=base.filter(Event.event_type == "authentication").count(),
                high_severity_events=base.filter(Event.severity.in_(["high", "critical"])).count(),
                blocked_events=0,
            )
            db.session.add(stat)

        # Skip if top-N data already computed (idempotent)
        if stat.top_source_ips is not None:
            continue

        # Compute unique IPs
        unique_ips = db.session.query(
            db.func.count(db.distinct(Event.source_ip))
        ).filter(
            Event.timestamp >= day_start, Event.timestamp < day_end,
            Event.protocol == protocol,
        ).scalar() or 0
        stat.unique_source_ips = unique_ips

        # Top 10 source IPs
        top_ips = (
            db.session.query(Event.source_ip, db.func.count().label("cnt"))
            .filter(Event.timestamp >= day_start, Event.timestamp < day_end, Event.protocol == protocol)
            .group_by(Event.source_ip)
            .order_by(db.text("cnt DESC"))
            .limit(10)
            .all()
        )
        stat.top_source_ips = json.dumps([{"ip": ip, "count": c} for ip, c in top_ips])

        # Top 10 usernames (auth events only)
        username_expr = db.func.json_extract(Event.details, "$.username")
        top_users = (
            db.session.query(username_expr.label("u"), db.func.count().label("cnt"))
            .filter(
                Event.timestamp >= day_start, Event.timestamp < day_end,
                Event.protocol == protocol, Event.event_type == "authentication",
                username_expr.isnot(None), username_expr != "",
            )
            .group_by(username_expr)
            .order_by(db.text("cnt DESC"))
            .limit(10)
            .all()
        )
        stat.top_usernames = json.dumps([{"username": u, "count": c} for u, c in top_users])

        # Top 10 passwords
        password_expr = db.func.json_extract(Event.details, "$.password")
        top_passwords = (
            db.session.query(password_expr.label("p"), db.func.count().label("cnt"))
            .filter(
                Event.timestamp >= day_start, Event.timestamp < day_end,
                Event.protocol == protocol, Event.event_type == "authentication",
                password_expr.isnot(None), password_expr != "",
            )
            .group_by(password_expr)
            .order_by(db.text("cnt DESC"))
            .limit(10)
            .all()
        )
        stat.top_passwords = json.dumps([{"password": p, "count": c} for p, c in top_passwords])

    db.session.commit()


def _batched_delete(table: str, where_sql: str, params: dict,
                    batch_size: int) -> int:
    """Delete matching rows in batches of ``batch_size``, committing each
    batch so progress survives interruption.  Returns rows deleted."""
    stmt = text(
        f"DELETE FROM {table} WHERE id IN "
        f"(SELECT id FROM {table} WHERE {where_sql} LIMIT :_batch)"
    )
    total = 0
    while True:
        result = db.session.execute(stmt, {**params, "_batch": batch_size})
        db.session.commit()
        deleted = result.rowcount or 0
        total += deleted
        if deleted < batch_size:
            break
    return total


def enforce_retention(retention_days: int,
                      batch_size: int = DELETE_BATCH_SIZE) -> tuple[int, int]:
    """Aggregate then delete events and sessions older than retention_days.

    Returns (deleted_events, deleted_sessions).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    # Aggregate each day that's about to be purged (that hasn't been yet).
    # Aggregation commits per day, so progress is durable.
    oldest_event = db.session.query(db.func.min(Event.timestamp)).scalar()
    if oldest_event:
        if oldest_event.tzinfo is None:
            oldest_event = oldest_event.replace(tzinfo=timezone.utc)
        day = oldest_event.date()
        cutoff_date = cutoff.date()
        while day < cutoff_date:
            try:
                aggregate_day(day)
            except Exception:
                db.session.rollback()
                logger.warning("Retention: failed to aggregate day %s", day, exc_info=True)
            day += timedelta(days=1)

    cutoff_str = _fmt(cutoff)
    deleted_events = _batched_delete(
        "events", "timestamp < :cutoff", {"cutoff": cutoff_str}, batch_size,
    )
    deleted_sessions = _batched_delete(
        "sessions", "status != 'active' AND start_time < :cutoff",
        {"cutoff": cutoff_str}, batch_size,
    )

    if deleted_events or deleted_sessions:
        logger.info(
            "Retention: pruned %d events and %d sessions older than %d days",
            deleted_events, deleted_sessions, retention_days,
        )
    return deleted_events, deleted_sessions
