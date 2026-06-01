#!/usr/bin/env python3
"""
One-time database cleanup script.

Aggregates existing event data into daily_stats, then deletes old events
and sessions, and VACUUMs the database.

Usage:
    cd backend && python purge_db.py [--dry-run]

Must be run while the app is stopped (or at least not actively writing).
"""

import json
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from datetime import datetime, timedelta, timezone

from flask import Flask
from config import Config
from models import DailyStat, Event, Session, db
from utils.helpers import generate_id


def create_minimal_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app


def aggregate_day(target_date):
    """Compute and store daily summary stats for a given date."""
    day_start = datetime(target_date.year, target_date.month, target_date.day, tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)

    existing = {
        row.protocol: row
        for row in DailyStat.query.filter_by(date=target_date).all()
    }

    protocols = [
        row[0] for row in
        db.session.query(db.distinct(Event.protocol))
        .filter(Event.timestamp >= day_start, Event.timestamp < day_end)
        .all()
        if row[0]
    ]

    created = 0
    for protocol in protocols:
        stat = existing.get(protocol)
        if stat and stat.top_source_ips is not None:
            continue  # already fully aggregated

        base = Event.query.filter(
            Event.timestamp >= day_start,
            Event.timestamp < day_end,
            Event.protocol == protocol,
        )

        total = base.count()
        if total == 0:
            continue

        if not stat:
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
            created += 1

        # Unique IPs
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

        # Top 10 usernames
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
    return created


def main():
    dry_run = "--dry-run" in sys.argv
    app = create_minimal_app()

    with app.app_context():
        # Enable WAL
        from sqlalchemy import text
        db.session.execute(text("PRAGMA journal_mode=WAL"))

        # --- Step 1: Check current size ---
        total_events = db.session.query(db.func.count()).select_from(Event).scalar()
        total_sessions = db.session.query(db.func.count()).select_from(Session).scalar()
        active_sessions = Session.query.filter_by(status="active").count()
        print(f"Current state:")
        print(f"  Events:          {total_events:,}")
        print(f"  Sessions:        {total_sessions:,} ({active_sessions:,} active)")
        print()

        # --- Step 2: Find date range ---
        oldest = db.session.query(db.func.min(Event.timestamp)).scalar()
        newest = db.session.query(db.func.max(Event.timestamp)).scalar()
        if not oldest:
            print("No events to process.")
            return

        if oldest.tzinfo is None:
            oldest = oldest.replace(tzinfo=timezone.utc)
        if newest.tzinfo is None:
            newest = newest.replace(tzinfo=timezone.utc)

        print(f"Event date range:  {oldest.date()} to {newest.date()}")

        cutoff = datetime.now(timezone.utc) - timedelta(days=Config.RETENTION_DAYS)
        print(f"Retention cutoff:  {cutoff.date()} ({Config.RETENTION_DAYS} days)")
        print()

        # --- Step 3: Aggregate all days ---
        print("Aggregating daily stats...")
        day = oldest.date()
        end_day = newest.date()
        days_aggregated = 0
        while day <= end_day:
            count = aggregate_day(day)
            if count:
                print(f"  {day}: {count} protocol(s) aggregated")
            days_aggregated += 1
            day += timedelta(days=1)
        print(f"  Scanned {days_aggregated} days")
        print()

        if dry_run:
            # Show what would be deleted
            old_events = db.session.query(db.func.count()).select_from(Event).filter(
                Event.timestamp < cutoff
            ).scalar()
            old_sessions = db.session.query(db.func.count()).select_from(Session).filter(
                Session.status != "active",
                Session.start_time < cutoff,
            ).scalar()
            stale_active = Session.query.filter(
                Session.status == "active",
                Session.start_time < cutoff,
            ).count()
            print(f"DRY RUN — would delete:")
            print(f"  Events older than {Config.RETENTION_DAYS} days: {old_events:,}")
            print(f"  Completed sessions older than {Config.RETENTION_DAYS} days: {old_sessions:,}")
            print(f"  Stale active sessions: {stale_active:,}")
            print()
            print("Run without --dry-run to execute.")
            return

        # --- Step 4: Delete old events ---
        print("Deleting events older than retention cutoff...")
        deleted_events = Event.query.filter(Event.timestamp < cutoff).delete()
        db.session.commit()
        print(f"  Deleted {deleted_events:,} events")

        # --- Step 5: Clean up sessions ---
        print("Cleaning up sessions...")
        # Mark stale active sessions as completed
        stale_cutoff = datetime.now(timezone.utc) - timedelta(seconds=300)
        stale = Session.query.filter(
            Session.status == "active",
            Session.start_time < stale_cutoff,
        ).all()
        for s in stale:
            if (s.commands_count or 0) == 0:
                db.session.delete(s)
            else:
                s.status = "completed"
                s.end_time = stale_cutoff
        db.session.commit()
        print(f"  Cleaned up {len(stale):,} stale active sessions")

        # Delete old completed sessions
        deleted_sessions = Session.query.filter(
            Session.status != "active",
            Session.start_time < cutoff,
        ).delete()
        db.session.commit()
        print(f"  Deleted {deleted_sessions:,} old sessions")

        # --- Step 6: VACUUM ---
        print("Running VACUUM (this may take a moment)...")
        db.session.execute(text("VACUUM"))
        print("  Done")
        print()

        # --- Final state ---
        remaining_events = db.session.query(db.func.count()).select_from(Event).scalar()
        remaining_sessions = db.session.query(db.func.count()).select_from(Session).scalar()
        stat_rows = db.session.query(db.func.count()).select_from(DailyStat).scalar()
        print(f"Final state:")
        print(f"  Events:          {remaining_events:,}")
        print(f"  Sessions:        {remaining_sessions:,}")
        print(f"  Daily stat rows: {stat_rows:,}")


if __name__ == "__main__":
    main()
