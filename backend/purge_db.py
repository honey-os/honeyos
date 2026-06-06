#!/usr/bin/env python3
"""
One-time database cleanup script.  Pure sqlite3 — no Flask or SQLAlchemy.

Aggregates existing event data into daily_stats, then deletes old events
and sessions, and VACUUMs the database.

Usage (from the repo root):
    python backend/purge_db.py data/honeyos.db [--dry-run]

Or via docker exec against a running container:
    docker compose exec backend python purge_db.py /data/honeyos.db [--dry-run]

Stop the app first if possible so nothing writes during VACUUM.
"""

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timedelta, timezone

RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "7"))


def generate_id():
    return uuid.uuid4().hex[:12]


def get_db(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def ensure_daily_stats_table(conn):
    """Create daily_stats table if it doesn't exist yet."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS daily_stats (
            id TEXT PRIMARY KEY,
            date DATE NOT NULL,
            protocol VARCHAR(32) NOT NULL,
            total_events INTEGER DEFAULT 0,
            connection_events INTEGER DEFAULT 0,
            auth_events INTEGER DEFAULT 0,
            unique_source_ips INTEGER DEFAULT 0,
            high_severity_events INTEGER DEFAULT 0,
            blocked_events INTEGER DEFAULT 0,
            top_source_ips TEXT,
            top_usernames TEXT,
            top_passwords TEXT,
            UNIQUE (date, protocol)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_daily_stats_date ON daily_stats (date)")
    # Add blocked_events column if missing (table existed before this feature)
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(daily_stats)")}
    if "blocked_events" not in cols:
        conn.execute("ALTER TABLE daily_stats ADD COLUMN blocked_events INTEGER DEFAULT 0")
    conn.commit()


def aggregate_day(conn, target_date):
    """Aggregate one day's events into daily_stats.  Returns number of rows created."""
    day_start = f"{target_date}T00:00:00"
    day_end = f"{target_date + timedelta(days=1)}T00:00:00"

    # Check what's already aggregated for this date
    existing = {}
    for row in conn.execute(
        "SELECT protocol, top_source_ips FROM daily_stats WHERE date = ?",
        (target_date.isoformat(),),
    ):
        existing[row["protocol"]] = row["top_source_ips"]

    # Get protocols active that day
    protocols = [
        row[0] for row in conn.execute(
            "SELECT DISTINCT protocol FROM events WHERE timestamp >= ? AND timestamp < ?",
            (day_start, day_end),
        ) if row[0]
    ]

    created = 0
    for protocol in protocols:
        # Skip if already fully aggregated (has top_source_ips)
        if protocol in existing and existing[protocol] is not None:
            continue

        # Counts
        row = conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN event_type = 'connection' THEN 1 ELSE 0 END) as connections,
                SUM(CASE WHEN event_type = 'authentication' THEN 1 ELSE 0 END) as auths,
                SUM(CASE WHEN severity IN ('high', 'critical') THEN 1 ELSE 0 END) as high_sev,
                COUNT(DISTINCT source_ip) as unique_ips
            FROM events
            WHERE timestamp >= ? AND timestamp < ? AND protocol = ?
        """, (day_start, day_end, protocol)).fetchone()

        total = row["total"]
        if total == 0:
            continue

        # Top 10 source IPs
        top_ips = conn.execute("""
            SELECT source_ip, COUNT(*) as cnt
            FROM events
            WHERE timestamp >= ? AND timestamp < ? AND protocol = ?
            GROUP BY source_ip ORDER BY cnt DESC LIMIT 10
        """, (day_start, day_end, protocol)).fetchall()
        top_ips_json = json.dumps([{"ip": r["source_ip"], "count": r["cnt"]} for r in top_ips])

        # Top 10 usernames
        top_users = conn.execute("""
            SELECT json_extract(details, '$.username') as u, COUNT(*) as cnt
            FROM events
            WHERE timestamp >= ? AND timestamp < ? AND protocol = ?
              AND event_type = 'authentication'
              AND json_extract(details, '$.username') IS NOT NULL
              AND json_extract(details, '$.username') != ''
            GROUP BY u ORDER BY cnt DESC LIMIT 10
        """, (day_start, day_end, protocol)).fetchall()
        top_users_json = json.dumps([{"username": r["u"], "count": r["cnt"]} for r in top_users])

        # Top 10 passwords
        top_passwords = conn.execute("""
            SELECT json_extract(details, '$.password') as p, COUNT(*) as cnt
            FROM events
            WHERE timestamp >= ? AND timestamp < ? AND protocol = ?
              AND event_type = 'authentication'
              AND json_extract(details, '$.password') IS NOT NULL
              AND json_extract(details, '$.password') != ''
            GROUP BY p ORDER BY cnt DESC LIMIT 10
        """, (day_start, day_end, protocol)).fetchall()
        top_passwords_json = json.dumps([{"password": r["p"], "count": r["cnt"]} for r in top_passwords])

        if protocol not in existing:
            # Insert new row
            conn.execute("""
                INSERT INTO daily_stats
                    (id, date, protocol, total_events, connection_events, auth_events,
                     high_severity_events, blocked_events, unique_source_ips,
                     top_source_ips, top_usernames, top_passwords)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
            """, (
                generate_id(), target_date.isoformat(), protocol,
                row["total"], row["connections"], row["auths"],
                row["high_sev"], row["unique_ips"],
                top_ips_json, top_users_json, top_passwords_json,
            ))
            created += 1
        else:
            # Update existing row with top-N data
            conn.execute("""
                UPDATE daily_stats
                SET unique_source_ips = ?, top_source_ips = ?,
                    top_usernames = ?, top_passwords = ?
                WHERE date = ? AND protocol = ?
            """, (
                row["unique_ips"], top_ips_json,
                top_users_json, top_passwords_json,
                target_date.isoformat(), protocol,
            ))

    conn.commit()
    return created


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python purge_db.py <path-to-honeyos.db> [--dry-run]")
        print("  e.g. python purge_db.py /data/honeyos.db")
        print("  e.g. python purge_db.py data/honeyos.db --dry-run")
        sys.exit(1)

    db_path = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    if not os.path.exists(db_path):
        print(f"Error: database not found at {db_path}")
        sys.exit(1)

    file_size_mb = os.path.getsize(db_path) / (1024 * 1024)
    print(f"Database: {db_path} ({file_size_mb:.1f} MB)")
    print()

    conn = get_db(db_path)
    ensure_daily_stats_table(conn)

    # --- Step 1: Current state ---
    total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    active_sessions = conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE status = 'active'"
    ).fetchone()[0]

    print(f"Current state:")
    print(f"  Events:          {total_events:,}")
    print(f"  Sessions:        {total_sessions:,} ({active_sessions:,} active)")
    print()

    # --- Step 2: Date range ---
    oldest_row = conn.execute("SELECT MIN(timestamp) FROM events").fetchone()
    newest_row = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()
    if not oldest_row[0]:
        print("No events to process.")
        conn.close()
        return

    oldest = datetime.fromisoformat(oldest_row[0].replace("Z", "+00:00"))
    newest = datetime.fromisoformat(newest_row[0].replace("Z", "+00:00"))
    print(f"Event date range:  {oldest.date()} to {newest.date()}")

    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    cutoff_str = cutoff.isoformat()
    print(f"Retention cutoff:  {cutoff.date()} ({RETENTION_DAYS} days)")
    print()

    # --- Step 3: Show per-day breakdown ---
    print("Events per day:")
    day_counts = conn.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as cnt
        FROM events GROUP BY day ORDER BY day
    """).fetchall()
    for row in day_counts:
        marker = " <- will delete" if row["day"] < cutoff.date().isoformat() else ""
        print(f"  {row['day']}: {row['cnt']:>10,}{marker}")
    print()

    # --- Step 4: Aggregate all days ---
    print("Aggregating daily stats...")
    day = oldest.date()
    end_day = newest.date()
    days_scanned = 0
    total_created = 0
    while day <= end_day:
        count = aggregate_day(conn, day)
        if count:
            print(f"  {day}: {count} protocol(s) aggregated")
        total_created += count
        days_scanned += 1
        day += timedelta(days=1)
    print(f"  Scanned {days_scanned} days, created {total_created} stat rows")
    print()

    if dry_run:
        old_events = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff_str,)
        ).fetchone()[0]
        old_sessions = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE status != 'active' AND start_time < ?",
            (cutoff_str,),
        ).fetchone()[0]
        stale_active = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE status = 'active' AND start_time < ?",
            (cutoff_str,),
        ).fetchone()[0]
        print(f"DRY RUN -- would delete:")
        print(f"  Events older than {RETENTION_DAYS} days:            {old_events:,}")
        print(f"  Completed sessions older than {RETENTION_DAYS} days: {old_sessions:,}")
        print(f"  Stale active sessions:                     {stale_active:,}")
        print()
        print("Run without --dry-run to execute.")
        conn.close()
        return

    # --- Step 5: Delete old events ---
    print("Deleting events older than retention cutoff...")
    conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_str,))
    deleted_events = conn.execute("SELECT changes()").fetchone()[0]
    conn.commit()
    print(f"  Deleted {deleted_events:,} events")

    # --- Step 6: Clean up sessions ---
    print("Cleaning up sessions...")

    # Delete stale active sessions with zero commands
    conn.execute("""
        DELETE FROM sessions
        WHERE status = 'active'
          AND start_time < ?
          AND (commands_count IS NULL OR commands_count = 0)
    """, (cutoff_str,))
    deleted_empty = conn.execute("SELECT changes()").fetchone()[0]

    # Mark stale active sessions with commands as completed
    conn.execute("""
        UPDATE sessions SET status = 'completed', end_time = ?
        WHERE status = 'active' AND start_time < ?
    """, (cutoff_str, cutoff_str))
    marked_completed = conn.execute("SELECT changes()").fetchone()[0]

    # Delete old completed sessions
    conn.execute("""
        DELETE FROM sessions
        WHERE status != 'active' AND start_time < ?
    """, (cutoff_str,))
    deleted_sessions = conn.execute("SELECT changes()").fetchone()[0]
    conn.commit()

    print(f"  Deleted {deleted_empty:,} empty stale sessions")
    print(f"  Marked {marked_completed:,} stale sessions as completed")
    print(f"  Deleted {deleted_sessions:,} old completed sessions")

    # --- Step 7: VACUUM ---
    print("Running VACUUM (this may take a moment on large DBs)...")
    conn.execute("VACUUM")
    print("  Done")
    print()

    # --- Final state ---
    remaining_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    remaining_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    stat_rows = conn.execute("SELECT COUNT(*) FROM daily_stats").fetchone()[0]
    new_size_mb = os.path.getsize(db_path) / (1024 * 1024)

    print(f"Final state:")
    print(f"  Events:          {remaining_events:,}")
    print(f"  Sessions:        {remaining_sessions:,}")
    print(f"  Daily stat rows: {stat_rows:,}")
    print(f"  Database size:   {new_size_mb:.1f} MB (was {file_size_mb:.1f} MB)")

    conn.close()


if __name__ == "__main__":
    main()
