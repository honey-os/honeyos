"""
EventProcessor -- validates, enriches, persists events and triggers alerts.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from config import Config
from models import DailyStat, Event, Honeypot, Session, db
from services import deception
from services.geoip import GeoIPService
from utils.helpers import generate_id, sanitize_input

logger = logging.getLogger(__name__)


class EventProcessor:
    """Central event ingestion pipeline."""

    def __init__(self, alert_service=None, connection_throttler=None):
        self.alert_service = alert_service
        self.connection_throttler = connection_throttler
        self.geoip_service = GeoIPService()

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def process_event(self, event_data: dict) -> Event | None:
        """
        Validate, enrich, persist an event and fire alert checks.

        Parameters
        ----------
        event_data : dict
            Raw event payload (must include at least event_type, protocol,
            source_ip, and destination_port).

        Returns
        -------
        Event | None  The persisted ORM instance, or None if the IP is blocked.
        """
        # Skip persistence for already-blocked IPs — we have enough evidence.
        # Still count them in daily stats so volume is tracked.
        if self.connection_throttler:
            ip = event_data.get("source_ip", "")
            protocol = event_data.get("protocol", "")
            if ip and protocol and self.connection_throttler.is_blocked(ip, protocol):
                self._increment_daily_stat(protocol, blocked=True)
                return None

        # Honeytoken replay: planted credentials arriving on ANY protocol
        # means this source read the HTTP bait files -- the highest-confidence
        # signal the system can produce.
        details = event_data.get("details")
        if deception.check_event_for_honeytoken(details, event_data.get("raw_payload")):
            details = details or {}
            details["honeytoken"] = True
            event_data["details"] = details
            event_data["severity"] = "critical"
            logger.warning(
                "HONEYTOKEN: planted credentials used by %s via %s",
                event_data.get("source_ip"), event_data.get("protocol"),
            )

        event = Event(
            id=event_data.get("id") or generate_id(),
            event_type=sanitize_input(event_data.get("event_type", "unknown")),
            protocol=sanitize_input(event_data.get("protocol", "unknown")),
            source_ip=event_data.get("source_ip", "0.0.0.0"),
            source_port=event_data.get("source_port"),
            destination_port=event_data.get("destination_port"),
            timestamp=event_data.get("timestamp") or datetime.now(timezone.utc),
            severity=event_data.get("severity", "medium"),
            details=json.dumps(event_data.get("details")) if event_data.get("details") else None,
            session_id=event_data.get("session_id"),
            user_agent=event_data.get("user_agent"),
            raw_payload=event_data.get("raw_payload"),
            geolocation=json.dumps(event_data.get("geolocation")) if event_data.get("geolocation") else None,
        )

        # GeoIP enrichment
        if Config.GEOIP_ENABLED and not event.geolocation:
            try:
                geo = self.geoip_service.lookup(event.source_ip)
                if geo:
                    event.geolocation = json.dumps(geo)
            except Exception:
                logger.exception("GeoIP lookup failed for %s", event.source_ip)

        # Try to correlate with an existing session
        if not event.session_id:
            session = self.correlate_session(event)
            if session:
                event.session_id = session.id

        db.session.add(event)

        # Update honeypot interaction stats
        honeypot = Honeypot.query.filter_by(protocol=event.protocol).first()
        if honeypot:
            honeypot.total_interactions = (honeypot.total_interactions or 0) + 1
            honeypot.last_activity = event.timestamp

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.exception("Failed to persist event %s", event.id)
            raise

        # Increment real-time daily stats
        self._increment_daily_stat(
            event.protocol,
            event_type=event.event_type,
            severity=event.severity,
        )

        # Record for connection throttling (after successful commit)
        if self.connection_throttler:
            self.connection_throttler.record_event(event.source_ip, event.protocol)

        logger.info(
            "Event %s persisted  type=%s  src=%s  port=%s",
            event.id,
            event.event_type,
            event.source_ip,
            event.destination_port,
        )

        # Trigger alert evaluation asynchronously-safe (we are still in
        # request context so this is fine for the SQLite case).
        if self.alert_service:
            try:
                self.alert_service.check_conditions(event)
            except Exception:
                logger.exception("Alert check failed for event %s", event.id)

        return event

    # -----------------------------------------------------------------
    # Session correlation
    # -----------------------------------------------------------------

    def correlate_session(self, event: Event) -> Session | None:
        """
        Look for an active session that matches the event's source_ip and
        protocol.  If found, return it so the event can be linked.
        """
        session = (
            Session.query.filter_by(
                source_ip=event.source_ip,
                protocol=event.protocol,
                status="active",
            )
            .order_by(Session.start_time.desc())
            .first()
        )
        return session

    # -----------------------------------------------------------------
    # Threat level
    # -----------------------------------------------------------------

    def get_threat_level(self) -> dict:
        """
        Calculate a threat-level indicator based on recent activity.

        The score prioritises *breadth* and *intent* over raw volume:
        - Multiple unique source IPs (breadth of attack)
        - IPs probing 2+ distinct protocols (reconnaissance)
        - High-severity events capped per-IP (one bot can't dominate)
        - Total event volume with logarithmic scaling (diminishing returns)

        Returns a dict with ``level`` (low / medium / high / critical) and
        ``score`` (0-100).
        """
        import math

        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        # Single scan for volume and unique IPs
        stats = db.session.query(
            db.func.count(Event.id),
            db.func.count(db.distinct(Event.source_ip)),
        ).filter(Event.timestamp >= one_hour_ago).first()

        recent_count = stats[0] or 0
        unique_ips = stats[1] or 0

        # Recon signal: count IPs that probed 2+ distinct protocols.
        # A single IP scanning SSH, FTP, and MySQL is reconnaissance;
        # nine different IPs each hitting one protocol is not.
        recon_ips = (
            db.session.query(db.func.count())
            .select_from(
                db.session.query(Event.source_ip)
                .filter(Event.timestamp >= one_hour_ago)
                .group_by(Event.source_ip)
                .having(db.func.count(db.distinct(Event.protocol)) >= 2)
                .subquery()
            )
            .scalar()
        ) or 0

        # High-severity events capped at 5 per source IP so a single bot
        # brute-forcing one service can't push us to critical on its own.
        high_sev_by_ip = (
            db.session.query(
                db.func.min(db.func.count(), 5).label("capped"),
            )
            .filter(
                Event.timestamp >= one_hour_ago,
                Event.severity.in_(["high", "critical"]),
            )
            .group_by(Event.source_ip)
            .all()
        )
        capped_high_sev = sum(row.capped for row in high_sev_by_ip)

        # Scoring components:
        #   volume  : log2(events+1) * 2       — 100 events ≈ 13 pts, 1000 ≈ 20
        #   breadth : sqrt(unique_ips) * 4     — diminishing returns per IP
        #   recon   : sqrt(recon_ips) * 5      — IPs scanning 2+ protocols
        #   severity: sqrt(capped_high_sev) * 3 — diminishing returns on severity
        volume_score = math.log2(recent_count + 1) * 2
        breadth_score = math.sqrt(unique_ips) * 4
        recon_score = math.sqrt(recon_ips) * 5
        severity_score = math.sqrt(capped_high_sev) * 3

        score = min(100, int(volume_score + breadth_score + recon_score + severity_score))

        # Thresholds:
        #   2 IPs, 0 recon, low sev, 5 events          → ~14 (low)
        #   8 IPs, 3 recon, 27 events, some sev         → ~42 (medium)
        #   30 IPs, 10 recon, 500 events, high sev      → ~70 (high)
        #   50+ IPs, 20+ recon, 1000+ events             → ~90 (critical)
        if score >= 80:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 20:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "score": score,
            "recent_events": recent_count,
            "high_severity_events": capped_high_sev,
            "unique_attackers": unique_ips,
            "recon_ips": recon_ips,
        }

    # -----------------------------------------------------------------
    # Real-time daily stats
    # -----------------------------------------------------------------

    @staticmethod
    def _increment_daily_stat(
        protocol: str,
        *,
        event_type: str | None = None,
        severity: str | None = None,
        blocked: bool = False,
    ) -> None:
        """Atomically increment today's DailyStat counters for a protocol.

        Uses INSERT ... ON CONFLICT DO UPDATE so concurrent threads are safe
        under SQLite WAL mode.
        """
        today = datetime.now(timezone.utc).date()

        # Determine which counters to bump
        total_inc = 0 if blocked else 1
        conn_inc = 1 if (not blocked and event_type == "connection") else 0
        auth_inc = 1 if (not blocked and event_type == "authentication") else 0
        high_inc = 1 if (not blocked and severity in ("high", "critical")) else 0
        blocked_inc = 1 if blocked else 0

        upsert = db.text("""
            INSERT INTO daily_stats (id, date, protocol, total_events, connection_events,
                                     auth_events, high_severity_events, blocked_events)
            VALUES (:id, :date, :protocol, :total, :conn, :auth, :high_sev, :blocked)
            ON CONFLICT (date, protocol) DO UPDATE SET
                total_events = daily_stats.total_events + excluded.total_events,
                connection_events = daily_stats.connection_events + excluded.connection_events,
                auth_events = daily_stats.auth_events + excluded.auth_events,
                high_severity_events = daily_stats.high_severity_events + excluded.high_severity_events,
                blocked_events = daily_stats.blocked_events + excluded.blocked_events
        """)

        try:
            db.session.execute(upsert, {
                "id": generate_id(),
                "date": today.isoformat(),
                "protocol": protocol,
                "total": total_inc,
                "conn": conn_inc,
                "auth": auth_inc,
                "high_sev": high_inc,
                "blocked": blocked_inc,
            })
            db.session.commit()
        except Exception:
            db.session.rollback()
            logger.debug("Failed to increment daily stat", exc_info=True)
