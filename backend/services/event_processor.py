"""
EventProcessor -- validates, enriches, persists events and triggers alerts.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from config import Config
from models import Event, Honeypot, Session, db
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
        if self.connection_throttler:
            ip = event_data.get("source_ip", "")
            protocol = event_data.get("protocol", "")
            if ip and protocol and self.connection_throttler.is_blocked(ip, protocol):
                return None

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
        - Multiple protocols from the same IP (reconnaissance)
        - High-severity events capped per-IP (one bot can't dominate)
        - Total event volume with logarithmic scaling (diminishing returns)

        Returns a dict with ``level`` (low / medium / high / critical) and
        ``score`` (0-100).
        """
        import math

        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        # Single scan for volume, unique IPs, and unique protocols
        stats = db.session.query(
            db.func.count(Event.id),
            db.func.count(db.distinct(Event.source_ip)),
            db.func.count(db.distinct(Event.protocol)),
        ).filter(Event.timestamp >= one_hour_ago).first()

        recent_count = stats[0] or 0
        unique_ips = stats[1] or 0
        unique_protocols = stats[2] or 0

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
        #   recon   : unique_protocols * 3     — multi-protocol probing
        #   severity: sqrt(capped_high_sev) * 3 — diminishing returns on severity
        volume_score = math.log2(recent_count + 1) * 2
        breadth_score = math.sqrt(unique_ips) * 4
        recon_score = unique_protocols * 3
        severity_score = math.sqrt(capped_high_sev) * 3

        score = min(100, int(volume_score + breadth_score + recon_score + severity_score))

        # Thresholds:
        #   2 IPs, 1 protocol, low sev, 5 events    → ~18 (low)
        #   8 IPs, 4 protocols, 27 events, some sev  → ~43 (medium)
        #   30 IPs, 5 protocols, 500 events, high sev → ~71 (high)
        #   50+ IPs, 7 protocols, 1000+ events        → ~90 (critical)
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
            "unique_protocols": unique_protocols,
        }
