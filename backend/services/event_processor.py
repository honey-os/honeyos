"""
EventProcessor -- validates, enriches, persists events and triggers alerts.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from config import Config
from models import Event, Session, db
from services.geoip import GeoIPService
from utils.helpers import generate_id, sanitize_input

logger = logging.getLogger(__name__)


class EventProcessor:
    """Central event ingestion pipeline."""

    def __init__(self, alert_service=None):
        self.alert_service = alert_service
        self.geoip_service = GeoIPService()

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def process_event(self, event_data: dict) -> Event:
        """
        Validate, enrich, persist an event and fire alert checks.

        Parameters
        ----------
        event_data : dict
            Raw event payload (must include at least event_type, protocol,
            source_ip, and destination_port).

        Returns
        -------
        Event  The persisted ORM instance.
        """
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
        db.session.commit()

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

        recent_count = Event.query.filter(
            Event.timestamp >= one_hour_ago,
        ).count()

        unique_ips = (
            db.session.query(Event.source_ip)
            .filter(Event.timestamp >= one_hour_ago)
            .distinct()
            .count()
        )

        unique_protocols = (
            db.session.query(Event.protocol)
            .filter(Event.timestamp >= one_hour_ago)
            .distinct()
            .count()
        )

        # High-severity events capped at 5 per source IP so a single bot
        # brute-forcing one service can't push us to critical on its own.
        high_sev_by_ip = (
            db.session.query(
                Event.source_ip,
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
        #   volume  : log2(events+1) * 3  — 100 events ≈ 20 pts, 1000 ≈ 30
        #   breadth : unique_ips * 8      — each new attacker is significant
        #   recon   : unique_protocols * 5 — multi-protocol probing
        #   severity: capped_high_sev * 4 — intent matters, but bounded
        volume_score = math.log2(recent_count + 1) * 3
        breadth_score = unique_ips * 8
        recon_score = unique_protocols * 5
        severity_score = capped_high_sev * 4

        score = min(100, int(volume_score + breadth_score + recon_score + severity_score))

        # Thresholds:
        #   1 IP, 1 protocol, low sev, 50 events  → ~30 (medium)
        #   1 IP, 1 protocol, high sev, 500 events → ~45 (medium)
        #   3 IPs, 2 protocols, some high sev       → ~55 (high)
        #   5+ IPs, 3+ protocols, high sev spread   → ~80+ (critical)
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
