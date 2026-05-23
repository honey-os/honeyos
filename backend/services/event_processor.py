"""
EventProcessor -- validates, enriches, persists events and triggers alerts.
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from models import Event, Session, db
from utils.helpers import generate_id, sanitize_input

logger = logging.getLogger(__name__)


class EventProcessor:
    """Central event ingestion pipeline."""

    def __init__(self, alert_service=None):
        self.alert_service = alert_service

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
        Calculate a simple threat-level indicator based on recent activity.

        Returns a dict with ``level`` (low / medium / high / critical) and
        ``score`` (0-100).
        """
        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        recent_count = Event.query.filter(Event.timestamp >= one_hour_ago).count()

        high_sev = Event.query.filter(
            Event.timestamp >= one_hour_ago,
            Event.severity.in_(["high", "critical"]),
        ).count()

        unique_ips = (
            db.session.query(Event.source_ip)
            .filter(Event.timestamp >= one_hour_ago)
            .distinct()
            .count()
        )

        # Weighted score
        score = min(100, recent_count * 2 + high_sev * 15 + unique_ips * 5)

        if score >= 75:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"
        else:
            level = "low"

        return {
            "level": level,
            "score": score,
            "recent_events": recent_count,
            "high_severity_events": high_sev,
            "unique_attackers": unique_ips,
        }
