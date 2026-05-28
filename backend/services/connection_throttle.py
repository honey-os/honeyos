"""
ConnectionThrottler -- per-IP, per-protocol event counting with automatic
time-based blocking, plus concurrent connection limiting.

Two independent mechanisms:

1. **Event throttle**: After THROTTLE_EVENT_THRESHOLD events from a single IP
   on a single protocol, block that (IP, protocol) pair for
   THROTTLE_BLOCK_SECONDS.

2. **Connection limit**: If an IP holds >= MAX_CONNECTIONS_PER_IP concurrent
   connections (across all protocols), refuse new connections and block the
   IP on all active protocols for THROTTLE_BLOCK_SECONDS.

Blocks are persisted to the ``throttle_blocks`` SQLite table so they survive
backend restarts.  The in-memory dict remains the hot-path for is_blocked()
checks (no DB queries on every connection).
"""

import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from config import Config

logger = logging.getLogger(__name__)


class ConnectionThrottler:
    """Thread-safe in-memory connection throttler with DB persistence."""

    def __init__(self, app=None) -> None:
        self._lock = threading.Lock()
        # (ip, protocol) -> event count
        self._counts: dict[tuple[str, str], int] = {}
        # (ip, protocol) -> monotonic timestamp when the block expires
        self._blocked_until: dict[tuple[str, str], float] = {}
        # ip -> number of active (in-flight) connections
        self._active: dict[str, int] = {}
        self._app = app
        if app is not None:
            self._load_from_db()

    # -----------------------------------------------------------------
    # DB persistence helpers
    # -----------------------------------------------------------------

    def _load_from_db(self) -> None:
        """On startup, restore active blocks from the database and create
        blocks for any (IP, protocol) pairs whose recent event volume already
        exceeds the threshold."""
        with self._app.app_context():
            from models import Event, ThrottleBlock, db

            # Use naive UTC for DB queries — SQLite stores naive datetimes
            # and SQLAlchemy's ORM evaluator will compare them in Python.
            now_naive = datetime.utcnow()
            now_mono = time.monotonic()

            # --- 1. Restore persisted blocks that haven't expired ----------
            blocks = ThrottleBlock.query.filter(
                ThrottleBlock.expires_at > now_naive
            ).all()
            for b in blocks:
                remaining = (b.expires_at - now_naive).total_seconds()
                self._blocked_until[(b.ip, b.protocol)] = now_mono + remaining

            # Clean up expired rows
            ThrottleBlock.query.filter(
                ThrottleBlock.expires_at <= now_naive
            ).delete()
            db.session.commit()

            if blocks:
                logger.info(
                    "Restored %d active throttle blocks from database",
                    len(blocks),
                )

            # --- 2. Scan recent events for IPs already over threshold ------
            # This catches attackers whose blocks were lost before DB
            # persistence was in place (e.g. first deployment, or blocks
            # created by the old in-memory-only code).
            threshold = Config.THROTTLE_EVENT_THRESHOLD
            duration = Config.THROTTLE_BLOCK_SECONDS
            cutoff = now_naive - timedelta(seconds=duration)

            high_volume = (
                db.session.query(
                    Event.source_ip,
                    Event.protocol,
                    db.func.count(Event.id),
                )
                .filter(Event.timestamp >= cutoff)
                .group_by(Event.source_ip, Event.protocol)
                .having(db.func.count(Event.id) >= threshold)
                .all()
            )

            new_blocks = 0
            for ip, protocol, _count in high_volume:
                key = (ip, protocol)
                if key not in self._blocked_until:
                    self._blocked_until[key] = now_mono + duration
                    expires_at = now_naive + timedelta(seconds=duration)
                    db.session.add(
                        ThrottleBlock(
                            ip=ip, protocol=protocol, expires_at=expires_at
                        )
                    )
                    new_blocks += 1

            if new_blocks:
                db.session.commit()
                logger.info(
                    "Created %d throttle blocks from recent event history",
                    new_blocks,
                )

    def _persist_block(self, ip: str, protocol: str, duration: int) -> None:
        """Upsert a throttle block row in the database."""
        if self._app is None:
            return
        try:
            with self._app.app_context():
                from models import ThrottleBlock, db

                expires_at = datetime.utcnow() + timedelta(seconds=duration)
                existing = ThrottleBlock.query.filter_by(
                    ip=ip, protocol=protocol
                ).first()
                if existing:
                    existing.expires_at = expires_at
                else:
                    db.session.add(
                        ThrottleBlock(
                            ip=ip, protocol=protocol, expires_at=expires_at
                        )
                    )
                db.session.commit()
        except Exception:
            logger.debug(
                "Failed to persist throttle block for %s/%s",
                ip,
                protocol,
                exc_info=True,
            )

    def _remove_block(self, ip: str, protocol: str) -> None:
        """Delete an expired throttle block row from the database."""
        if self._app is None:
            return
        try:
            with self._app.app_context():
                from models import ThrottleBlock, db

                ThrottleBlock.query.filter_by(ip=ip, protocol=protocol).delete()
                db.session.commit()
        except Exception:
            logger.debug(
                "Failed to remove throttle block for %s/%s",
                ip,
                protocol,
                exc_info=True,
            )

    # -----------------------------------------------------------------
    # Event-based throttle
    # -----------------------------------------------------------------

    def record_event(self, ip: str, protocol: str) -> None:
        """Increment the event counter; trigger a block at the threshold."""
        key = (ip, protocol)
        persist = False
        duration = 0

        with self._lock:
            # If currently blocked, nothing to count
            if key in self._blocked_until:
                return

            count = self._counts.get(key, 0) + 1
            self._counts[key] = count

            if count >= Config.THROTTLE_EVENT_THRESHOLD:
                duration = Config.THROTTLE_BLOCK_SECONDS
                self._blocked_until[key] = time.monotonic() + duration
                self._counts.pop(key, None)
                persist = True
                logger.warning(
                    "Throttle triggered: %s on %s after %d events — "
                    "blocked for %ds",
                    ip, protocol, count, duration,
                )

        if persist:
            self._persist_block(ip, protocol, duration)

    def is_blocked(self, ip: str, protocol: str) -> bool:
        """Return True if the IP is currently blocked on this protocol."""
        key = (ip, protocol)
        expired = False

        with self._lock:
            expires = self._blocked_until.get(key)
            if expires is None:
                return False

            if time.monotonic() >= expires:
                # Block expired — clean up and grant a fresh budget
                del self._blocked_until[key]
                self._counts.pop(key, None)
                expired = True
                logger.info(
                    "Throttle expired: %s on %s — connections allowed again",
                    ip, protocol,
                )

        if expired:
            self._remove_block(ip, protocol)
            return False

        return True

    # -----------------------------------------------------------------
    # Concurrent connection limiting
    # -----------------------------------------------------------------

    def track_connect(self, ip: str, protocol: str) -> bool:
        """Register a new connection.  Returns True if allowed, False if
        the IP has reached MAX_CONNECTIONS_PER_IP and must be refused.

        When the limit is hit the IP is blocked on *protocol* for
        THROTTLE_BLOCK_SECONDS (same duration as the event throttle).
        """
        limit = Config.MAX_CONNECTIONS_PER_IP
        persist = False
        duration = 0
        allowed = True

        with self._lock:
            current = self._active.get(ip, 0)
            if current >= limit:
                # Trigger a time-based block on this protocol
                key = (ip, protocol)
                if key not in self._blocked_until:
                    duration = Config.THROTTLE_BLOCK_SECONDS
                    self._blocked_until[key] = time.monotonic() + duration
                    self._counts.pop(key, None)
                    persist = True
                    logger.warning(
                        "Connection limit reached: %s has %d active "
                        "connections — blocked %s for %ds",
                        ip, current, protocol, duration,
                    )
                allowed = False
            else:
                self._active[ip] = current + 1

        if persist:
            self._persist_block(ip, protocol, duration)

        return allowed

    def track_disconnect(self, ip: str) -> None:
        """Unregister a connection when it closes."""
        with self._lock:
            current = self._active.get(ip, 0)
            if current <= 1:
                self._active.pop(ip, None)
            else:
                self._active[ip] = current - 1

    # -----------------------------------------------------------------
    # Query
    # -----------------------------------------------------------------

    def get_all_blocked(self) -> list[dict]:
        """Return all currently active blocks (pruning any that have expired).

        Each entry: ``{"ip": str, "protocol": str, "expires_in": int}``
        where ``expires_in`` is seconds remaining.
        """
        now = time.monotonic()
        result: list[dict] = []
        expired_keys: list[tuple[str, str]] = []

        with self._lock:
            for key, expires in self._blocked_until.items():
                if now >= expires:
                    expired_keys.append(key)
                else:
                    ip, protocol = key
                    result.append({
                        "ip": ip,
                        "protocol": protocol,
                        "expires_in": int(expires - now),
                    })

            for key in expired_keys:
                del self._blocked_until[key]
                self._counts.pop(key, None)

        for ip, protocol in expired_keys:
            self._remove_block(ip, protocol)

        return result

    def get_active_connections(self) -> dict[str, int]:
        """Return a snapshot of active connection counts per IP."""
        with self._lock:
            return dict(self._active)
