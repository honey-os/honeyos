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
"""

import logging
import threading
import time

from config import Config

logger = logging.getLogger(__name__)


class ConnectionThrottler:
    """Thread-safe in-memory connection throttler."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (ip, protocol) -> event count
        self._counts: dict[tuple[str, str], int] = {}
        # (ip, protocol) -> monotonic timestamp when the block expires
        self._blocked_until: dict[tuple[str, str], float] = {}
        # ip -> number of active (in-flight) connections
        self._active: dict[str, int] = {}

    # -----------------------------------------------------------------
    # Event-based throttle
    # -----------------------------------------------------------------

    def record_event(self, ip: str, protocol: str) -> None:
        """Increment the event counter; trigger a block at the threshold."""
        key = (ip, protocol)
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
                logger.warning(
                    "Throttle triggered: %s on %s after %d events — "
                    "blocked for %ds",
                    ip, protocol, count, duration,
                )

    def is_blocked(self, ip: str, protocol: str) -> bool:
        """Return True if the IP is currently blocked on this protocol."""
        key = (ip, protocol)
        with self._lock:
            expires = self._blocked_until.get(key)
            if expires is None:
                return False

            if time.monotonic() >= expires:
                # Block expired — clean up and grant a fresh budget
                del self._blocked_until[key]
                self._counts.pop(key, None)
                logger.info(
                    "Throttle expired: %s on %s — connections allowed again",
                    ip, protocol,
                )
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
        with self._lock:
            current = self._active.get(ip, 0)
            if current >= limit:
                # Trigger a time-based block on this protocol
                key = (ip, protocol)
                if key not in self._blocked_until:
                    duration = Config.THROTTLE_BLOCK_SECONDS
                    self._blocked_until[key] = time.monotonic() + duration
                    self._counts.pop(key, None)
                    logger.warning(
                        "Connection limit reached: %s has %d active "
                        "connections — blocked %s for %ds",
                        ip, current, protocol, duration,
                    )
                return False

            self._active[ip] = current + 1
            return True

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

        return result

    def get_active_connections(self) -> dict[str, int]:
        """Return a snapshot of active connection counts per IP."""
        with self._lock:
            return dict(self._active)
