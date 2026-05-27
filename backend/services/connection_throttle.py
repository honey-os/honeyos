"""
ConnectionThrottler -- per-IP, per-protocol event counting with automatic
time-based blocking.

After THROTTLE_EVENT_THRESHOLD events from a single IP on a single protocol,
new connections are blocked for THROTTLE_BLOCK_SECONDS.  When the block
expires the counter resets and the IP gets a fresh budget.
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
