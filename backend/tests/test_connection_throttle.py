"""Tests for backend/services/connection_throttle.py"""

import time
from unittest.mock import patch

from services.connection_throttle import ConnectionThrottler


class TestRecordEvent:
    def test_counts_events(self):
        throttler = ConnectionThrottler()
        for _ in range(3):
            throttler.record_event("10.0.0.1", "ssh")
        assert throttler._counts.get(("10.0.0.1", "ssh")) == 3

    @patch("services.connection_throttle.Config")
    def test_triggers_block_at_threshold(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 3
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()

        for _ in range(3):
            throttler.record_event("10.0.0.1", "ssh")

        assert throttler.is_blocked("10.0.0.1", "ssh") is True
        # Counter should be cleared after block
        assert ("10.0.0.1", "ssh") not in throttler._counts

    @patch("services.connection_throttle.Config")
    def test_no_block_below_threshold(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 10
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()

        for _ in range(5):
            throttler.record_event("10.0.0.1", "ssh")

        assert throttler.is_blocked("10.0.0.1", "ssh") is False

    @patch("services.connection_throttle.Config")
    def test_ignores_events_when_already_blocked(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 3
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()

        # Trigger block
        for _ in range(3):
            throttler.record_event("10.0.0.1", "ssh")

        # Additional events should not increment
        throttler.record_event("10.0.0.1", "ssh")
        assert ("10.0.0.1", "ssh") not in throttler._counts


class TestIsBlocked:
    def test_unblocked_ip(self):
        throttler = ConnectionThrottler()
        assert throttler.is_blocked("10.0.0.1", "ssh") is False

    @patch("services.connection_throttle.Config")
    def test_block_expires(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 1
        mock_config.THROTTLE_BLOCK_SECONDS = 0  # immediate expiry
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()
        throttler.record_event("10.0.0.1", "ssh")

        # Block should expire immediately (monotonic time has passed)
        time.sleep(0.01)
        assert throttler.is_blocked("10.0.0.1", "ssh") is False


class TestTrackConnect:
    @patch("services.connection_throttle.Config")
    def test_allows_connection_below_limit(self, mock_config):
        mock_config.MAX_CONNECTIONS_PER_IP = 5
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()
        assert throttler.track_connect("10.0.0.1", "ssh") is True
        assert throttler._active.get("10.0.0.1") == 1

    @patch("services.connection_throttle.Config")
    def test_blocks_at_connection_limit(self, mock_config):
        mock_config.MAX_CONNECTIONS_PER_IP = 2
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()

        assert throttler.track_connect("10.0.0.1", "ssh") is True
        assert throttler.track_connect("10.0.0.1", "ssh") is True
        # Third connection exceeds limit
        assert throttler.track_connect("10.0.0.1", "ssh") is False
        assert throttler.is_blocked("10.0.0.1", "ssh") is True


class TestTrackDisconnect:
    def test_decrements_active_count(self):
        throttler = ConnectionThrottler()
        # Use track_connect so the semaphore stays in sync
        throttler.track_connect("10.0.0.1", "ssh")
        throttler.track_connect("10.0.0.1", "ssh")
        throttler.track_connect("10.0.0.1", "ssh")
        assert throttler._active["10.0.0.1"] == 3
        throttler.track_disconnect("10.0.0.1")
        assert throttler._active["10.0.0.1"] == 2

    def test_removes_entry_at_zero(self):
        throttler = ConnectionThrottler()
        throttler.track_connect("10.0.0.1", "ssh")
        assert throttler._active["10.0.0.1"] == 1
        throttler.track_disconnect("10.0.0.1")
        assert "10.0.0.1" not in throttler._active

    def test_noop_for_unknown_ip(self):
        throttler = ConnectionThrottler()
        throttler.track_disconnect("10.0.0.1")  # should not raise


class TestGlobalConnectionLimit:
    @patch("services.connection_throttle.Config")
    def test_refuses_above_global_limit(self, mock_config):
        mock_config.MAX_CONNECTIONS_PER_IP = 100
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 3
        throttler = ConnectionThrottler()

        assert throttler.track_connect("10.0.0.1", "ssh") is True
        assert throttler.track_connect("10.0.0.2", "ssh") is True
        assert throttler.track_connect("10.0.0.3", "ssh") is True
        # 4th connection exceeds global limit
        assert throttler.track_connect("10.0.0.4", "ssh") is False

    @patch("services.connection_throttle.Config")
    def test_allows_after_disconnect(self, mock_config):
        mock_config.MAX_CONNECTIONS_PER_IP = 100
        mock_config.THROTTLE_BLOCK_SECONDS = 60
        mock_config.MAX_TOTAL_CONNECTIONS = 2
        throttler = ConnectionThrottler()

        assert throttler.track_connect("10.0.0.1", "ssh") is True
        assert throttler.track_connect("10.0.0.2", "ssh") is True
        assert throttler.track_connect("10.0.0.3", "ssh") is False
        # Disconnect one — slot opens up
        throttler.track_disconnect("10.0.0.1")
        assert throttler.track_connect("10.0.0.3", "ssh") is True


class TestGetAllBlocked:
    @patch("services.connection_throttle.Config")
    def test_returns_active_blocks(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 1
        mock_config.THROTTLE_BLOCK_SECONDS = 3600
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()
        throttler.record_event("10.0.0.1", "ssh")

        blocked = throttler.get_all_blocked()
        assert len(blocked) == 1
        assert blocked[0]["ip"] == "10.0.0.1"
        assert blocked[0]["protocol"] == "ssh"
        assert blocked[0]["expires_in"] > 0

    def test_empty_when_no_blocks(self):
        throttler = ConnectionThrottler()
        assert throttler.get_all_blocked() == []

    @patch("services.connection_throttle.Config")
    def test_prunes_expired_blocks(self, mock_config):
        mock_config.THROTTLE_EVENT_THRESHOLD = 1
        mock_config.THROTTLE_BLOCK_SECONDS = 0
        mock_config.MAX_TOTAL_CONNECTIONS = 200
        throttler = ConnectionThrottler()
        throttler.record_event("10.0.0.1", "ssh")
        time.sleep(0.01)

        blocked = throttler.get_all_blocked()
        assert len(blocked) == 0


class TestGetActiveConnections:
    def test_returns_snapshot(self):
        throttler = ConnectionThrottler()
        throttler._active["10.0.0.1"] = 5
        throttler._active["10.0.0.2"] = 2
        result = throttler.get_active_connections()
        assert result == {"10.0.0.1": 5, "10.0.0.2": 2}
