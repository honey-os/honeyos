"""
NetworkScanner -- TCP port scanning and change detection.
"""

import json
import logging
import socket
import time
from datetime import datetime, timezone

from models import NetworkScan, db
from utils.helpers import generate_id, parse_json_field

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Simple TCP connect scanner suitable for Raspberry-Pi-class hardware."""

    DEFAULT_TIMEOUT = 0.5  # seconds per port

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_ports(
        self,
        target_host: str,
        port_range: tuple[int, int] = (1, 1024),
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict:
        """
        Scan *target_host* for open TCP ports in *port_range*.

        Returns a dict with ``open_ports``, ``scan_duration_ms``, and
        ``target_host``.
        """
        start = time.monotonic()
        open_ports: list[int] = []

        for port in range(port_range[0], port_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    result = s.connect_ex((target_host, port))
                    if result == 0:
                        open_ports.append(port)
            except (socket.error, OSError):
                continue

        elapsed_ms = int((time.monotonic() - start) * 1000)

        logger.info(
            "Scan of %s (%d-%d) completed in %d ms -- %d open ports",
            target_host,
            port_range[0],
            port_range[1],
            elapsed_ms,
            len(open_ports),
        )

        return {
            "target_host": target_host,
            "open_ports": open_ports,
            "scan_duration_ms": elapsed_ms,
        }

    # ------------------------------------------------------------------
    # Change detection
    # ------------------------------------------------------------------

    def detect_changes(self, current_ports: list[int], previous_ports: list[int]) -> dict:
        """
        Compare two lists of open ports and report new / closed ports.
        """
        current_set = set(current_ports)
        previous_set = set(previous_ports)

        return {
            "new_ports": sorted(current_set - previous_set),
            "closed_ports": sorted(previous_set - current_set),
            "unchanged_ports": sorted(current_set & previous_set),
            "changes_detected": current_set != previous_set,
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save_scan_result(self, scan_data: dict) -> NetworkScan:
        """
        Persist a scan result.  Automatically links to the most recent
        previous scan for the same host and performs change detection.
        """
        target = scan_data["target_host"]

        # Find previous scan for this host
        previous = (
            NetworkScan.query.filter_by(target_host=target)
            .order_by(NetworkScan.timestamp.desc())
            .first()
        )

        previous_ports: list[int] = []
        previous_id = None
        changes_detected = False

        if previous:
            previous_ports = parse_json_field(previous.discovered_ports) or []
            previous_id = previous.id
            changes = self.detect_changes(scan_data["open_ports"], previous_ports)
            changes_detected = changes["changes_detected"]

        scan = NetworkScan(
            id=generate_id(),
            target_host=target,
            scan_type=scan_data.get("scan_type", "tcp"),
            discovered_ports=json.dumps(scan_data["open_ports"]),
            scan_duration_ms=scan_data.get("scan_duration_ms", 0),
            timestamp=datetime.now(timezone.utc),
            changes_detected=changes_detected,
            previous_scan_id=previous_id,
        )
        db.session.add(scan)
        db.session.commit()
        return scan
