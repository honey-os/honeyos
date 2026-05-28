"""
PerimeterService -- public IP detection, Shodan passive lookup,
declared-port drift analysis, and banner comparison.
"""

import json
import logging

import requests

from config import Config
from utils.helpers import generate_id

logger = logging.getLogger(__name__)


class PerimeterService:
    """Perimeter drift detection and Shodan exposure analysis."""

    def __init__(self, app=None) -> None:
        self._app = app
        self._cached_ip: str | None = None

    # -----------------------------------------------------------------
    # Public IP detection
    # -----------------------------------------------------------------

    def detect_public_ip(self) -> str | None:
        """Return the public IP, using the configured override or ipify."""
        if Config.PUBLIC_IP:
            return Config.PUBLIC_IP
        if self._cached_ip:
            return self._cached_ip
        try:
            resp = requests.get(
                "https://api.ipify.org?format=json", timeout=5
            )
            resp.raise_for_status()
            self._cached_ip = resp.json().get("ip")
            return self._cached_ip
        except Exception:
            logger.warning("Failed to detect public IP", exc_info=True)
            return None

    # -----------------------------------------------------------------
    # Honeypot port sync
    # -----------------------------------------------------------------

    def sync_honeypot_ports(self) -> None:
        """Upsert DeclaredPort rows from enabled Honeypot entries and remove
        stale honeypot-sourced declarations."""
        with self._app.app_context():
            from models import DeclaredPort, Honeypot, db

            honeypots = Honeypot.query.filter_by(enabled=True).all()
            active_ports: set[int] = set()

            for hp in honeypots:
                external_port = Config.EXTERNAL_PORT.get(hp.protocol, hp.port)
                active_ports.add(external_port)
                existing = DeclaredPort.query.filter_by(
                    port=external_port, transport="tcp"
                ).first()
                if existing:
                    if existing.source == "honeypot":
                        existing.label = hp.name
                else:
                    db.session.add(DeclaredPort(
                        port=external_port,
                        transport="tcp",
                        label=hp.name,
                        source="honeypot",
                    ))

            # Remove honeypot-sourced rows whose port is no longer active
            stale = DeclaredPort.query.filter(
                DeclaredPort.source == "honeypot",
                ~DeclaredPort.port.in_(active_ports) if active_ports else True,
            ).all()
            for row in stale:
                db.session.delete(row)

            db.session.commit()
            logger.info("Synced declared ports from %d enabled honeypots", len(honeypots))

    # -----------------------------------------------------------------
    # Shodan lookup
    # -----------------------------------------------------------------

    def lookup_shodan(self, ip: str):
        """Query the Shodan host API and persist a ShodanSnapshot."""
        from models import ShodanSnapshot, db

        api_key = Config.SHODAN_API_KEY
        if not api_key:
            return None

        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": api_key},
                timeout=15,
            )
            if resp.status_code == 404:
                logger.info("Shodan: no data for %s", ip)
                return None
            if resp.status_code == 403:
                raise PermissionError(
                    "Shodan API key is invalid, expired, or rate-limited"
                )
            resp.raise_for_status()
            data = resp.json()
        except PermissionError:
            raise
        except Exception:
            logger.warning("Shodan lookup failed for %s", ip, exc_info=True)
            return None

        ports_data = []
        for entry in data.get("data", []):
            ports_data.append({
                "port": entry.get("port"),
                "transport": entry.get("transport", "tcp"),
                "service": entry.get("_shodan", {}).get("module", ""),
                "product": entry.get("product", ""),
                "version": entry.get("version", ""),
                "banner": (entry.get("data", "") or "")[:2000],
            })

        tags = data.get("tags", [])
        honeypot_flagged = "honeypot" in tags

        # Keep only latest snapshot per IP
        ShodanSnapshot.query.filter_by(ip=ip).delete()

        snapshot = ShodanSnapshot(
            id=generate_id(),
            ip=ip,
            ports_data=json.dumps(ports_data),
            tags=json.dumps(tags),
            honeypot_flagged=honeypot_flagged,
            vulns=json.dumps(list(data.get("vulns", []))),
            hostnames=json.dumps(data.get("hostnames", [])),
            org=data.get("org"),
            isp=data.get("isp"),
            os_name=data.get("os"),
            shodan_updated=data.get("last_update"),
        )
        db.session.add(snapshot)
        db.session.commit()
        return snapshot

    # -----------------------------------------------------------------
    # Drift check
    # -----------------------------------------------------------------

    def run_drift_check(self):
        """Compare declared ports against what Shodan sees externally."""
        from models import DeclaredPort, PerimeterScan, ShodanSnapshot, db

        ip = self.detect_public_ip()
        if not ip:
            return None

        # Get or refresh Shodan snapshot
        with self._app.app_context():
            snapshot = ShodanSnapshot.query.filter_by(ip=ip).first()
            if not snapshot and Config.SHODAN_API_KEY:
                try:
                    snapshot = self.lookup_shodan(ip)
                except PermissionError:
                    logger.warning("Shodan API key rejected; continuing drift check without Shodan data")
                    snapshot = None

            # Declared ports
            declared = DeclaredPort.query.all()
            declared_set = {(d.port, d.transport) for d in declared}
            declared_snapshot = [d.to_dict() for d in declared]

            # Actual ports from Shodan
            actual_ports: list[int] = []
            actual_set: set[tuple[int, str]] = set()
            if snapshot:
                ports_data = json.loads(snapshot.ports_data) if isinstance(snapshot.ports_data, str) else (snapshot.ports_data or [])
                for p in ports_data:
                    port_num = p.get("port")
                    transport = p.get("transport", "tcp")
                    if port_num is not None:
                        actual_ports.append(port_num)
                        actual_set.add((port_num, transport))

            unexpected = [p for p, t in actual_set if (p, t) not in declared_set]
            missing = [p for p, t in declared_set if (p, t) not in actual_set]
            drift_detected = len(unexpected) > 0 or len(missing) > 0

            scan = PerimeterScan(
                id=generate_id(),
                public_ip=ip,
                scan_source="shodan" if snapshot else "none",
                declared_snapshot=json.dumps(declared_snapshot),
                actual_ports=json.dumps(sorted(set(actual_ports))),
                unexpected_ports=json.dumps(sorted(unexpected)),
                missing_ports=json.dumps(sorted(missing)),
                drift_detected=drift_detected,
            )
            db.session.add(scan)
            db.session.commit()
            return scan.to_dict()

    # -----------------------------------------------------------------
    # Banner comparison
    # -----------------------------------------------------------------

    def get_banner_comparison(self) -> list[dict]:
        """Compare configured honeypot banners against Shodan-captured banners."""
        from models import Honeypot, ShodanSnapshot

        ip = self.detect_public_ip()
        if not ip:
            return []

        with self._app.app_context():
            snapshot = ShodanSnapshot.query.filter_by(ip=ip).first()
            if not snapshot:
                return []

            ports_data = json.loads(snapshot.ports_data) if isinstance(snapshot.ports_data, str) else (snapshot.ports_data or [])
            honeypots_by_ext: dict[int, Honeypot] = {}
            for hp in Honeypot.query.filter_by(enabled=True).all():
                ext = Config.EXTERNAL_PORT.get(hp.protocol, hp.port)
                honeypots_by_ext[ext] = hp

            results = []
            for p in ports_data:
                port_num = p.get("port")
                hp = honeypots_by_ext.get(port_num)
                if not hp:
                    continue

                # Extract configured banner from honeypot config
                config = json.loads(hp.config) if isinstance(hp.config, str) else (hp.config or {})
                configured_banner = (
                    config.get("banner")
                    or config.get("server_header")
                    or config.get("version_string")
                )

                shodan_banner = p.get("banner", "")
                match = False
                if configured_banner and shodan_banner:
                    match = configured_banner in shodan_banner

                results.append({
                    "port": port_num,
                    "protocol": hp.protocol,
                    "configured_banner": configured_banner,
                    "shodan_banner": shodan_banner[:500] if shodan_banner else None,
                    "match": match,
                })

            return results
