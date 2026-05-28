"""
PerimeterService -- public IP detection, Censys passive lookup,
declared-port drift analysis, and banner comparison.
"""

import json
import logging

import requests

from config import Config
from utils.helpers import generate_id

logger = logging.getLogger(__name__)


class PerimeterService:
    """Perimeter drift detection and Censys exposure analysis."""

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
            active: set[tuple[int, str]] = set()

            _UDP_PROTOCOLS = {"dns"}

            for hp in honeypots:
                external_port = Config.EXTERNAL_PORT.get(hp.protocol, hp.port)
                transport = "udp" if hp.protocol in _UDP_PROTOCOLS else "tcp"
                active.add((external_port, transport))
                existing = DeclaredPort.query.filter_by(
                    port=external_port, transport=transport
                ).first()
                if existing:
                    if existing.source == "honeypot":
                        existing.label = hp.name
                else:
                    db.session.add(DeclaredPort(
                        port=external_port,
                        transport=transport,
                        label=hp.name,
                        source="honeypot",
                    ))

            # Declare the frontend/dashboard port
            frontend_port = Config.FRONTEND_PORT
            if frontend_port:
                active.add((frontend_port, "tcp"))
                existing = DeclaredPort.query.filter_by(
                    port=frontend_port, transport="tcp"
                ).first()
                if existing:
                    if existing.source == "system":
                        existing.label = "HoneyOS Dashboard"
                else:
                    db.session.add(DeclaredPort(
                        port=frontend_port,
                        transport="tcp",
                        label="HoneyOS Dashboard",
                        source="system",
                    ))

            # Remove auto-sourced rows whose (port, transport) is no longer active
            for row in DeclaredPort.query.filter(
                DeclaredPort.source.in_(["honeypot", "system"])
            ).all():
                if (row.port, row.transport) not in active:
                    db.session.delete(row)

            db.session.commit()
            logger.info("Synced declared ports from %d enabled honeypots", len(honeypots))

    # -----------------------------------------------------------------
    # Censys lookup
    # -----------------------------------------------------------------

    def lookup_censys(self, ip: str):
        """Query the Censys Platform API v3 and persist a CensysSnapshot."""
        from models import CensysSnapshot, db

        api_token = Config.CENSYS_API_TOKEN
        if not api_token:
            logger.warning("lookup_censys: CENSYS_API_TOKEN is empty, skipping")
            return None

        url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
        logger.info("Censys: querying %s", url)

        try:
            resp = requests.get(
                url,
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=15,
            )
            logger.info("Censys: response status %d for %s", resp.status_code, ip)
            if resp.status_code == 404:
                logger.info("Censys: no data for %s", ip)
                return None
            if resp.status_code in (401, 403):
                logger.warning("Censys: auth failed (%d) for %s", resp.status_code, ip)
                raise PermissionError(
                    f"Censys API returned {resp.status_code}: token is invalid or lacks permissions"
                )
            if resp.status_code == 429:
                logger.warning("Censys: rate limited for %s", ip)
                raise PermissionError(
                    "Censys API rate limit exceeded"
                )
            resp.raise_for_status()
            data = resp.json()
        except PermissionError:
            raise
        except Exception:
            logger.error("Censys lookup failed for %s", ip, exc_info=True)
            return None

        # v3 nests host data under result.resource
        resource = data.get("result", {}).get("resource", {})

        services = resource.get("services", [])

        ports_data = []
        for svc in services:
            # Extract product from software array
            product = ""
            for sw in svc.get("software", []):
                if isinstance(sw, dict) and sw.get("product"):
                    product = sw["product"]
                    # Capitalise and clean underscores
                    product = product.replace("_", " ").title()
                    break

            # Extract version and banner from protocol-specific sub-objects
            banner = ""
            version = ""
            proto_key = svc.get("protocol", "").lower()
            if proto_key == "ssh" and "ssh" in svc:
                ssh = svc["ssh"]
                eid = ssh.get("endpoint_id", {})
                banner = eid.get("raw", "")
                version = eid.get("software_version", "")
            elif proto_key in ("http", "https") and "http" in svc:
                resp = svc["http"].get("response", {})
                headers = resp.get("headers", {})
                server = headers.get("Server") or headers.get("server")
                if isinstance(server, list):
                    banner = server[0] if server else ""
                elif isinstance(server, str):
                    banner = server
                if not banner:
                    banner = resp.get("status_line", "")
                # Try X-Powered-By for version
                powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
                if powered:
                    version = powered[0] if isinstance(powered, list) else powered
            elif proto_key == "ftp" and "ftp" in svc:
                ftp = svc["ftp"]
                banner = ftp.get("status_meaning", "") or ftp.get("banner", "")
            elif proto_key == "mysql" and "mysql" in svc:
                mysql = svc["mysql"]
                version = mysql.get("server_version", "")
                banner = version
            elif proto_key == "dns" and "dns" in svc:
                dns_data = svc["dns"]
                version = dns_data.get("version", "")
                banner = version
            elif proto_key == "smb" and "smb" in svc:
                smb = svc["smb"]
                version = smb.get("version", "")

            ports_data.append({
                "port": svc.get("port"),
                "transport": (svc.get("transport_protocol") or "tcp").lower(),
                "service": svc.get("protocol", ""),
                "product": product,
                "version": version,
                "banner": (banner or "")[:2000],
            })

        raw_labels = resource.get("labels", [])
        labels = [
            lbl["value"] if isinstance(lbl, dict) else lbl
            for lbl in raw_labels
        ]
        honeypot_flagged = any(
            lbl.lower() == "honeypot" for lbl in labels
        )

        autonomous_system = resource.get("autonomous_system", {})
        operating_system = resource.get("operating_system", {})
        dns = resource.get("dns", {})
        reverse_dns = dns.get("reverse_dns", {})
        hostnames = reverse_dns.get("names", [])

        logger.info("Censys: found %d services, %d labels for %s",
                     len(ports_data), len(labels), ip)

        # Keep only latest snapshot per IP
        CensysSnapshot.query.filter_by(ip=ip).delete()

        snapshot = CensysSnapshot(
            id=generate_id(),
            ip=ip,
            ports_data=json.dumps(ports_data),
            tags=json.dumps(labels),
            honeypot_flagged=honeypot_flagged,
            vulns=json.dumps([]),
            hostnames=json.dumps(hostnames),
            org=autonomous_system.get("name"),
            isp=autonomous_system.get("description"),
            os_name=operating_system.get("product"),
            censys_updated=resource.get("last_updated_at")
                or max((s.get("scan_time", "") for s in services), default=None),
        )
        db.session.add(snapshot)
        db.session.commit()
        return snapshot

    # -----------------------------------------------------------------
    # Drift check
    # -----------------------------------------------------------------

    def run_drift_check(self):
        """Compare declared ports against what Censys sees externally."""
        from models import DeclaredPort, PerimeterScan, CensysSnapshot, db

        ip = self.detect_public_ip()
        if not ip:
            logger.warning("Drift check: could not detect public IP")
            return None

        logger.info("Drift check: starting for IP %s", ip)
        censys_status = "not_configured"

        # Always fetch fresh Censys data
        with self._app.app_context():
            snapshot = None

            if not Config.CENSYS_API_TOKEN:
                logger.warning("Drift check: CENSYS_API_TOKEN not configured, skipping lookup")
                censys_status = "not_configured"
            else:
                logger.info("Drift check: querying Censys for %s", ip)
                try:
                    snapshot = self.lookup_censys(ip)
                    if snapshot:
                        censys_status = "ok"
                        logger.info("Drift check: Censys lookup succeeded for %s", ip)
                    else:
                        censys_status = "no_data"
                        logger.warning("Drift check: Censys returned no data for %s", ip)
                except PermissionError as exc:
                    censys_status = "auth_error"
                    logger.warning("Drift check: Censys auth failed: %s", exc)
                    snapshot = None

            # Declared ports
            declared = DeclaredPort.query.all()
            declared_set = {(d.port, d.transport) for d in declared}
            declared_snapshot = [d.to_dict() for d in declared]

            # Actual ports from Censys
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

            logger.info("Drift check: %d declared, %d actual, %d unexpected, %d missing, censys_status=%s",
                        len(declared), len(actual_ports), len(unexpected), len(missing), censys_status)

            scan = PerimeterScan(
                id=generate_id(),
                public_ip=ip,
                scan_source="censys" if snapshot else "none",
                declared_snapshot=json.dumps(declared_snapshot),
                actual_ports=json.dumps(sorted(set(actual_ports))),
                unexpected_ports=json.dumps(sorted(unexpected)),
                missing_ports=json.dumps(sorted(missing)),
                drift_detected=drift_detected,
            )
            db.session.add(scan)
            db.session.commit()

            result = scan.to_dict()
            result["censys_status"] = censys_status
            return result

    # -----------------------------------------------------------------
    # Banner comparison
    # -----------------------------------------------------------------

    def get_banner_comparison(self) -> list[dict]:
        """Compare configured honeypot banners against Censys-captured banners."""
        from models import Honeypot, CensysSnapshot

        ip = self.detect_public_ip()
        if not ip:
            return []

        snapshot = CensysSnapshot.query.filter_by(ip=ip).first()
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

            censys_banner = p.get("banner", "")
            match = False
            if configured_banner and censys_banner:
                match = configured_banner in censys_banner

            results.append({
                "port": port_num,
                "protocol": hp.protocol,
                "configured_banner": configured_banner,
                "censys_banner": censys_banner[:500] if censys_banner else None,
                "match": match,
            })

        return results
