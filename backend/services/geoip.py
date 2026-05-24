"""
GeoIP lookup service using ip-api.com (free, no API key required).

Caches results in the ``ip_geo_cache`` table to avoid redundant lookups.
"""

import ipaddress
import logging
from datetime import datetime, timezone

import requests

from models import IPGeoCache, db

logger = logging.getLogger(__name__)

_IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as"


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a private/reserved address."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


class GeoIPService:
    """Look up geographic information for IP addresses."""

    def lookup(self, ip: str) -> dict | None:
        """Return geo dict for *ip*, or ``None`` for private/failed lookups.

        Results are cached permanently in the database.
        """
        if _is_private(ip):
            return None

        # Check cache first
        cached = db.session.get(IPGeoCache, ip)
        if cached is not None:
            return cached.to_dict()

        # Query ip-api.com
        try:
            resp = requests.get(
                _IP_API_URL.format(ip=ip),
                timeout=5,
            )
        except requests.RequestException:
            logger.warning("GeoIP request failed for %s", ip)
            return None

        if resp.status_code == 429:
            logger.warning("GeoIP rate-limited, skipping %s", ip)
            return None

        if resp.status_code != 200:
            logger.warning("GeoIP unexpected status %d for %s", resp.status_code, ip)
            return None

        data = resp.json()
        if data.get("status") != "success":
            logger.debug("GeoIP lookup failed for %s: %s", ip, data.get("message"))
            return None

        result = {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
        }

        # Persist to cache
        entry = IPGeoCache(
            ip=ip,
            country=result["country"],
            country_code=result["country_code"],
            region=result["region"],
            city=result["city"],
            lat=result["lat"],
            lon=result["lon"],
            isp=result["isp"],
            org=result["org"],
            asn=result["asn"],
            looked_up_at=datetime.now(timezone.utc),
        )
        db.session.merge(entry)
        db.session.commit()

        return result
