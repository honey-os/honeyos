"""
URLhaus (abuse.ch) malware URL lookup service.

Searches session IOCs (URLs, IPs, domains, hashes) against URLhaus
to identify known malware distribution URLs.
"""

import logging
import re

import requests

from services.threatfox import (
    _FULL_URL_RE,
    _IP_PORT_RE,
    _IP_RE,
    _MD5_RE,
    _SHA256_RE,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"


def _classify_ioc(ioc: str) -> tuple[str, str]:
    """Classify an IOC and return (endpoint_path, form_data_key).

    Returns ("", "") if the IOC type is not supported by URLhaus.
    """
    if _FULL_URL_RE.fullmatch(ioc):
        return "/url/", "url"
    if _SHA256_RE.fullmatch(ioc):
        return "/payload/", "sha256_hash"
    if _MD5_RE.fullmatch(ioc):
        return "/payload/", "md5_hash"
    if _IP_PORT_RE.fullmatch(ioc):
        # Strip port — URLhaus host endpoint takes bare IP/domain
        ip = ioc.split(":")[0]
        return "/host/", ip  # special case: value is the IP, not the key name
    if _IP_RE.fullmatch(ioc):
        return "/host/", "host"
    # Check if it looks like a domain (not a hash, not an IP)
    if re.fullmatch(r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}", ioc):
        return "/host/", "host"
    return "", ""


class UrlhausService:
    """Query URLhaus for malware distribution URLs found in honeypot sessions."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def analyze_iocs(self, iocs: list[str]) -> list[dict]:
        """Search URLhaus for each IOC using the appropriate endpoint.

        Categorizes IOCs and routes to the correct endpoint:
        - Full URLs        -> POST /v1/url/     (form: url=<value>)
        - Bare IPs/domains -> POST /v1/host/    (form: host=<value>)
        - ip:port pairs    -> POST /v1/host/    (form: host=<ip part>)
        - SHA256 hashes    -> POST /v1/payload/ (form: sha256_hash=<value>)
        - MD5 hashes       -> POST /v1/payload/ (form: md5_hash=<value>)
        """
        all_matches: list[dict] = []
        searched_hosts: set[str] = set()

        for ioc in iocs:
            endpoint, form_key = _classify_ioc(ioc)
            if not endpoint:
                continue

            # Build the form data
            if endpoint == "/host/":
                if form_key != "host":
                    # ip:port case — form_key is actually the bare IP
                    host_value = form_key
                    form_key = "host"
                else:
                    host_value = ioc

                # Deduplicate host lookups
                if host_value in searched_hosts:
                    continue
                searched_hosts.add(host_value)

                form_data = {"host": host_value}
            elif endpoint == "/url/":
                form_data = {"url": ioc}
            else:
                # Payload endpoint
                form_data = {form_key: ioc}

            matches = self._query(endpoint, form_data, ioc)
            all_matches.extend(matches)

        return all_matches

    def _query(self, endpoint: str, form_data: dict, original_ioc: str) -> list[dict]:
        """Execute a single URLhaus API query and normalize results."""
        url = f"{_BASE_URL}{endpoint}"
        headers = {"Auth-Key": self.api_key} if self.api_key else {}

        try:
            resp = requests.post(url, data=form_data, headers=headers, timeout=15)
        except requests.RequestException:
            logger.warning("URLhaus request failed for %s (%s)", original_ioc, endpoint)
            return []

        if resp.status_code != 200:
            logger.warning("URLhaus returned status %d for %s", resp.status_code, original_ioc)
            return []

        data = resp.json()
        query_status = data.get("query_status", "unknown")

        if query_status in ("no_results", "no_result"):
            return []
        if query_status not in ("ok", "is_host"):
            logger.info("URLhaus query_status=%s for %s", query_status, original_ioc)
            return []

        if endpoint == "/url/":
            return self._parse_url_response(data, original_ioc)
        elif endpoint == "/host/":
            return self._parse_host_response(data, original_ioc)
        else:
            return self._parse_payload_response(data, original_ioc)

    def _parse_url_response(self, data: dict, ioc: str) -> list[dict]:
        """Parse a single URL record from URLhaus."""
        threat = data.get("threat") or ""
        tags = data.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        # Try to get malware name from payloads
        malware = ""
        payloads = data.get("payloads") or []
        if isinstance(payloads, list):
            for p in payloads:
                sig = p.get("signature")
                if sig and sig != "null":
                    malware = sig
                    break
        if not malware and tags:
            malware = tags[0]

        return [{
            "ioc": ioc,
            "threat_type": threat or "malware_download",
            "malware": malware,
            "confidence_level": 0,
            "first_seen": data.get("date_added", ""),
            "tags": tags,
            "reference": data.get("urlhaus_reference"),
            "source": "urlhaus",
        }]

    def _parse_host_response(self, data: dict, ioc: str) -> list[dict]:
        """Parse host response — one match per malicious URL found for the host."""
        urls = data.get("urls") or []
        if not isinstance(urls, list):
            return []

        matches = []
        for url_entry in urls:
            threat = url_entry.get("threat") or ""
            tags = url_entry.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            malware = ""
            if tags:
                malware = tags[0]

            matches.append({
                "ioc": url_entry.get("url", ioc),
                "threat_type": threat or "malware_download",
                "malware": malware,
                "confidence_level": 0,
                "first_seen": url_entry.get("date_added", ""),
                "tags": tags,
                "reference": url_entry.get("urlhaus_reference"),
                "source": "urlhaus",
            })

        return matches

    def _parse_payload_response(self, data: dict, ioc: str) -> list[dict]:
        """Parse payload response from URLhaus."""
        signature = data.get("signature") or ""
        urls = data.get("urls") or []
        first_seen = data.get("firstseen", "")

        tags: list[str] = []
        if signature:
            tags = [signature]

        # Build a reference from the first associated URL if available
        reference = None
        if isinstance(urls, list) and urls:
            reference = urls[0].get("urlhaus_reference")

        return [{
            "ioc": ioc,
            "threat_type": "payload",
            "malware": signature,
            "confidence_level": 0,
            "first_seen": first_seen,
            "tags": tags,
            "reference": reference,
            "source": "urlhaus",
        }]
