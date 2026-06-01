"""
URLhaus (abuse.ch) malware URL lookup service.

Searches session IOCs (URLs, hashes) against URLhaus to identify
known malware distribution URLs.
"""

import logging

import requests

from services.threatfox import (
    _FULL_URL_RE,
    _MD5_RE,
    _SHA256_RE,
)

logger = logging.getLogger(__name__)

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"

# Tags that describe architecture/format rather than malware families.
# Used to skip past them when selecting a malware name from the tags list.
_NON_MALWARE_TAGS = frozenset({
    "32-bit", "64-bit", "arm", "arm5", "arm6", "arm7",
    "mips", "mipsel", "x86", "x86_64", "aarch64",
    "elf", "exe", "dll", "doc", "apk", "jar",
    "js", "vbs", "ps1", "bat", "sh", "py", "php",
})


def _malware_from_tags(tags: list[str]) -> str:
    """Return the first tag that looks like a malware family name."""
    for tag in tags:
        if tag.lower() not in _NON_MALWARE_TAGS:
            return tag
    return tags[0] if tags else ""


def _classify_ioc(ioc: str) -> tuple[str, str]:
    """Classify an IOC and return (endpoint_path, form_data_key).

    Returns ("", "") if the IOC type is not supported by URLhaus.

    Only full URLs, hashes, and payloads are queried.  Bare IPs and
    domains are *not* sent to the /host/ endpoint because that returns
    every malicious URL ever seen on that host — far too noisy for a
    per-session check.  ThreatFox handles bare-IP/domain lookups instead.
    """
    if _FULL_URL_RE.fullmatch(ioc):
        return "/url/", "url"
    if _SHA256_RE.fullmatch(ioc):
        return "/payload/", "sha256_hash"
    if _MD5_RE.fullmatch(ioc):
        return "/payload/", "md5_hash"
    return "", ""


class UrlhausService:
    """Query URLhaus for malware distribution URLs found in honeypot sessions."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def analyze_iocs(self, iocs: list[str]) -> list[dict]:
        """Search URLhaus for each IOC using the appropriate endpoint.

        Only precise lookups are performed:
        - Full URLs    -> POST /v1/url/     (form: url=<value>)
        - SHA256 hashes -> POST /v1/payload/ (form: sha256_hash=<value>)
        - MD5 hashes   -> POST /v1/payload/ (form: md5_hash=<value>)

        Bare IPs/domains are skipped — the /host/ endpoint returns every
        URL ever seen on that host, which is too noisy for session-level
        analysis.  ThreatFox handles those IOC types instead.
        """
        all_matches: list[dict] = []

        for ioc in iocs:
            endpoint, form_key = _classify_ioc(ioc)
            if not endpoint:
                continue

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
        if query_status not in ("ok",):
            logger.info("URLhaus query_status=%s for %s", query_status, original_ioc)
            return []

        if endpoint == "/url/":
            return self._parse_url_response(data, original_ioc)
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
            malware = _malware_from_tags(tags)

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
