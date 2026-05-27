"""
ThreatFox (abuse.ch) IOC lookup service.

Searches session IOCs (IPs, domains, URLs, hashes) against ThreatFox
to identify known malware families.
"""

import json
import logging
import re
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

_THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Regex patterns for IOC extraction from command text
_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_MD5_RE = re.compile(r"\b([a-f0-9]{32})\b", re.IGNORECASE)
_SHA256_RE = re.compile(r"\b([a-f0-9]{64})\b", re.IGNORECASE)
_URL_RE = re.compile(
    r"(?:https?://)"                      # scheme
    r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})"   # domain
    r"(?:[/\w.,@?^=%&:;~+#-]*)?",         # path/query
)
_DOMAIN_CMD_RE = re.compile(
    r"(?:wget|curl|nc|nslookup|dig|host)\s+"
    r"(?:-[^\s]+\s+)*"                     # skip flags
    r"(?:https?://)?"
    r"([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})",   # domain
)


class ThreatFoxService:
    """Query ThreatFox for known IOCs found in honeypot sessions."""

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key

    def is_available(self) -> bool:
        """Return True if the service has a configured API key."""
        return bool(self.api_key)

    def search_ioc(self, ioc: str) -> list[dict]:
        """Search ThreatFox for a single IOC string.

        Returns a list of match dicts or an empty list on error / no results.
        """
        try:
            resp = requests.post(
                _THREATFOX_API_URL,
                json={"query": "search_ioc", "search_term": ioc},
                headers={"API-KEY": self.api_key},
                timeout=15,
            )
        except requests.RequestException:
            logger.warning("ThreatFox request failed for IOC %s", ioc)
            return []

        if resp.status_code != 200:
            logger.warning("ThreatFox returned status %d for IOC %s", resp.status_code, ioc)
            return []

        data = resp.json()
        if data.get("query_status") != "ok":
            return []

        raw_results = data.get("data", [])
        if not isinstance(raw_results, list):
            return []

        matches = []
        for entry in raw_results:
            matches.append({
                "ioc": entry.get("ioc", ioc),
                "threat_type": entry.get("threat_type", ""),
                "malware": entry.get("malware_printable", ""),
                "confidence_level": entry.get("confidence_level", 0),
                "first_seen": entry.get("first_seen", ""),
                "tags": entry.get("tags") or [],
                "reference": entry.get("reference"),
            })
        return matches

    def analyze_session(self, session) -> dict:
        """Extract IOCs from a session and query ThreatFox for each.

        Returns a structured result dict suitable for JSON storage.
        """
        iocs = self._extract_iocs(session)
        all_matches: list[dict] = []

        for ioc in iocs:
            matches = self.search_ioc(ioc)
            all_matches.extend(matches)

        return {
            "iocs_searched": iocs,
            "matches": all_matches,
            "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _extract_iocs(self, session) -> list[str]:
        """Pull unique IOCs from a session's source IP and commands."""
        iocs: list[str] = []
        seen: set[str] = set()

        def _add(value: str) -> None:
            v = value.strip()
            if v and v not in seen:
                seen.add(v)
                iocs.append(v)

        # Always include the source IP
        _add(session.source_ip)

        # Parse commands text
        commands_raw = session.commands
        if isinstance(commands_raw, str):
            try:
                commands_raw = json.loads(commands_raw)
            except (json.JSONDecodeError, TypeError):
                commands_raw = None

        if isinstance(commands_raw, list):
            for entry in commands_raw:
                text = ""
                if isinstance(entry, dict):
                    text = entry.get("command", "")
                elif isinstance(entry, str):
                    text = entry
                if not text:
                    continue

                # IPs (skip common private ranges and the session's own IP)
                for ip_match in _IP_RE.findall(text):
                    _add(ip_match)

                # Hashes
                for h in _SHA256_RE.findall(text):
                    _add(h)
                for h in _MD5_RE.findall(text):
                    _add(h)

                # Domains from wget/curl/nc commands
                for domain in _DOMAIN_CMD_RE.findall(text):
                    _add(domain)

                # Domains from full URLs
                for domain in _URL_RE.findall(text):
                    _add(domain)

        return iocs
