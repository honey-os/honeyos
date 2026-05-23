"""
Utility helpers used throughout HoneyOS.
"""

import json
import re
import uuid
from datetime import datetime, timezone


def generate_id() -> str:
    """Return a new UUID4 string."""
    return str(uuid.uuid4())


def sanitize_input(text: str | None) -> str:
    """
    Basic input sanitisation.

    Strips leading/trailing whitespace, removes null bytes,
    and escapes HTML-significant characters.
    """
    if text is None:
        return ""
    text = text.strip()
    text = text.replace("\x00", "")
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace('"', "&quot;")
    text = text.replace("'", "&#x27;")
    return text


def parse_json_field(field) -> dict | list | None:
    """
    Safely parse a value that may already be a dict/list or a JSON string.

    Returns the parsed object, or None on failure.
    """
    if field is None:
        return None
    if isinstance(field, (dict, list)):
        return field
    if isinstance(field, str):
        try:
            return json.loads(field)
        except (json.JSONDecodeError, TypeError):
            return None
    return None


def format_timestamp(dt: datetime | None) -> str | None:
    """
    Format a datetime as an ISO-8601 string.

    If the datetime is naive it is assumed to be UTC.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()
