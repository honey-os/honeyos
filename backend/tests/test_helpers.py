"""Tests for backend/utils/helpers.py"""

import re

from utils.helpers import generate_id, format_timestamp, parse_json_field, sanitize_input


class TestGenerateId:
    def test_returns_uuid4_format(self):
        result = generate_id()
        pattern = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
        assert pattern.match(result), f"{result!r} is not a valid UUID4"

    def test_uniqueness(self):
        ids = {generate_id() for _ in range(100)}
        assert len(ids) == 100


class TestSanitizeInput:
    def test_strips_whitespace(self):
        assert sanitize_input("  hello  ") == "hello"

    def test_removes_null_bytes(self):
        assert sanitize_input("ab\x00cd") == "abcd"

    def test_escapes_html(self):
        result = sanitize_input('<script>alert("xss")</script>')
        assert "<" not in result
        assert ">" not in result
        assert "&lt;" in result
        assert "&gt;" in result
        assert "&quot;" in result

    def test_escapes_ampersand(self):
        assert sanitize_input("a&b") == "a&amp;b"

    def test_escapes_single_quote(self):
        assert sanitize_input("it's") == "it&#x27;s"

    def test_none_returns_empty_string(self):
        assert sanitize_input(None) == ""

    def test_empty_string(self):
        assert sanitize_input("") == ""


class TestParseJsonField:
    def test_dict_passthrough(self):
        d = {"key": "value"}
        assert parse_json_field(d) is d

    def test_list_passthrough(self):
        lst = [1, 2, 3]
        assert parse_json_field(lst) is lst

    def test_string_parsing(self):
        result = parse_json_field('{"a": 1}')
        assert result == {"a": 1}

    def test_none_returns_none(self):
        assert parse_json_field(None) is None

    def test_invalid_json_returns_none(self):
        assert parse_json_field("not json") is None

    def test_numeric_input_returns_none(self):
        assert parse_json_field(42) is None


class TestFormatTimestamp:
    def test_none_returns_none(self):
        assert format_timestamp(None) is None

    def test_naive_datetime_treated_as_utc(self):
        from datetime import datetime
        dt = datetime(2024, 1, 15, 12, 30, 0)
        result = format_timestamp(dt)
        assert "+00:00" in result

    def test_aware_datetime(self):
        from datetime import datetime, timezone
        dt = datetime(2024, 1, 15, 12, 30, 0, tzinfo=timezone.utc)
        result = format_timestamp(dt)
        assert "2024-01-15" in result
