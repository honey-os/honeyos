"""Tests for classify_auth_severity() and _is_binary_garbage()."""

import pytest

from utils.helpers import classify_auth_severity, _is_binary_garbage


# -------------------------------------------------------------------
# _is_binary_garbage
# -------------------------------------------------------------------

class TestIsBinaryGarbage:
    def test_empty_string(self):
        assert _is_binary_garbage("") is False

    def test_normal_text(self):
        assert _is_binary_garbage("admin") is False

    def test_all_replacement_chars(self):
        assert _is_binary_garbage("\ufffd\ufffd\ufffd\ufffd") is True

    def test_control_chars(self):
        assert _is_binary_garbage("\x01\x02\x03\x04") is True

    def test_mixed_below_threshold(self):
        # 1 garbage char in 5 total = 20%, below 30%
        assert _is_binary_garbage("abcd\x01") is False

    def test_mixed_above_threshold(self):
        # 2 garbage chars in 5 total = 40%, above 30%
        assert _is_binary_garbage("abc\x01\x02") is True

    def test_tls_client_hello_pattern(self):
        # Simulated TLS ClientHello binary data
        data = "\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03"
        assert _is_binary_garbage(data) is True

    def test_tabs_newlines_not_garbage(self):
        assert _is_binary_garbage("line1\nline2\ttab\r") is False


# -------------------------------------------------------------------
# classify_auth_severity
# -------------------------------------------------------------------

class TestClassifyAuthSeverity:
    def test_both_none(self):
        assert classify_auth_severity(None, None) == "low"

    def test_both_empty(self):
        assert classify_auth_severity("", "") == "low"

    def test_none_and_empty(self):
        assert classify_auth_severity(None, "") == "low"

    def test_empty_and_none(self):
        assert classify_auth_severity("", None) == "low"

    def test_binary_garbage_username(self):
        garbage = "\ufffd\ufffd\ufffd\ufffd"
        assert classify_auth_severity(garbage, "pass123") == "low"

    def test_binary_garbage_password(self):
        garbage = "\x01\x02\x03\x04\x05"
        assert classify_auth_severity("admin", garbage) == "low"

    def test_non_printable_control_chars(self):
        assert classify_auth_severity("\x16\x03\x01\x00", "test") == "low"

    def test_real_credentials(self):
        assert classify_auth_severity("admin", "password123") == "medium"

    def test_username_only_mysql_case(self):
        assert classify_auth_severity("root", None) == "medium"

    def test_single_replacement_in_normal_string(self):
        # 1 replacement char in 10 total = 10%, below 30% threshold
        assert classify_auth_severity("adminuser\ufffd", "pass") == "medium"

    def test_protocol_param_accepted(self):
        assert classify_auth_severity("admin", "pass", protocol="ssh") == "medium"
