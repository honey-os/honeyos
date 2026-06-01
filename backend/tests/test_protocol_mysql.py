"""Tests for backend/services/protocols/mysql_honeypot.py"""

import struct

from services.protocols.mysql_honeypot import (
    _build_greeting_packet,
    _build_ok_packet,
    _build_error_packet,
    _parse_auth_packet,
    _query_resultset,
    _lenenc_int,
    _lenenc_str,
    _SERVER_STATUS_AUTOCOMMIT,
)


class TestBuildGreetingPacket:
    def test_has_mysql_header(self):
        pkt = _build_greeting_packet(1)
        # First 3 bytes are length (little-endian), 4th byte is sequence id
        length = struct.unpack("<I", pkt[:3] + b"\x00")[0]
        seq = pkt[3]
        assert seq == 0
        assert length > 0
        assert len(pkt) == 4 + length

    def test_protocol_version_10(self):
        pkt = _build_greeting_packet(1)
        # Protocol version is the first byte of the payload
        assert pkt[4] == 10

    def test_server_version_string(self):
        pkt = _build_greeting_packet(1)
        # Server version starts at byte 5, null-terminated
        null_idx = pkt.index(b"\x00", 5)
        version = pkt[5:null_idx].decode("utf-8")
        assert "5.7.38" in version

    def test_different_connection_ids(self):
        pkt1 = _build_greeting_packet(1)
        pkt2 = _build_greeting_packet(42)
        # Connection ID is after the version string null terminator
        null_idx = pkt1.index(b"\x00", 5)
        thread_id_1 = struct.unpack("<I", pkt1[null_idx + 1:null_idx + 5])[0]
        null_idx2 = pkt2.index(b"\x00", 5)
        thread_id_2 = struct.unpack("<I", pkt2[null_idx2 + 1:null_idx2 + 5])[0]
        assert thread_id_1 == 1
        assert thread_id_2 == 42


class TestBuildOkPacket:
    def test_ok_indicator(self):
        pkt = _build_ok_packet(1)
        # Payload starts at byte 4; first byte should be 0x00 (OK)
        assert pkt[4] == 0x00

    def test_sequence_id(self):
        pkt = _build_ok_packet(5)
        assert pkt[3] == 5

    def test_status_flags(self):
        pkt = _build_ok_packet(1, status_flags=0x0002)
        # Status flags are at payload offset 3-4
        status = struct.unpack("<H", pkt[7:9])[0]
        assert status == 0x0002


class TestBuildErrorPacket:
    def test_error_indicator(self):
        pkt = _build_error_packet(1, 1045, "Access denied")
        assert pkt[4] == 0xFF

    def test_error_code(self):
        pkt = _build_error_packet(1, 1045, "Access denied")
        code = struct.unpack("<H", pkt[5:7])[0]
        assert code == 1045

    def test_error_message(self):
        pkt = _build_error_packet(1, 1045, "Access denied")
        # Skip header(4) + 0xFF(1) + code(2) + '#'(1) + sqlstate(5)
        msg = pkt[13:].decode("utf-8")
        assert msg == "Access denied"


class TestParseAuthPacket:
    def test_extracts_username(self):
        # Build a minimal HandshakeResponse41
        # capabilities(4) + max_packet(4) + charset(1) + reserved(23) = 32 bytes
        header = b"\x00" * 32
        username = b"testuser\x00"
        auth_len = b"\x00"  # 0-length auth response
        database = b"mydb\x00"
        payload = header + username + auth_len + database
        result = _parse_auth_packet(payload)
        assert result["username"] == "testuser"
        assert result["database"] == "mydb"

    def test_username_only(self):
        header = b"\x00" * 32
        username = b"root\x00"
        payload = header + username
        result = _parse_auth_packet(payload)
        assert result["username"] == "root"

    def test_empty_payload(self):
        result = _parse_auth_packet(b"")
        assert result["username"] == ""
        assert result["database"] == ""


class TestQueryResultset:
    def test_show_databases(self):
        result = _query_resultset("SHOW DATABASES", 1, _SERVER_STATUS_AUTOCOMMIT, "")
        assert result is not None
        assert len(result) > 0

    def test_show_databases_case_insensitive(self):
        result = _query_resultset("show databases;", 1, _SERVER_STATUS_AUTOCOMMIT, "")
        assert result is not None

    def test_show_tables(self):
        result = _query_resultset("SHOW TABLES", 1, _SERVER_STATUS_AUTOCOMMIT, "mydb")
        assert result is not None

    def test_select_system_variable(self):
        result = _query_resultset(
            "SELECT @@version", 1, _SERVER_STATUS_AUTOCOMMIT, ""
        )
        assert result is not None

    def test_select_database(self):
        result = _query_resultset(
            "SELECT DATABASE()", 1, _SERVER_STATUS_AUTOCOMMIT, "testdb"
        )
        assert result is not None

    def test_unknown_query_returns_none(self):
        result = _query_resultset(
            "INSERT INTO users VALUES (1)", 1, _SERVER_STATUS_AUTOCOMMIT, ""
        )
        assert result is None

    def test_select_autocommit(self):
        result = _query_resultset(
            "SELECT @@autocommit", 1, _SERVER_STATUS_AUTOCOMMIT, ""
        )
        assert result is not None


class TestLenencInt:
    def test_small_value(self):
        assert _lenenc_int(0) == b"\x00"
        assert _lenenc_int(250) == b"\xfa"

    def test_two_byte(self):
        result = _lenenc_int(251)
        assert result[0] == 0xFC

    def test_three_byte(self):
        result = _lenenc_int(0x10000)
        assert result[0] == 0xFD


class TestLenencStr:
    def test_short_string(self):
        result = _lenenc_str("hello")
        assert result == b"\x05hello"
