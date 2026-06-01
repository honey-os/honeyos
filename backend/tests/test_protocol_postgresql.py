"""Tests for backend/services/protocols/postgresql_honeypot.py"""

import struct

from services.protocols.postgresql_honeypot import (
    _make_msg,
    _make_parameter_status,
    _make_error,
    _make_command_complete,
    _make_ready_for_query,
    _make_empty_result,
    _make_row_result,
    _query_response,
    AUTH_REQUEST,
    PARAMETER_STATUS,
    READY_FOR_QUERY,
    ROW_DESCRIPTION,
    DATA_ROW,
    COMMAND_COMPLETE,
    ERROR_RESPONSE,
    TXN_IDLE,
)


class TestMakeMsg:
    def test_structure(self):
        msg = _make_msg(b"T", b"hello")
        assert msg[0:1] == b"T"
        length = struct.unpack("!I", msg[1:5])[0]
        assert length == 4 + 5  # 4 (self) + len("hello")
        assert msg[5:] == b"hello"

    def test_empty_payload(self):
        msg = _make_msg(b"Z", b"I")
        assert msg[0:1] == b"Z"
        length = struct.unpack("!I", msg[1:5])[0]
        assert length == 5


class TestMakeParameterStatus:
    def test_format(self):
        msg = _make_parameter_status("server_version", "14.5")
        assert msg[0:1] == PARAMETER_STATUS
        # Payload should contain key\0value\0
        payload = msg[5:]
        assert b"server_version\x00" in payload
        assert b"14.5\x00" in payload


class TestMakeError:
    def test_contains_fields(self):
        msg = _make_error("ERROR", "42P01", "table not found")
        assert msg[0:1] == ERROR_RESPONSE
        payload = msg[5:]
        assert b"SERROR\x00" in payload
        assert b"C42P01\x00" in payload
        assert b"Mtable not found\x00" in payload

    def test_terminated(self):
        msg = _make_error("ERROR", "0A000", "not supported")
        # Last byte of payload should be 0x00 (terminator)
        assert msg[-1] == 0x00


class TestMakeCommandComplete:
    def test_format(self):
        msg = _make_command_complete("SELECT 1")
        assert msg[0:1] == COMMAND_COMPLETE
        payload = msg[5:]
        assert payload == b"SELECT 1\x00"


class TestMakeReadyForQuery:
    def test_idle_status(self):
        msg = _make_ready_for_query()
        assert msg[0:1] == READY_FOR_QUERY
        assert msg[5:6] == TXN_IDLE


class TestMakeEmptyResult:
    def test_contains_row_description(self):
        result = _make_empty_result()
        assert ROW_DESCRIPTION in result

    def test_contains_command_complete(self):
        result = _make_empty_result("SELECT 0")
        assert COMMAND_COMPLETE in result


class TestMakeRowResult:
    def test_single_column(self):
        result = _make_row_result([("version", "14.5")])
        assert ROW_DESCRIPTION in result
        assert DATA_ROW in result
        assert COMMAND_COMPLETE in result

    def test_null_value(self):
        result = _make_row_result([("col", None)])
        assert DATA_ROW in result


class TestQueryResponse:
    def test_set_command(self):
        wire, text = _query_response("SET client_encoding TO 'UTF8'")
        assert text == "SET"
        assert COMMAND_COMPLETE in wire

    def test_begin_command(self):
        wire, text = _query_response("BEGIN")
        assert text == "BEGIN"

    def test_commit_command(self):
        wire, text = _query_response("COMMIT")
        assert text == "COMMIT"

    def test_insert_command(self):
        wire, text = _query_response("INSERT INTO users VALUES (1)")
        assert text == "INSERT 0 0"

    def test_select_version(self):
        wire, text = _query_response("SELECT version()")
        assert "PostgreSQL" in text
        assert ROW_DESCRIPTION in wire

    def test_select_current_user(self):
        wire, text = _query_response(
            "SELECT current_user", username="testuser"
        )
        assert text == "testuser"

    def test_select_current_database(self):
        wire, text = _query_response(
            "SELECT current_database()", database="mydb"
        )
        assert text == "mydb"

    def test_select_inet_server_addr(self):
        wire, text = _query_response(
            "SELECT inet_server_addr()", server_addr="10.0.0.5"
        )
        assert "10.0.0.5" in text

    def test_unknown_select_returns_empty(self):
        wire, text = _query_response("SELECT * FROM some_table")
        assert text == "SELECT 0"

    def test_copy_with_subquery(self):
        wire, text = _query_response("COPY (SELECT '') TO PROGRAM '/bin/sh'")
        assert text == "COPY 1"

    def test_plain_copy(self):
        wire, text = _query_response("COPY data FROM '/tmp/file'")
        assert text == "COPY 0"
