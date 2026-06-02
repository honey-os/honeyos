"""
MySQLHoneypot -- minimal MySQL protocol emulation that captures
authentication and query attempts.

Implements just enough of the MySQL wire protocol to convince
simple clients and scanners.
"""

import logging
import os
import re
import socket
import struct
import threading
from datetime import datetime, timezone

from utils.helpers import classify_auth_severity

logger = logging.getLogger(__name__)


def _build_greeting_packet(connection_id: int) -> bytes:
    """
    Build a MySQL server greeting (HandshakeV10) packet.

    Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/
               page_protocol_connection_phase_packets_protocol_handshake_v10.html
    """
    protocol_version = 10
    server_version = b"5.7.38-log\x00"
    thread_id = struct.pack("<I", connection_id)
    # auth-plugin-data part 1 (8 bytes)
    salt_part1 = os.urandom(8)
    filler = b"\x00"
    # capability flags (lower 2 bytes) -- advertise basic caps
    cap_lower = struct.pack("<H", 0xF7FF)
    charset = b"\x21"  # utf8_general_ci
    status_flags = struct.pack("<H", 0x0002)  # SERVER_STATUS_AUTOCOMMIT
    cap_upper = struct.pack("<H", 0x807F)
    auth_plugin_data_len = b"\x15"  # 21
    reserved = b"\x00" * 10
    # auth-plugin-data part 2 (at least 13 bytes)
    salt_part2 = os.urandom(12) + b"\x00"
    auth_plugin_name = b"mysql_native_password\x00"

    payload = (
        bytes([protocol_version])
        + server_version
        + thread_id
        + salt_part1
        + filler
        + cap_lower
        + charset
        + status_flags
        + cap_upper
        + auth_plugin_data_len
        + reserved
        + salt_part2
        + auth_plugin_name
    )

    # MySQL packet header: 3-byte length + 1-byte sequence id (0)
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload


# Server status flag bits
_SERVER_STATUS_AUTOCOMMIT = 0x0002

# Pattern to detect SET AUTOCOMMIT = 0|1|ON|OFF
_RE_SET_AUTOCOMMIT = re.compile(
    r"^\s*SET\s+AUTOCOMMIT\s*=\s*(?P<val>0|1|ON|OFF)\s*$",
    re.IGNORECASE,
)


def _build_ok_packet(seq: int, status_flags: int = _SERVER_STATUS_AUTOCOMMIT) -> bytes:
    """Build a MySQL OK packet.

    Wire format (after the 4-byte header):
        1 byte   0x00          OK indicator
        lenenc   affected_rows (0)
        lenenc   last_insert_id (0)
        2 bytes  status_flags  (little-endian)
        2 bytes  warnings      (0)
    """
    payload = (
        b"\x00"                                 # OK indicator
        + b"\x00"                               # affected_rows = 0 (lenenc)
        + b"\x00"                               # last_insert_id = 0 (lenenc)
        + struct.pack("<H", status_flags)       # server status flags
        + b"\x00\x00"                           # warnings = 0
    )
    header = struct.pack("<I", len(payload))[:3] + bytes([seq])
    return header + payload


def _build_error_packet(seq: int, code: int, message: str) -> bytes:
    """Build a MySQL ERR packet."""
    payload = (
        b"\xff"
        + struct.pack("<H", code)
        + b"#"
        + b"HY000"
        + message.encode("utf-8")
    )
    header = struct.pack("<I", len(payload))[:3] + bytes([seq])
    return header + payload


# ---------------------------------------------------------------------------
# Result-set helpers  (text protocol)
# ---------------------------------------------------------------------------

def _lenenc_int(n: int) -> bytes:
    """Encode *n* as a MySQL length-encoded integer."""
    if n < 251:
        return bytes([n])
    if n < 0x10000:
        return b"\xfc" + struct.pack("<H", n)
    if n < 0x1000000:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def _lenenc_str(s: str) -> bytes:
    """Encode *s* as a MySQL length-encoded string."""
    raw = s.encode("utf-8")
    return _lenenc_int(len(raw)) + raw


def _build_eof_packet(seq: int, status_flags: int) -> bytes:
    """Build a MySQL EOF packet (0xFE marker)."""
    payload = b"\xfe\x00\x00" + struct.pack("<H", status_flags)
    header = struct.pack("<I", len(payload))[:3] + bytes([seq])
    return header + payload


def _build_resultset(seq: int, columns: list[str], rows: list[list[str]],
                     status_flags: int) -> bytes:
    """Build a complete MySQL COM_QUERY text-protocol result set.

    Packet sequence: column-count → column-defs → EOF → rows → EOF.
    """
    parts: list[bytes] = []

    def _pkt(s: int, payload: bytes) -> bytes:
        return struct.pack("<I", len(payload))[:3] + bytes([s]) + payload

    # Column count
    parts.append(_pkt(seq, _lenenc_int(len(columns))))
    seq += 1

    # Column definitions
    for name in columns:
        col = (
            _lenenc_str("def")          # catalog
            + _lenenc_str("")           # schema
            + _lenenc_str("")           # virtual table
            + _lenenc_str("")           # physical table
            + _lenenc_str(name)         # column name
            + _lenenc_str(name)         # org column name
            + b"\x0c"                   # fixed-length fields length
            + struct.pack("<H", 33)     # charset  utf8_general_ci
            + struct.pack("<I", 256)    # column display width
            + bytes([253])              # type  VAR_STRING
            + struct.pack("<H", 0)      # flags
            + bytes([0])                # decimals
            + b"\x00\x00"              # filler
        )
        parts.append(_pkt(seq, col))
        seq += 1

    # EOF after column definitions
    parts.append(_build_eof_packet(seq, status_flags))
    seq += 1

    # Row data
    for row in rows:
        parts.append(_pkt(seq, b"".join(_lenenc_str(v) for v in row)))
        seq += 1

    # EOF after rows
    parts.append(_build_eof_packet(seq, status_flags))
    return b"".join(parts)


# ---------------------------------------------------------------------------
# Query → result-set dispatcher
# ---------------------------------------------------------------------------

_RE_SELECT_VAR = re.compile(
    r"^SELECT\s+@@(?:global\.|session\.)?(\w+)", re.IGNORECASE,
)
_RE_SELECT_DATABASE = re.compile(
    r"^SELECT\s+DATABASE\s*\(\s*\)", re.IGNORECASE,
)

# System-variable values a real MySQL 5.7 would return.
_SYSTEM_VARIABLES: dict[str, str] = {
    "version": "5.7.38-log",
    "version_comment": "MySQL Community Server (GPL)",
    "version_compile_os": "Linux",
    "max_allowed_packet": "67108864",
    "character_set_server": "utf8",
    "collation_server": "utf8_general_ci",
    "interactive_timeout": "28800",
    "wait_timeout": "28800",
    "net_write_timeout": "60",
    "max_connections": "151",
    "lower_case_table_names": "0",
    "hostname": "mysql-server",
}


def _query_resultset(query: str, seq: int, status_flags: int,
                     database: str) -> bytes | None:
    """Return wire bytes for queries that expect a tabular result, else *None*.

    Handles the handful of probe queries bots and clients issue right after
    authenticating.  Everything else falls through to the caller's OK packet.
    """
    upper = query.upper().strip().rstrip(";").strip()

    # SHOW DATABASES / SHOW SCHEMAS
    if upper in ("SHOW DATABASES", "SHOW SCHEMAS"):
        return _build_resultset(seq, ["Database"], [
            ["information_schema"],
            ["mysql"],
            ["performance_schema"],
            ["sys"],
        ], status_flags)

    # SHOW TABLES  (return empty set -- no real tables to expose)
    if upper.startswith("SHOW TABLES"):
        col = "Tables_in_" + (database or "mysql")
        return _build_resultset(seq, [col], [], status_flags)

    # SELECT @@variable  (@@global.var / @@session.var / @@var)
    m = _RE_SELECT_VAR.match(query)
    if m:
        var = m.group(1).lower()
        if var == "autocommit":
            val = "ON" if (status_flags & _SERVER_STATUS_AUTOCOMMIT) else "OFF"
        else:
            val = _SYSTEM_VARIABLES.get(var, "")
        # Use the original token as the column alias, like a real server.
        col = query.split()[1].rstrip(";")
        return _build_resultset(seq, [col], [[val]], status_flags)

    # SELECT DATABASE()
    if _RE_SELECT_DATABASE.match(query):
        return _build_resultset(seq, ["DATABASE()"],
                                [[database or ""]], status_flags)

    return None


def _describe_query_result(query: str, database: str) -> str:
    """Return a human-readable description of the result set for replay."""
    upper = query.upper().strip().rstrip(";").strip()
    if upper in ("SHOW DATABASES", "SHOW SCHEMAS"):
        return "information_schema, mysql, performance_schema, sys"
    if upper.startswith("SHOW TABLES"):
        return f"(empty set — no tables in {database or 'mysql'})"
    m = _RE_SELECT_VAR.match(query)
    if m:
        var = m.group(1).lower()
        val = _SYSTEM_VARIABLES.get(var, "")
        return f"{m.group(1)} = {val}"
    if _RE_SELECT_DATABASE.match(query):
        return database or "(NULL)"
    return "OK"


def _read_packet(sock: socket.socket) -> tuple[int, bytes] | None:
    """Read one MySQL packet.  Returns (sequence_id, payload) or None."""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk

    length = struct.unpack("<I", header[:3] + b"\x00")[0]
    seq = header[3]

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk

    return seq, payload


def _parse_auth_packet(payload: bytes) -> dict:
    """
    Parse a HandshakeResponse41 packet to extract username.
    """
    info: dict = {"username": "", "database": ""}
    try:
        # Client capabilities (4 bytes), max packet size (4 bytes),
        # charset (1 byte), reserved (23 bytes)
        offset = 4 + 4 + 1 + 23
        # Username (null-terminated)
        end = payload.index(b"\x00", offset)
        info["username"] = payload[offset:end].decode("utf-8", errors="replace")
        offset = end + 1
        # Auth response length (1 byte) + data
        if offset < len(payload):
            auth_len = payload[offset]
            offset += 1 + auth_len
        # Database (null-terminated, optional)
        if offset < len(payload):
            end = payload.index(b"\x00", offset)
            info["database"] = payload[offset:end].decode("utf-8", errors="replace")
    except (IndexError, ValueError):
        pass
    return info


class MySQLHoneypot:
    """
    Fake MySQL server that captures authentication and query attempts.
    """

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None, connection_throttler=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self.connection_throttler = connection_throttler
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()
        self._conn_counter = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.settimeout(1.0)

        try:
            self._server_socket.bind(("0.0.0.0", self.port))
            self._server_socket.listen(5)
            logger.info("MySQL honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("MySQL honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                if self.connection_throttler and (
                    self.connection_throttler.is_blocked(addr[0], "mysql")
                    or not self.connection_throttler.track_connect(addr[0], "mysql")
                ):
                    client.close()
                    continue
                self._conn_counter += 1
                t = threading.Thread(
                    target=self._handle_client,
                    args=(client, addr, self._conn_counter),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("MySQL accept error")
                break

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    def _handle_client(self, client_sock: socket.socket, addr: tuple,
                       conn_id: int) -> None:
        from models import db as _db

        session_id = None
        ctx = self.app.app_context() if self.app else None
        if ctx:
            ctx.push()
        try:
            client_sock.settimeout(60)

            # Send greeting
            greeting = _build_greeting_packet(conn_id)
            client_sock.sendall(greeting)

            # Read auth response
            result = _read_packet(client_sock)
            if result is None:
                return
            seq, payload = result
            auth_info = _parse_auth_packet(payload)
            username = auth_info.get("username", "")
            database = auth_info.get("database", "")

            logger.info("MySQL auth  user=%s  db=%s  from=%s", username, database, addr[0])

            # Get or reuse session (before event so we can link the auth event)
            if self.session_recorder:
                sess, _ = self.session_recorder.get_or_start_session(addr[0], "mysql")
                session_id = sess.id
                self.session_recorder.record_command(
                    session_id,
                    f"AUTH user={username} db={database}",
                    datetime.now(timezone.utc),
                    output="OK (authentication accepted)",
                )

            # Log credential attempt
            if self.event_processor:
                self.event_processor.process_event({
                    "event_type": "authentication",
                    "protocol": "mysql",
                    "source_ip": addr[0],
                    "source_port": addr[1],
                    "destination_port": self.port,
                    "severity": classify_auth_severity(username, None),
                    "session_id": session_id,
                    "details": {
                        "username": username,
                        "database": database,
                    },
                })

            # Per-connection server status (starts with autocommit on,
            # matching the greeting packet we already sent).
            status_flags = _SERVER_STATUS_AUTOCOMMIT

            # Send OK to let the client continue
            client_sock.sendall(_build_ok_packet(seq + 1, status_flags))

            # Command phase
            while not self._stop_event.is_set():
                result = _read_packet(client_sock)
                if result is None:
                    break
                seq, payload = result

                if not payload:
                    break

                cmd_type = payload[0]
                cmd_data = payload[1:].decode("utf-8", errors="replace")

                if cmd_type == 0x01:  # COM_QUIT
                    break

                if cmd_type == 0x03:  # COM_QUERY
                    query = cmd_data.strip()
                    logger.info("MySQL query from %s: %s", addr[0], query)
                    cmd_time = datetime.now(timezone.utc)

                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "query",
                            "protocol": "mysql",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "medium",
                            "session_id": session_id,
                            "details": {"query": query},
                        })

                    # Track SET AUTOCOMMIT so the status flags in the
                    # OK response reflect the new state -- bots check this.
                    m = _RE_SET_AUTOCOMMIT.match(query)
                    if m:
                        val = m.group("val").upper()
                        if val in ("1", "ON"):
                            status_flags |= _SERVER_STATUS_AUTOCOMMIT
                        else:
                            status_flags &= ~_SERVER_STATUS_AUTOCOMMIT

                    # Queries that expect a tabular result set (SHOW, SELECT)
                    # get a proper column/row response; everything else gets OK.
                    resultset = _query_resultset(
                        query, seq + 1, status_flags, database,
                    )
                    if resultset is not None:
                        client_sock.sendall(resultset)
                        reply_text = _describe_query_result(query, database)
                    else:
                        client_sock.sendall(_build_ok_packet(seq + 1, status_flags))
                        reply_text = "OK"

                    if self.session_recorder and session_id:
                        self.session_recorder.record_command(
                            session_id, query, cmd_time, output=reply_text,
                        )

                elif cmd_type == 0x02:  # COM_INIT_DB
                    client_sock.sendall(_build_ok_packet(seq + 1, status_flags))

                elif cmd_type == 0x0E:  # COM_PING
                    client_sock.sendall(_build_ok_packet(seq + 1, status_flags))

                else:
                    # Unknown command -- send error
                    client_sock.sendall(
                        _build_error_packet(seq + 1, 1047, "Unknown command")
                    )

        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            logger.debug("MySQL connection lost for %s (scanner/probe)", addr[0])
        except Exception:
            logger.exception("MySQL handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            if ctx:
                _db.session.remove()
                ctx.pop()
            try:
                client_sock.close()
            except OSError:
                pass
