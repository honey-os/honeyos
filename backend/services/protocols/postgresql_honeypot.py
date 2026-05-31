"""
PostgreSQLHoneypot -- minimal PostgreSQL wire-protocol emulation that captures
authentication and query attempts.

Implements just enough of the PostgreSQL v3 protocol to convince
simple clients (psql, pgAdmin, scanners).
"""

import logging
import re
import socket
import struct
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------
# Protocol constants
# -----------------------------------------------------------------------
# Message types (backend → frontend)
AUTH_REQUEST = b"R"
PARAMETER_STATUS = b"S"
BACKEND_KEY_DATA = b"K"
READY_FOR_QUERY = b"Z"
ROW_DESCRIPTION = b"T"
DATA_ROW = b"D"
COMMAND_COMPLETE = b"C"
ERROR_RESPONSE = b"E"
NOTICE_RESPONSE = b"N"

# Auth sub-types
AUTH_OK = 0
AUTH_CLEARTEXT = 3
AUTH_MD5 = 5

# ReadyForQuery transaction status
TXN_IDLE = b"I"


# -----------------------------------------------------------------------
# Packet helpers
# -----------------------------------------------------------------------

def _make_msg(tag: bytes, payload: bytes) -> bytes:
    """Build a PostgreSQL tagged message: tag(1) + length(4) + payload."""
    length = 4 + len(payload)
    return tag + struct.pack("!I", length) + payload


def _make_parameter_status(key: str, value: str) -> bytes:
    payload = key.encode() + b"\x00" + value.encode() + b"\x00"
    return _make_msg(PARAMETER_STATUS, payload)


def _make_error(severity: str, code: str, message: str) -> bytes:
    payload = (
        b"S" + severity.encode() + b"\x00"
        + b"V" + severity.encode() + b"\x00"
        + b"C" + code.encode() + b"\x00"
        + b"M" + message.encode() + b"\x00"
        + b"\x00"  # terminator
    )
    return _make_msg(ERROR_RESPONSE, payload)


def _make_command_complete(tag: str) -> bytes:
    return _make_msg(COMMAND_COMPLETE, tag.encode() + b"\x00")


def _make_ready_for_query() -> bytes:
    return _make_msg(READY_FOR_QUERY, TXN_IDLE)


def _make_empty_result(tag: str = "SELECT 0") -> bytes:
    """Return an empty result set (0 columns) followed by CommandComplete."""
    # RowDescription with 0 fields
    row_desc = _make_msg(ROW_DESCRIPTION, struct.pack("!H", 0))
    cmd_complete = _make_command_complete(tag)
    return row_desc + cmd_complete


def _make_row_result(columns: list[tuple[str, str | None]],
                     tag: str = "SELECT 1") -> bytes:
    """Return a result set with one row.

    *columns* is a list of ``(column_name, value)`` pairs.
    A value of ``None`` sends a SQL NULL.
    """
    num_fields = len(columns)
    # -- RowDescription --
    fields = b""
    for col_name, _ in columns:
        fields += col_name.encode() + b"\x00"
        # table_oid=0  col_attr=0  type_oid=25(text)  typlen=-1  typmod=-1  fmt=0
        fields += struct.pack("!IhIhih", 0, 0, 25, -1, -1, 0)
    row_desc = _make_msg(ROW_DESCRIPTION, struct.pack("!H", num_fields) + fields)
    # -- DataRow --
    row_data = struct.pack("!H", num_fields)
    for _, value in columns:
        if value is None:
            row_data += struct.pack("!i", -1)
        else:
            val_bytes = value.encode()
            row_data += struct.pack("!i", len(val_bytes)) + val_bytes
    data_row = _make_msg(DATA_ROW, row_data)
    # -- CommandComplete --
    return row_desc + data_row + _make_command_complete(tag)


# Map of statement-leading keywords to their CommandComplete tag.
# These are statements that do NOT return a result set — the correct
# response is just CommandComplete(<tag>) + ReadyForQuery.
_COMMAND_TAGS: dict[str, str] = {
    "SET":       "SET",
    "RESET":     "RESET",
    "BEGIN":     "BEGIN",
    "START":     "START TRANSACTION",
    "COMMIT":    "COMMIT",
    "END":       "COMMIT",
    "ROLLBACK":  "ROLLBACK",
    "ABORT":     "ROLLBACK",
    "DISCARD":   "DISCARD ALL",
    "CLOSE":     "CLOSE CURSOR",
    "DEALLOCATE": "DEALLOCATE",
    "UNLISTEN":  "UNLISTEN",
    "LISTEN":    "LISTEN",
    "NOTIFY":    "NOTIFY",
    "CREATE":    "CREATE TABLE",
    "ALTER":     "ALTER TABLE",
    "DROP":      "DROP TABLE",
    "INSERT":    "INSERT 0 0",
    "UPDATE":    "UPDATE 0",
    "DELETE":    "DELETE 0",
    "GRANT":     "GRANT",
    "REVOKE":    "REVOKE",
    "COPY":      "COPY 0",
    "TRUNCATE":  "TRUNCATE TABLE",
    "COMMENT":   "COMMENT",
    "DO":        "DO",
    "VACUUM":    "VACUUM",
    "ANALYZE":   "ANALYZE",
}


# Patterns for SELECT queries that must return realistic data to avoid
# fingerprinting.  Returning 0 rows for scalar functions like
# inet_server_addr() is a dead giveaway that this isn't real Postgres.
_RE_INET_SERVER = re.compile(r"inet_server_addr", re.IGNORECASE)
_RE_VERSION_FUNC = re.compile(r"\bversion\s*\(\s*\)", re.IGNORECASE)
_RE_CURRENT_USER = re.compile(r"\bcurrent_user\b", re.IGNORECASE)
_RE_CURRENT_DB = re.compile(r"\bcurrent_database\s*\(\s*\)", re.IGNORECASE)
_RE_COPY_SUBQUERY = re.compile(r"^COPY\s*\(", re.IGNORECASE)


def _query_response(query: str, *, server_addr: str = "127.0.0.1",
                    version: str = "14.5", username: str = "postgres",
                    database: str = "postgres") -> tuple[bytes, str]:
    """Build the wire response and human-readable reply text for *query*.

    Returns ``(wire_bytes, reply_text)`` where *wire_bytes* is everything
    before the ReadyForQuery message and *reply_text* is a short string
    for the session recorder.
    """
    keyword = query.split(None, 1)[0].upper().rstrip(";") if query else ""

    # COPY with a sub-SELECT (e.g. COPY (SELECT '') TO PROGRAM '…')
    # pipes at least 1 row.  Real Postgres returns COPY 1.
    if keyword == "COPY" and _RE_COPY_SUBQUERY.match(query):
        tag = "COPY 1"
        return _make_command_complete(tag), tag

    # Non-row-returning statements (SET, BEGIN, INSERT, plain COPY, …)
    tag = _COMMAND_TAGS.get(keyword)
    if tag is not None:
        return _make_command_complete(tag), tag

    # -- Row-returning statements (SELECT, SHOW, EXPLAIN, …) -----------

    # inet_server_addr() — must return at least 1 row on real PG.
    if _RE_INET_SERVER.search(query):
        ip = server_addr
        if "host(" in query.lower():
            return _make_row_result([("host", ip)]), ip
        return _make_row_result([("inet_server_addr", f"{ip}/32")]), f"{ip}/32"

    # version()
    if _RE_VERSION_FUNC.search(query):
        full = (f"PostgreSQL {version} on x86_64-pc-linux-gnu, "
                "compiled by gcc (GCC) 12.2.0, 64-bit")
        return _make_row_result([("version", full)]), f"PostgreSQL {version}"

    # current_user
    if _RE_CURRENT_USER.search(query):
        return _make_row_result([("current_user", username)]), username

    # current_database()
    if _RE_CURRENT_DB.search(query):
        return _make_row_result([("current_database", database)]), database

    # Unknown SELECT → empty result set
    return _make_empty_result(), "SELECT 0"


def _read_message(sock: socket.socket) -> tuple[str, bytes] | None:
    """Read a single tagged PostgreSQL message. Returns (tag, payload) or None."""
    tag_byte = b""
    while len(tag_byte) < 1:
        chunk = sock.recv(1)
        if not chunk:
            return None
        tag_byte += chunk

    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk

    length = struct.unpack("!I", hdr)[0] - 4
    if length < 0 or length > 10_000_000:
        return None

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk

    return tag_byte.decode("ascii", errors="replace"), payload


def _read_startup(sock: socket.socket) -> dict | None:
    """
    Read the initial startup message (no tag byte).

    Returns parsed parameters dict or None on error.
    Special key ``__ssl`` is set if the client sent an SSLRequest.
    """
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk

    length = struct.unpack("!I", hdr)[0] - 4
    if length < 4 or length > 10_000:
        return None

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return None
        payload += chunk

    protocol_version = struct.unpack("!I", payload[:4])[0]

    # SSLRequest: protocol 80877103
    if protocol_version == 80877103:
        return {"__ssl": True}

    # GSSENCRequest: protocol 80877104
    if protocol_version == 80877104:
        return {"__gssenc": True}

    # CancelRequest: protocol 80877102
    if protocol_version == 80877102:
        return None

    # Parse key=value\0 pairs
    params: dict[str, str] = {}
    rest = payload[4:]
    parts = rest.split(b"\x00")
    i = 0
    while i + 1 < len(parts):
        key = parts[i].decode("utf-8", errors="replace")
        val = parts[i + 1].decode("utf-8", errors="replace")
        if key:
            params[key] = val
        i += 2

    return params


# -----------------------------------------------------------------------
# Honeypot class
# -----------------------------------------------------------------------

class PostgreSQLHoneypot:
    """Fake PostgreSQL server that captures authentication and query attempts."""

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
        self._host_ip = self._detect_host_ip()

    @staticmethod
    def _detect_host_ip() -> str:
        """Return the IP that inet_server_addr() should report.

        Prefers the PUBLIC_IP env var (explicit override), then tries to
        detect the default-route IP via a non-transmitting UDP socket.
        Falls back to 127.0.0.1 if detection fails.
        """
        import os
        public = os.getenv("PUBLIC_IP", "")
        if public:
            return public
        try:
            # Connect a UDP socket to an external address to discover
            # which local interface the OS would route through.
            # No data is actually sent.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

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
            logger.info("PostgreSQL honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("PostgreSQL honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                if self.connection_throttler and (
                    self.connection_throttler.is_blocked(addr[0], "postgresql")
                    or not self.connection_throttler.track_connect(addr[0], "postgresql")
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
                    logger.exception("PostgreSQL accept error")
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
            server_addr = self._host_ip

            # Read startup message
            params = _read_startup(client_sock)
            if params is None:
                return

            # Handle SSLRequest -- decline and read the real startup
            if params.get("__ssl"):
                client_sock.sendall(b"N")  # deny SSL
                params = _read_startup(client_sock)
                if params is None:
                    return

            # Handle GSSENCRequest -- decline and read the real startup
            if params.get("__gssenc"):
                client_sock.sendall(b"N")
                params = _read_startup(client_sock)
                if params is None:
                    return

            username = params.get("user", "")
            database = params.get("database", username)

            logger.info("PostgreSQL auth  user=%s  db=%s  from=%s", username, database, addr[0])

            # Request cleartext password
            client_sock.sendall(_make_msg(AUTH_REQUEST, struct.pack("!I", AUTH_CLEARTEXT)))

            # Read password message (tag 'p') with a short timeout so scanners
            # that don't send a password still get the version info.
            password = ""
            prev_timeout = client_sock.gettimeout()
            client_sock.settimeout(5)
            try:
                result = _read_message(client_sock)
                if result and result[0] == "p":
                    password = result[1].rstrip(b"\x00").decode("utf-8", errors="replace")
            except (socket.timeout, OSError):
                pass
            finally:
                client_sock.settimeout(prev_timeout)

            # Log credential attempt
            if self.event_processor:
                self.event_processor.process_event({
                    "event_type": "authentication",
                    "protocol": "postgresql",
                    "source_ip": addr[0],
                    "source_port": addr[1],
                    "destination_port": self.port,
                    "severity": "high",
                    "details": {
                        "username": username,
                        "database": database,
                        "password": password,
                    },
                })

            # Start session
            if self.session_recorder:
                sess = self.session_recorder.start_session(addr[0], "postgresql")
                session_id = sess.id

            # Send AuthenticationOk -- always sent, even if no password was
            # received, so scanners can read the ParameterStatus messages.
            client_sock.sendall(_make_msg(AUTH_REQUEST, struct.pack("!I", AUTH_OK)))

            # Send parameter status messages (mimics a real server)
            version = self.config.get("version_string", "14.5")
            status_params = [
                ("server_version", version),
                ("server_encoding", "UTF8"),
                ("client_encoding", "UTF8"),
                ("DateStyle", "ISO, MDY"),
                ("TimeZone", "UTC"),
                ("integer_datetimes", "on"),
                ("standard_conforming_strings", "on"),
            ]
            for key, val in status_params:
                client_sock.sendall(_make_parameter_status(key, val))

            # BackendKeyData (process id + secret key -- fake values)
            client_sock.sendall(
                _make_msg(BACKEND_KEY_DATA, struct.pack("!II", conn_id, 0))
            )

            # ReadyForQuery
            client_sock.sendall(_make_ready_for_query())

            # Command phase
            while not self._stop_event.is_set():
                result = _read_message(client_sock)
                if result is None:
                    break

                tag, payload = result

                if tag == "X":  # Terminate
                    break

                if tag == "Q":  # Simple Query
                    query = payload.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                    logger.info("PostgreSQL query from %s: %s", addr[0], query)
                    cmd_time = datetime.now(timezone.utc)

                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "query",
                            "protocol": "postgresql",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "medium",
                            "session_id": session_id,
                            "details": {"query": query},
                        })

                    # Respond with the right message shape for the
                    # statement type, then signal ReadyForQuery so the
                    # client knows it can send the next command.
                    response, reply_text = _query_response(
                        query,
                        server_addr=server_addr,
                        version=version,
                        username=username,
                        database=database,
                    )
                    client_sock.sendall(response + _make_ready_for_query())

                    # Record command with human-readable response
                    if self.session_recorder and session_id:
                        self.session_recorder.record_command(
                            session_id, query, cmd_time, output=reply_text,
                        )

                else:
                    # Unknown/unsupported message -- send error and stay alive
                    client_sock.sendall(
                        _make_error("ERROR", "0A000", "Feature not supported")
                        + _make_ready_for_query()
                    )

        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            logger.debug("PostgreSQL connection lost for %s (scanner/probe)", addr[0])
        except Exception:
            logger.exception("PostgreSQL handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
            if ctx:
                _db.session.remove()
                ctx.pop()
