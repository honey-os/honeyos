"""
MySQLHoneypot -- minimal MySQL protocol emulation that captures
authentication and query attempts.

Implements just enough of the MySQL wire protocol to convince
simple clients and scanners.
"""

import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone

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


def _build_ok_packet(seq: int) -> bytes:
    """Build a simple OK packet."""
    payload = b"\x00\x00\x00\x02\x00\x00\x00"
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
                 session_recorder=None, app=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
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
        session_id = None
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

            # Log credential attempt
            if self.event_processor and self.app:
                with self.app.app_context():
                    self.event_processor.process_event({
                        "event_type": "authentication",
                        "protocol": "mysql",
                        "source_ip": addr[0],
                        "source_port": addr[1],
                        "destination_port": self.port,
                        "severity": "high",
                        "details": {
                            "username": username,
                            "database": database,
                        },
                    })

            # Start session
            if self.session_recorder and self.app:
                with self.app.app_context():
                    sess = self.session_recorder.start_session(addr[0], "mysql")
                    session_id = sess.id

            # Send OK to let the client continue
            client_sock.sendall(_build_ok_packet(seq + 1))

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

                    if self.session_recorder and session_id and self.app:
                        with self.app.app_context():
                            self.session_recorder.record_command(
                                session_id, query, datetime.now(timezone.utc)
                            )

                    if self.event_processor and self.app:
                        with self.app.app_context():
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

                    # Respond with an empty result set (OK packet)
                    client_sock.sendall(_build_ok_packet(seq + 1))

                elif cmd_type == 0x02:  # COM_INIT_DB
                    client_sock.sendall(_build_ok_packet(seq + 1))

                elif cmd_type == 0x0E:  # COM_PING
                    client_sock.sendall(_build_ok_packet(seq + 1))

                else:
                    # Unknown command -- send error
                    client_sock.sendall(
                        _build_error_packet(seq + 1, 1047, "Unknown command")
                    )

        except Exception:
            logger.exception("MySQL handler error for %s", addr)
        finally:
            if session_id and self.session_recorder and self.app:
                with self.app.app_context():
                    self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
