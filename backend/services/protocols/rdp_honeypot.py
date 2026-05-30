"""
RDPHoneypot -- fake RDP server capturing connection attempts and
username extraction from X.224 Connection Request cookies.

Implements minimal X.224/RDP negotiation: parses the initial Connection
Request (extracting the mstshash cookie username and requested security
protocols), then replies with a valid Connection Confirm + RDP Negotiation
Response. This is enough to convince scanners and capture attacker info.
"""

import logging
import socket
import struct
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# TPKT header: version 3, reserved 0, 2-byte big-endian length
_TPKT_VERSION = 3

# X.224 Connection Request / Confirm
_X224_CR = 0xE0  # Connection Request
_X224_CC = 0xD0  # Connection Confirm

# RDP Negotiation Request/Response type codes
_RDP_NEG_REQ = 0x01
_RDP_NEG_RSP = 0x02

# RDP Negotiation protocol flags
_PROTOCOL_RDP = 0x00000000
_PROTOCOL_SSL = 0x00000001
_PROTOCOL_HYBRID = 0x00000003  # CredSSP (NLA)

# Cookie prefix in X.224 CR
_COOKIE_PREFIX = b"Cookie: mstshash="


class RDPHoneypot:
    """
    Socket-based RDP honeypot implementing X.224 negotiation to capture
    connection metadata and attacker usernames from mstshash cookies.
    """

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None, connection_throttler=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self.connection_throttler = connection_throttler
        self.server_name = self.config.get("server_name", "DESKTOP-HOS7890")
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()

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
            logger.info("RDP honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("RDP honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                if self.connection_throttler and (
                    self.connection_throttler.is_blocked(addr[0], "rdp")
                    or not self.connection_throttler.track_connect(addr[0], "rdp")
                ):
                    client.close()
                    continue
                t = threading.Thread(
                    target=self._handle_client, args=(client, addr), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("RDP accept error")
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

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        from models import db as _db

        session_id: str | None = None
        app_ctx = self.app.app_context() if self.app else None
        if app_ctx:
            app_ctx.push()
        try:
            client_sock.settimeout(30)

            # Read TPKT header (4 bytes)
            tpkt = self._recv_exact(client_sock, 4)
            if not tpkt or tpkt[0] != _TPKT_VERSION:
                return

            pkt_len = struct.unpack(">H", tpkt[2:4])[0]
            if pkt_len < 7 or pkt_len > 8192:
                return

            # Read the rest of the TPKT packet
            remaining = pkt_len - 4
            payload = self._recv_exact(client_sock, remaining)
            if not payload:
                return

            # Parse X.224 Connection Request
            cr_info = self._parse_x224_cr(payload)
            if cr_info is None:
                return

            # Create session
            if self.session_recorder:
                sess = self.session_recorder.start_session(addr[0], "rdp")
                session_id = sess.id

            # Emit connection event
            self._emit_connection_event(addr, session_id, cr_info)

            # Record command if we have a session
            if self.session_recorder and session_id:
                parts = [f"X224_CR user={cr_info.get('username', '')}"]
                req_proto = cr_info.get("requested_protocols")
                if req_proto is not None:
                    parts.append(f"protocols=0x{req_proto:08x}")
                self.session_recorder.record_command(
                    session_id,
                    " ".join(parts),
                    datetime.now(timezone.utc),
                    output="X224_CC PROTOCOL_RDP",
                )

            # Send X.224 Connection Confirm
            response = self._build_x224_cc()
            client_sock.sendall(response)

            # Wait briefly for any follow-up data (TLS ClientHello, etc.)
            try:
                client_sock.settimeout(3)
                extra = client_sock.recv(4096)
                if extra and self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id,
                        f"POST_NEGOTIATE {len(extra)} bytes",
                        datetime.now(timezone.utc),
                        output="(connection closed)",
                    )
            except (socket.timeout, OSError):
                pass

        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            logger.exception("RDP handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
            if app_ctx:
                _db.session.remove()
                app_ctx.pop()

    # ------------------------------------------------------------------
    # X.224 parsing / building
    # ------------------------------------------------------------------

    def _parse_x224_cr(self, payload: bytes) -> dict | None:
        """Parse an X.224 Connection Request and extract cookie + negotiation.

        Expected payload layout (after TPKT header):
          [0]     X.224 length indicator
          [1-2]   X.224 CR + dst-ref (0xE0, 0x00)
          [3-4]   src-ref
          [5]     class/options
          [6+]    variable: cookie string, then optional RDP Negotiation Request
        """
        if len(payload) < 6:
            return None

        x224_type = payload[1] >> 4
        if x224_type != (_X224_CR >> 4):
            return None

        result: dict = {
            "username": "",
            "requested_protocols": None,
            "cookie_raw": "",
        }

        # Variable data starts at offset 6
        var_data = payload[6:]

        # Look for mstshash cookie
        cookie_idx = var_data.find(_COOKIE_PREFIX)
        if cookie_idx >= 0:
            # Username follows "Cookie: mstshash=" up to \r\n
            name_start = cookie_idx + len(_COOKIE_PREFIX)
            cr_idx = var_data.find(b"\r\n", name_start)
            if cr_idx > name_start:
                username = var_data[name_start:cr_idx].decode("ascii", errors="replace")
            else:
                username = var_data[name_start:min(name_start + 64, len(var_data))].decode(
                    "ascii", errors="replace"
                )
            result["username"] = username.strip()
            result["cookie_raw"] = var_data[cookie_idx:cr_idx + 2].decode(
                "ascii", errors="replace"
            ) if cr_idx > cookie_idx else ""

        # Look for RDP Negotiation Request (type 0x01, flags, length 8, protocol flags)
        # It sits at the end of the variable data, always 8 bytes
        neg_offset = self._find_neg_request(var_data)
        if neg_offset is not None and neg_offset + 8 <= len(var_data):
            neg_type = var_data[neg_offset]
            if neg_type == _RDP_NEG_REQ:
                req_protocols = struct.unpack_from("<I", var_data, neg_offset + 4)[0]
                result["requested_protocols"] = req_protocols

        return result

    @staticmethod
    def _find_neg_request(var_data: bytes) -> int | None:
        """Locate the RDP Negotiation Request in the variable portion.

        The negotiation request is always 8 bytes and appears at the end
        of the variable data (after the cookie + CRLF, if present).
        """
        # Try the last 8 bytes first — most common case
        if len(var_data) >= 8:
            candidate = len(var_data) - 8
            if var_data[candidate] == _RDP_NEG_REQ:
                # Verify length field is 8
                neg_len = struct.unpack_from("<H", var_data, candidate + 2)[0]
                if neg_len == 8:
                    return candidate

        # Fallback: scan for type byte 0x01 with length 0x0008
        for i in range(len(var_data) - 7):
            if var_data[i] == _RDP_NEG_REQ:
                neg_len = struct.unpack_from("<H", var_data, i + 2)[0]
                if neg_len == 8:
                    return i

        return None

    def _build_x224_cc(self) -> bytes:
        """Build a complete TPKT + X.224 Connection Confirm + RDP Negotiation
        Response selecting standard RDP security.

        Total: 19 bytes
          TPKT header:    4 bytes (version=3, reserved=0, length=19)
          X.224 CC:       7 bytes (length=14, type=0xD0, dst/src/class)
          RDP Neg RSP:    8 bytes (type=0x02, flags=0, length=8, protocol=0)
        """
        pkt = bytearray(19)

        # TPKT header
        pkt[0] = _TPKT_VERSION  # version
        pkt[1] = 0              # reserved
        struct.pack_into(">H", pkt, 2, 19)  # total length

        # X.224 Connection Confirm
        pkt[4] = 14             # X.224 length indicator (bytes following this byte)
        pkt[5] = _X224_CC       # type: Connection Confirm
        pkt[6] = 0x00           # dst-ref high
        pkt[7] = 0x00           # dst-ref low
        pkt[8] = 0x00           # src-ref high
        pkt[9] = 0x00           # src-ref low
        pkt[10] = 0x00          # class 0, no options

        # RDP Negotiation Response
        pkt[11] = _RDP_NEG_RSP  # type
        pkt[12] = 0x00          # flags
        struct.pack_into("<H", pkt, 13, 8)  # length
        struct.pack_into("<I", pkt, 15, _PROTOCOL_RDP)  # selected protocol: standard RDP

        return bytes(pkt)

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit_connection_event(self, addr: tuple, session_id: str | None,
                               cr_info: dict) -> None:
        username = cr_info.get("username", "")
        req_protocols = cr_info.get("requested_protocols")

        details: dict = {
            "server_name": self.server_name,
        }
        if username:
            details["username"] = username
        if req_protocols is not None:
            details["requested_protocols"] = req_protocols
            # Decode protocol flags for readability
            proto_names = []
            if req_protocols & _PROTOCOL_SSL:
                proto_names.append("SSL")
            if req_protocols & 0x00000002:
                proto_names.append("CredSSP")
            if not proto_names:
                proto_names.append("RDP")
            details["requested_protocol_names"] = proto_names

        severity = "medium" if username else "low"

        logger.info(
            "RDP connection  user=%s  protocols=%s  from=%s",
            username or "(none)",
            details.get("requested_protocol_names", ["unknown"]),
            addr[0],
        )

        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "connection",
                "protocol": "rdp",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": severity,
                "session_id": session_id,
                "details": details,
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recv_exact(sock: socket.socket, length: int) -> bytes | None:
        """Receive exactly *length* bytes or return None on failure."""
        buf = b""
        while len(buf) < length:
            try:
                chunk = sock.recv(length - len(buf))
            except (socket.timeout, ConnectionResetError, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return buf
