"""
SMBHoneypot -- fake SMB/CIFS file server capturing authentication attempts
and share access requests.

Handles both SMB1 and SMB2 negotiation, NTLMSSP authentication flow,
and tree connect requests.
"""

import logging
import os
import socket
import struct
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# SMB protocol magic bytes
_SMB1_MAGIC = b"\xffSMB"
_SMB2_MAGIC = b"\xfeSMB"

# SMB1 commands
_SMB1_COM_NEGOTIATE = 0x72
_SMB1_COM_SESSION_SETUP = 0x73
_SMB1_COM_TREE_CONNECT = 0x75

# SMB2 commands
_SMB2_COM_NEGOTIATE = 0x0000
_SMB2_COM_SESSION_SETUP = 0x0001
_SMB2_COM_TREE_CONNECT = 0x0003

# NT status codes
_STATUS_SUCCESS = 0x00000000
_STATUS_MORE_PROCESSING = 0xC0000016
_STATUS_LOGON_FAILURE = 0xC000006D
_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_BAD_NETWORK_NAME = 0xC00000CC

# NTLMSSP constants
_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLMSSP_NEGOTIATE = 1
_NTLMSSP_CHALLENGE = 2
_NTLMSSP_AUTH = 3

# NTLMSSP negotiate flags
_NTLMSSP_FLAGS = (
    0x00000001  # NEGOTIATE_UNICODE
    | 0x00000002  # NEGOTIATE_OEM
    | 0x00000004  # REQUEST_TARGET
    | 0x00000200  # NEGOTIATE_NTLM
    | 0x00008000  # NEGOTIATE_ALWAYS_SIGN
    | 0x00080000  # NEGOTIATE_NTLM2
    | 0x02000000  # NEGOTIATE_TARGET_INFO
)


class SMBHoneypot:
    """
    Socket-based SMB honeypot implementing negotiate, NTLMSSP auth,
    and tree connect to capture attacker credentials and share access.
    """

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None, connection_throttler=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self.connection_throttler = connection_throttler
        self.server_name = self.config.get("server_name", "FILESERVER")
        self.domain = self.config.get("domain", "WORKGROUP")
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()
        self._challenge = os.urandom(8)

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
            logger.info("SMB honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("SMB honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                if self.connection_throttler and self.connection_throttler.is_blocked(addr[0], "smb"):
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
                    logger.exception("SMB accept error")
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
        # session_id is created lazily on first auth/share event so that
        # bare negotiate-only connections don't produce 0-command sessions.
        ctx: dict = {"session_id": None}
        smb_version = "unknown"
        app_ctx = self.app.app_context() if self.app else None
        if app_ctx:
            app_ctx.push()
        try:
            client_sock.settimeout(30)

            while not self._stop_event.is_set():
                # Read NetBIOS session header (4 bytes: type + 3 bytes length)
                header = self._recv_exact(client_sock, 4)
                if not header:
                    break

                msg_len = struct.unpack(">I", b"\x00" + header[1:4])[0]
                if msg_len == 0 or msg_len > 65536:
                    break

                payload = self._recv_exact(client_sock, msg_len)
                if not payload:
                    break

                # Detect SMB version from magic
                if payload[:4] == _SMB1_MAGIC:
                    smb_version = "SMB1"
                    response = self._handle_smb1(payload, addr, ctx, smb_version)
                elif payload[:4] == _SMB2_MAGIC:
                    smb_version = "SMB2"
                    response = self._handle_smb2(payload, addr, ctx, smb_version)
                else:
                    break

                if response is None:
                    break

                # Send with NetBIOS header
                nb_header = struct.pack(">I", len(response))
                nb_header = b"\x00" + nb_header[1:4]
                client_sock.sendall(nb_header + response)

        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            logger.exception("SMB handler error for %s", addr)
        finally:
            if ctx["session_id"] and self.session_recorder:
                self.session_recorder.end_session(ctx["session_id"])
            try:
                client_sock.close()
            except OSError:
                pass
            if app_ctx:
                _db.session.remove()
                app_ctx.pop()

    def _ensure_session(self, addr: tuple, ctx: dict) -> str | None:
        """Lazily create a session on first meaningful interaction."""
        if ctx["session_id"] is None and self.session_recorder:
            sess = self.session_recorder.start_session(addr[0], "smb")
            ctx["session_id"] = sess.id
        return ctx["session_id"]

    # ------------------------------------------------------------------
    # SMB1 handling
    # ------------------------------------------------------------------

    def _handle_smb1(self, payload: bytes, addr: tuple,
                     ctx: dict, smb_version: str) -> bytes | None:
        """Handle an SMB1 message and return a response."""
        if len(payload) < 33:
            return None

        command = payload[4]

        if command == _SMB1_COM_NEGOTIATE:
            self._emit_connection_event(addr, ctx, smb_version)
            return self._smb1_negotiate_response(payload)

        elif command == _SMB1_COM_SESSION_SETUP:
            return self._smb1_session_setup(payload, addr, ctx)

        elif command == _SMB1_COM_TREE_CONNECT:
            return self._smb1_tree_connect(payload, addr, ctx)

        return None

    def _smb1_negotiate_response(self, request: bytes) -> bytes:
        """Build SMB1 negotiate response advertising NT LM 0.12 with NTLMSSP."""
        # SMB1 header: 32 bytes
        header = bytearray(32)
        header[0:4] = _SMB1_MAGIC
        header[4] = _SMB1_COM_NEGOTIATE
        # Status: SUCCESS
        struct.pack_into("<I", header, 5, _STATUS_SUCCESS)
        # Flags
        header[9] = 0x88  # case-insensitive, canonicalized paths
        struct.pack_into("<H", header, 10, 0xC853)  # flags2: unicode, NT status, extended security
        # MID, PID, TID, UID from request
        if len(request) >= 32:
            header[24:32] = request[24:32]

        # Security blob (NTLMSSP negotiate token)
        security_blob = self._build_spnego_init()

        # Negotiate response word count=17 (34 bytes of parameters)
        params = bytearray(34)
        struct.pack_into("<H", params, 0, 0)  # dialect index (NT LM 0.12)
        params[2] = 0x03  # security mode: signing enabled
        struct.pack_into("<H", params, 3, 1)  # max MPX count
        struct.pack_into("<H", params, 5, 1)  # max VCs
        struct.pack_into("<I", params, 7, 16644)  # max buffer size
        struct.pack_into("<I", params, 11, 16644)  # max raw
        struct.pack_into("<I", params, 15, 0)  # session key
        struct.pack_into("<I", params, 19, 0x0000F3F8)  # capabilities (extended security)
        # System time (0)
        struct.pack_into("<Q", params, 23, 0)
        struct.pack_into("<H", params, 31, 0)  # server timezone
        params[33] = 0  # encryption key length

        # Build response
        word_count = 17
        byte_count = len(security_blob)
        resp = bytearray()
        resp.append(word_count)
        resp.extend(params)
        resp.extend(struct.pack("<H", byte_count))
        resp.extend(security_blob)

        return bytes(header) + bytes(resp)

    def _smb1_session_setup(self, payload: bytes, addr: tuple,
                            ctx: dict) -> bytes:
        """Handle SMB1 session setup (NTLMSSP negotiate/auth)."""
        ntlmssp_type = self._find_ntlmssp_type(payload)

        if ntlmssp_type == _NTLMSSP_NEGOTIATE:
            challenge_blob = self._build_ntlmssp_challenge()
            return self._smb1_session_setup_response(
                payload, _STATUS_MORE_PROCESSING, challenge_blob
            )

        elif ntlmssp_type == _NTLMSSP_AUTH:
            creds = self._parse_ntlmssp_auth(payload)
            session_id = self._ensure_session(addr, ctx)
            self._emit_auth_event(addr, session_id, creds)
            return self._smb1_session_setup_response(
                payload, _STATUS_LOGON_FAILURE, b""
            )

        challenge_blob = self._build_ntlmssp_challenge()
        return self._smb1_session_setup_response(
            payload, _STATUS_MORE_PROCESSING, challenge_blob
        )

    def _smb1_session_setup_response(self, request: bytes, status: int,
                                     security_blob: bytes) -> bytes:
        """Build SMB1 session setup response."""
        header = bytearray(32)
        header[0:4] = _SMB1_MAGIC
        header[4] = _SMB1_COM_SESSION_SETUP
        struct.pack_into("<I", header, 5, status)
        header[9] = 0x88
        struct.pack_into("<H", header, 10, 0xC853)
        if len(request) >= 32:
            header[24:32] = request[24:32]

        # Word count=4, params=8 bytes
        params = bytearray(8)
        struct.pack_into("<H", params, 0, 0)  # action
        struct.pack_into("<H", params, 2, len(security_blob))  # security blob length
        # padding
        struct.pack_into("<I", params, 4, 0)

        resp = bytearray()
        resp.append(4)  # word count
        resp.extend(params)
        byte_count = len(security_blob)
        resp.extend(struct.pack("<H", byte_count))
        resp.extend(security_blob)

        return bytes(header) + bytes(resp)

    def _smb1_tree_connect(self, payload: bytes, addr: tuple,
                           ctx: dict) -> bytes:
        """Handle SMB1 tree connect — log and reject."""
        share_name = self._extract_tree_path(payload)
        session_id = self._ensure_session(addr, ctx)
        self._emit_share_event(addr, session_id, share_name)

        header = bytearray(32)
        header[0:4] = _SMB1_MAGIC
        header[4] = _SMB1_COM_TREE_CONNECT
        struct.pack_into("<I", header, 5, _STATUS_BAD_NETWORK_NAME)
        header[9] = 0x88
        struct.pack_into("<H", header, 10, 0xC853)
        if len(payload) >= 32:
            header[24:32] = payload[24:32]

        resp = bytearray()
        resp.append(0)  # word count = 0
        resp.extend(struct.pack("<H", 0))  # byte count = 0

        return bytes(header) + bytes(resp)

    # ------------------------------------------------------------------
    # SMB2 handling
    # ------------------------------------------------------------------

    def _handle_smb2(self, payload: bytes, addr: tuple,
                     ctx: dict, smb_version: str) -> bytes | None:
        """Handle an SMB2 message and return a response."""
        if len(payload) < 64:
            return None

        command = struct.unpack_from("<H", payload, 12)[0]

        if command == _SMB2_COM_NEGOTIATE:
            self._emit_connection_event(addr, ctx, smb_version)
            return self._smb2_negotiate_response(payload)

        elif command == _SMB2_COM_SESSION_SETUP:
            return self._smb2_session_setup(payload, addr, ctx)

        elif command == _SMB2_COM_TREE_CONNECT:
            return self._smb2_tree_connect(payload, addr, ctx)

        return None

    def _smb2_negotiate_response(self, request: bytes) -> bytes:
        """Build SMB2 negotiate response."""
        header = bytearray(64)
        header[0:4] = _SMB2_MAGIC
        struct.pack_into("<H", header, 4, 64)  # structure size
        struct.pack_into("<H", header, 6, 0)  # credit charge
        struct.pack_into("<I", header, 8, _STATUS_SUCCESS)
        struct.pack_into("<H", header, 12, _SMB2_COM_NEGOTIATE)
        struct.pack_into("<H", header, 14, 1)  # credits granted
        struct.pack_into("<I", header, 16, 0x01)  # flags: response
        # Message ID from request
        if len(request) >= 28:
            header[24:32] = request[24:32]

        security_blob = self._build_spnego_init()

        # Negotiate response body (65 bytes + security blob)
        body = bytearray(65)
        struct.pack_into("<H", body, 0, 65)  # structure size
        struct.pack_into("<H", body, 2, 0x01)  # security mode: signing enabled
        struct.pack_into("<H", body, 4, 0x0202)  # dialect: SMB 2.0.2
        struct.pack_into("<H", body, 6, 0)  # negotiate context count
        # Server GUID (16 bytes)
        body[8:24] = os.urandom(16)
        struct.pack_into("<I", body, 24, 0x00000041)  # capabilities
        struct.pack_into("<I", body, 28, 8388608)  # max transact size
        struct.pack_into("<I", body, 32, 8388608)  # max read size
        struct.pack_into("<I", body, 36, 8388608)  # max write size
        # System time, start time (0)
        struct.pack_into("<Q", body, 40, 0)
        struct.pack_into("<Q", body, 48, 0)
        # Security buffer offset/length
        struct.pack_into("<H", body, 56, 64 + 65)  # offset from header start
        struct.pack_into("<H", body, 58, len(security_blob))

        return bytes(header) + bytes(body) + security_blob

    def _smb2_session_setup(self, payload: bytes, addr: tuple,
                            ctx: dict) -> bytes:
        """Handle SMB2 session setup (NTLMSSP flow)."""
        ntlmssp_type = self._find_ntlmssp_type(payload)

        if ntlmssp_type == _NTLMSSP_NEGOTIATE:
            challenge_blob = self._build_ntlmssp_challenge()
            return self._smb2_session_setup_response(
                payload, _STATUS_MORE_PROCESSING, challenge_blob
            )

        elif ntlmssp_type == _NTLMSSP_AUTH:
            creds = self._parse_ntlmssp_auth(payload)
            session_id = self._ensure_session(addr, ctx)
            self._emit_auth_event(addr, session_id, creds)
            return self._smb2_session_setup_response(
                payload, _STATUS_LOGON_FAILURE, b""
            )

        challenge_blob = self._build_ntlmssp_challenge()
        return self._smb2_session_setup_response(
            payload, _STATUS_MORE_PROCESSING, challenge_blob
        )

    def _smb2_session_setup_response(self, request: bytes, status: int,
                                     security_blob: bytes) -> bytes:
        """Build SMB2 session setup response."""
        header = bytearray(64)
        header[0:4] = _SMB2_MAGIC
        struct.pack_into("<H", header, 4, 64)
        struct.pack_into("<I", header, 8, status)
        struct.pack_into("<H", header, 12, _SMB2_COM_SESSION_SETUP)
        struct.pack_into("<H", header, 14, 1)  # credits
        struct.pack_into("<I", header, 16, 0x01)  # flags: response
        if len(request) >= 32:
            header[24:32] = request[24:32]

        # Session setup response body (9 bytes + security blob)
        body = bytearray(9)
        struct.pack_into("<H", body, 0, 9)  # structure size
        struct.pack_into("<H", body, 2, 0)  # session flags
        struct.pack_into("<H", body, 4, 64 + 9)  # security buffer offset
        struct.pack_into("<H", body, 6, len(security_blob))

        # Pad to align (body is 9 bytes, odd — pad 0 already in bytearray)
        return bytes(header) + bytes(body) + security_blob

    def _smb2_tree_connect(self, payload: bytes, addr: tuple,
                           ctx: dict) -> bytes:
        """Handle SMB2 tree connect — log and reject."""
        share_name = self._extract_tree_path(payload)
        session_id = self._ensure_session(addr, ctx)
        self._emit_share_event(addr, session_id, share_name)

        header = bytearray(64)
        header[0:4] = _SMB2_MAGIC
        struct.pack_into("<H", header, 4, 64)
        struct.pack_into("<I", header, 8, _STATUS_BAD_NETWORK_NAME)
        struct.pack_into("<H", header, 12, _SMB2_COM_TREE_CONNECT)
        struct.pack_into("<H", header, 14, 1)
        struct.pack_into("<I", header, 16, 0x01)
        if len(payload) >= 32:
            header[24:32] = payload[24:32]

        # Tree connect response body
        body = bytearray(16)
        struct.pack_into("<H", body, 0, 16)  # structure size
        body[2] = 0x01  # share type: disk
        struct.pack_into("<I", body, 4, 0)  # share flags
        struct.pack_into("<I", body, 8, _STATUS_ACCESS_DENIED)  # max access

        return bytes(header) + bytes(body)

    # ------------------------------------------------------------------
    # NTLMSSP helpers
    # ------------------------------------------------------------------

    def _build_spnego_init(self) -> bytes:
        """Build a minimal SPNEGO init token advertising NTLMSSP."""
        # Simplified: just the raw NTLMSSP OID wrapped in a minimal ASN.1
        # Real clients handle this well enough for honeypot purposes
        ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
        mech_list = b"\x30" + bytes([len(ntlmssp_oid)]) + ntlmssp_oid
        mech_types = b"\xa0" + bytes([len(mech_list)]) + mech_list
        neg_init = b"\x30" + bytes([len(mech_types)]) + mech_types
        spnego = b"\xa0" + bytes([len(neg_init) + 2]) + b"\x06\x06\x2b\x06\x01\x05\x05\x02" + b"\xa0" + bytes([len(neg_init)]) + neg_init

        return spnego

    def _build_ntlmssp_challenge(self) -> bytes:
        """Build NTLMSSP Type 2 (challenge) message."""
        target_name = self.domain.encode("utf-16-le")

        # Build target info
        target_info = bytearray()
        # Domain name (MsvAvNbDomainName = 0x0002)
        domain_bytes = self.domain.encode("utf-16-le")
        target_info.extend(struct.pack("<HH", 0x0002, len(domain_bytes)))
        target_info.extend(domain_bytes)
        # Server name (MsvAvNbComputerName = 0x0001)
        server_bytes = self.server_name.encode("utf-16-le")
        target_info.extend(struct.pack("<HH", 0x0001, len(server_bytes)))
        target_info.extend(server_bytes)
        # Terminator (MsvAvEOL = 0x0000)
        target_info.extend(struct.pack("<HH", 0x0000, 0))

        # NTLMSSP challenge message
        msg = bytearray()
        msg.extend(_NTLMSSP_SIGNATURE)
        struct.pack_into("<I", msg, len(msg) - 4, 0)  # fix: rewrite
        msg = bytearray(_NTLMSSP_SIGNATURE)
        msg.extend(struct.pack("<I", _NTLMSSP_CHALLENGE))

        # Target name fields (offset computed after header)
        target_name_offset = 56  # fixed offset for Type 2
        msg.extend(struct.pack("<HHI", len(target_name), len(target_name), target_name_offset))

        # Negotiate flags
        msg.extend(struct.pack("<I", _NTLMSSP_FLAGS))

        # Server challenge
        msg.extend(self._challenge)

        # Reserved (8 bytes)
        msg.extend(b"\x00" * 8)

        # Target info fields
        target_info_offset = target_name_offset + len(target_name)
        msg.extend(struct.pack("<HHI", len(target_info), len(target_info), target_info_offset))

        # Pad to offset if needed
        while len(msg) < target_name_offset:
            msg.append(0)

        msg.extend(target_name)
        msg.extend(target_info)

        return bytes(msg)

    def _find_ntlmssp_type(self, payload: bytes) -> int | None:
        """Find NTLMSSP message type in an SMB payload."""
        idx = payload.find(_NTLMSSP_SIGNATURE)
        if idx < 0 or idx + 12 > len(payload):
            return None
        return struct.unpack_from("<I", payload, idx + 8)[0]

    def _parse_ntlmssp_auth(self, payload: bytes) -> dict:
        """Parse NTLMSSP Type 3 (authenticate) and extract credentials."""
        creds: dict = {
            "domain": "",
            "username": "",
            "workstation": "",
        }

        idx = payload.find(_NTLMSSP_SIGNATURE)
        if idx < 0 or idx + 72 > len(payload):
            return creds

        base = idx
        # Type 3 layout after signature (8) + type (4):
        # LmChallengeResponse: 8 bytes (offset 12)
        # NtChallengeResponse: 8 bytes (offset 20)
        # DomainName: 8 bytes (offset 28)
        # UserName: 8 bytes (offset 36)
        # Workstation: 8 bytes (offset 44)

        try:
            domain_len, _, domain_off = struct.unpack_from("<HHI", payload, base + 28)
            user_len, _, user_off = struct.unpack_from("<HHI", payload, base + 36)
            ws_len, _, ws_off = struct.unpack_from("<HHI", payload, base + 44)

            if domain_len > 0 and base + domain_off + domain_len <= len(payload):
                creds["domain"] = payload[base + domain_off:base + domain_off + domain_len].decode("utf-16-le", errors="replace")

            if user_len > 0 and base + user_off + user_len <= len(payload):
                creds["username"] = payload[base + user_off:base + user_off + user_len].decode("utf-16-le", errors="replace")

            if ws_len > 0 and base + ws_off + ws_len <= len(payload):
                creds["workstation"] = payload[base + ws_off:base + ws_off + ws_len].decode("utf-16-le", errors="replace")
        except (struct.error, UnicodeDecodeError):
            pass

        return creds

    def _extract_tree_path(self, payload: bytes) -> str:
        """Try to extract the share path from a tree connect request."""
        # Look for \\server\share pattern in UTF-16LE
        try:
            # Search for the \\ prefix in UTF-16LE
            marker = b"\x5c\x00\x5c\x00"  # \\  in UTF-16LE
            idx = payload.find(marker)
            if idx >= 0:
                # Read until null terminator or end
                end = payload.find(b"\x00\x00\x00", idx)
                if end > idx:
                    raw = payload[idx:end + 1]  # include one null for alignment
                else:
                    raw = payload[idx:min(idx + 256, len(payload))]
                return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    def _emit_connection_event(self, addr: tuple, ctx: dict,
                               smb_version: str) -> None:
        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "connection",
                "protocol": "smb",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": "low",
                "session_id": ctx["session_id"],
                "details": {
                    "smb_version": smb_version,
                    "server_name": self.server_name,
                },
            })

    def _emit_auth_event(self, addr: tuple, session_id: str | None,
                         creds: dict) -> None:
        logger.info(
            "SMB auth  domain=%s  user=%s  workstation=%s  from=%s",
            creds.get("domain", ""),
            creds.get("username", ""),
            creds.get("workstation", ""),
            addr[0],
        )

        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "authentication",
                "protocol": "smb",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": "high",
                "session_id": session_id,
                "details": {
                    "domain": creds.get("domain", ""),
                    "username": creds.get("username", ""),
                    "workstation": creds.get("workstation", ""),
                },
            })

        if self.session_recorder and session_id:
            self.session_recorder.record_command(
                session_id,
                f"NTLMSSP_AUTH domain={creds.get('domain', '')} user={creds.get('username', '')}",
                datetime.now(timezone.utc),
            )

    def _emit_share_event(self, addr: tuple, session_id: str | None,
                          share_name: str) -> None:
        logger.info("SMB share access  share=%s  from=%s", share_name, addr[0])

        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "share_access",
                "protocol": "smb",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": "medium",
                "session_id": session_id,
                "details": {"share_name": share_name},
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
