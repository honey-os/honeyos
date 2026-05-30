"""Tests for backend/services/protocols/rdp_honeypot.py"""

import socket
import struct
import threading
import time

from services.protocols.rdp_honeypot import RDPHoneypot


def _make_rdp():
    return RDPHoneypot(port=0, config={"server_name": "TESTPC"})


class TestBuildX224CC:
    def test_length_is_19_bytes(self):
        hp = _make_rdp()
        cc = hp._build_x224_cc()
        assert len(cc) == 19

    def test_tpkt_header(self):
        hp = _make_rdp()
        cc = hp._build_x224_cc()
        assert cc[0] == 3  # TPKT version
        assert cc[1] == 0  # reserved
        total_len = struct.unpack(">H", cc[2:4])[0]
        assert total_len == 19

    def test_x224_type_is_cc(self):
        hp = _make_rdp()
        cc = hp._build_x224_cc()
        # X.224 type at byte 5 (upper nibble = 0xD0 >> 4 = 13)
        assert (cc[5] >> 4) == (0xD0 >> 4)

    def test_rdp_neg_response(self):
        hp = _make_rdp()
        cc = hp._build_x224_cc()
        # RDP Negotiation Response starts at byte 11
        assert cc[11] == 0x02  # type: RDP_NEG_RSP
        neg_len = struct.unpack_from("<H", cc, 13)[0]
        assert neg_len == 8
        selected_proto = struct.unpack_from("<I", cc, 15)[0]
        assert selected_proto == 0  # PROTOCOL_RDP


class TestParseX224CR:
    def _build_cr_payload(self, username="testuser", protocols=0x00000003):
        """Build a minimal X.224 CR payload (without TPKT header)."""
        # X.224 header: length indicator, type (0xE0), dst-ref, src-ref, class
        x224_hdr = bytearray(6)
        x224_hdr[1] = 0xE0  # type: Connection Request

        # Cookie
        cookie = f"Cookie: mstshash={username}\r\n".encode()

        # RDP Negotiation Request (8 bytes)
        neg_req = bytearray(8)
        neg_req[0] = 0x01  # type
        neg_req[1] = 0x00  # flags
        struct.pack_into("<H", neg_req, 2, 8)  # length
        struct.pack_into("<I", neg_req, 4, protocols)

        payload = bytes(x224_hdr) + cookie + bytes(neg_req)
        # Update length indicator
        payload = bytes([len(payload) - 1]) + payload[1:]
        return payload

    def test_extracts_username(self):
        hp = _make_rdp()
        payload = self._build_cr_payload(username="administrator")
        result = hp._parse_x224_cr(payload)
        assert result is not None
        assert result["username"] == "administrator"

    def test_extracts_requested_protocols(self):
        hp = _make_rdp()
        payload = self._build_cr_payload(protocols=0x00000003)
        result = hp._parse_x224_cr(payload)
        assert result is not None
        assert result["requested_protocols"] == 3  # HYBRID (CredSSP)

    def test_no_cookie(self):
        hp = _make_rdp()
        # Payload with X.224 header but no cookie, just negotiation request
        x224_hdr = bytearray(6)
        x224_hdr[1] = 0xE0
        neg_req = bytearray(8)
        neg_req[0] = 0x01
        struct.pack_into("<H", neg_req, 2, 8)
        struct.pack_into("<I", neg_req, 4, 0)
        payload = bytes(x224_hdr) + bytes(neg_req)
        result = hp._parse_x224_cr(payload)
        assert result is not None
        assert result["username"] == ""

    def test_rejects_non_cr(self):
        hp = _make_rdp()
        # Not a Connection Request (wrong type nibble)
        payload = bytearray(6)
        payload[1] = 0x50  # wrong type
        assert hp._parse_x224_cr(bytes(payload)) is None

    def test_rejects_short_payload(self):
        hp = _make_rdp()
        assert hp._parse_x224_cr(b"\x00\x00\x00") is None


class TestFindNegRequest:
    def test_finds_at_end(self):
        neg_req = bytearray(8)
        neg_req[0] = 0x01  # type
        struct.pack_into("<H", neg_req, 2, 8)  # length = 8
        struct.pack_into("<I", neg_req, 4, 0x00000001)

        data = b"some prefix data" + bytes(neg_req)
        result = RDPHoneypot._find_neg_request(data)
        assert result is not None
        assert result == len(data) - 8

    def test_returns_none_when_absent(self):
        data = b"no negotiation request here at all"
        assert RDPHoneypot._find_neg_request(data) is None

    def test_empty_data(self):
        assert RDPHoneypot._find_neg_request(b"") is None


class TestRDPIntegration:
    """Integration test: start RDP listener on port 0, send X.224 CR, verify CC."""

    def test_x224_handshake(self):
        hp = RDPHoneypot(port=0, config={"server_name": "TESTPC"})

        # Bind to port 0 to get an ephemeral port
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]

        response_data = []
        error = []

        def _server():
            try:
                conn, addr = server_sock.accept()
                conn.settimeout(5)
                # Read TPKT header
                tpkt = conn.recv(4)
                if not tpkt or len(tpkt) < 4:
                    return
                pkt_len = struct.unpack(">H", tpkt[2:4])[0]
                payload = conn.recv(pkt_len - 4)
                # Parse and respond
                cr_info = hp._parse_x224_cr(payload)
                if cr_info:
                    cc = hp._build_x224_cc()
                    conn.sendall(cc)
                conn.close()
            except Exception as e:
                error.append(e)
            finally:
                server_sock.close()

        t = threading.Thread(target=_server, daemon=True)
        t.start()

        # Build X.224 Connection Request
        x224_hdr = bytearray(6)
        x224_hdr[1] = 0xE0
        cookie = b"Cookie: mstshash=testuser\r\n"
        neg_req = bytearray(8)
        neg_req[0] = 0x01
        struct.pack_into("<H", neg_req, 2, 8)
        struct.pack_into("<I", neg_req, 4, 0)
        cr_body = bytes(x224_hdr) + cookie + bytes(neg_req)

        # TPKT header
        tpkt = bytearray(4)
        tpkt[0] = 3
        tpkt[1] = 0
        struct.pack_into(">H", tpkt, 2, 4 + len(cr_body))

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect(("127.0.0.1", port))
        client.sendall(bytes(tpkt) + cr_body)

        # Read CC response
        response = b""
        try:
            while True:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        client.close()
        t.join(timeout=5)

        assert not error, f"Server error: {error}"
        assert len(response) == 19
        assert response[0] == 3  # TPKT version
        assert (response[5] >> 4) == (0xD0 >> 4)  # X.224 CC
