"""Tests for backend/services/protocols/rdp_honeypot.py"""

import socket
import struct
import threading
import time

from cryptography.hazmat.primitives.asymmetric import padding

from services.protocols.rdp_honeypot import (
    RDPHoneypot,
    _build_mcs_attach_user_confirm,
    _build_mcs_channel_join_confirm,
    _build_mcs_connect_response,
    _build_proprietary_cert,
    _derive_keys,
    _generate_rsa_512,
    _parse_client_info,
    _parse_security_exchange,
    _parse_ts_info_packet,
    _rc4,
    _INFO_UNICODE,
    _TPKT_VERSION,
)


def _make_rdp():
    return RDPHoneypot(port=0, config={"server_name": "TESTPC"})


# ======================================================================
# Existing tests (X.224 layer)
# ======================================================================

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


# ======================================================================
# New tests: crypto primitives
# ======================================================================

class TestRSA512:
    """Test 512-bit RSA key generation and basic operations."""

    def test_key_generates_at_512_bits(self):
        key = _generate_rsa_512()
        pub = key.public_key().public_numbers()
        bit_length = pub.n.bit_length()
        # Allow 511-512 due to how primes can work out
        assert 511 <= bit_length <= 512

    def test_pkcs1v15_roundtrip(self):
        key = _generate_rsa_512()
        plaintext = b"A" * 32  # 32-byte client_random
        ciphertext = key.public_key().encrypt(plaintext, padding.PKCS1v15())
        decrypted = key.decrypt(ciphertext, padding.PKCS1v15())
        assert decrypted == plaintext

    def test_different_keys_are_different(self):
        k1 = _generate_rsa_512()
        k2 = _generate_rsa_512()
        n1 = k1.public_key().public_numbers().n
        n2 = k2.public_key().public_numbers().n
        assert n1 != n2


class TestRC4:
    """Test manual RC4 implementation."""

    def test_encrypt_decrypt_roundtrip(self):
        key = b"secretkey"
        plaintext = b"Hello, RDP honeypot world!"
        ciphertext = _rc4(key, plaintext)
        assert ciphertext != plaintext
        decrypted = _rc4(key, ciphertext)
        assert decrypted == plaintext

    def test_known_vector(self):
        # RFC 6229 / well-known: RC4("Key", "Plaintext") test
        key = b"Key"
        plaintext = b"Plaintext"
        ciphertext = _rc4(key, plaintext)
        # RC4("Key", "Plaintext") = BBF316E8D940AF0AD3
        expected = bytes.fromhex("BBF316E8D940AF0AD3")
        assert ciphertext == expected

    def test_empty_data(self):
        assert _rc4(b"key", b"") == b""


class TestKeyDerivation:
    """Test session key derivation."""

    def test_produces_16_byte_keys(self):
        cr = b"\x01" * 32
        sr = b"\x02" * 32
        mac_key, decrypt_key = _derive_keys(cr, sr)
        assert len(mac_key) == 16
        assert len(decrypt_key) == 16

    def test_different_randoms_different_keys(self):
        cr1, sr1 = b"\x01" * 32, b"\x02" * 32
        cr2, sr2 = b"\x03" * 32, b"\x04" * 32
        _, dk1 = _derive_keys(cr1, sr1)
        _, dk2 = _derive_keys(cr2, sr2)
        assert dk1 != dk2

    def test_deterministic(self):
        cr = b"\xAA" * 32
        sr = b"\xBB" * 32
        _, dk1 = _derive_keys(cr, sr)
        _, dk2 = _derive_keys(cr, sr)
        assert dk1 == dk2


# ======================================================================
# New tests: PDU builders
# ======================================================================

class TestProprietaryCert:
    """Test proprietary certificate builder."""

    def test_contains_rsa1_magic(self):
        key = _generate_rsa_512()
        cert = _build_proprietary_cert(key)
        assert b"RSA1" in cert

    def test_modulus_is_64_bytes(self):
        key = _generate_rsa_512()
        cert = _build_proprietary_cert(key)
        # Find RSA1 magic, then check modulus length
        idx = cert.index(b"RSA1")
        # After RSA1: bitLen(4) + exponent(4) = 8 bytes, then modulus
        bit_len = struct.unpack_from("<I", cert, idx + 4)[0]
        assert bit_len == 512
        # Modulus starts at idx + 12, should be 64 bytes (512/8)
        modulus = cert[idx + 12:idx + 12 + 64]
        assert len(modulus) == 64


class TestMCSConnectResponse:
    """Test MCS Connect Response builder."""

    def test_valid_tpkt_header(self):
        key = _generate_rsa_512()
        sr = b"\x11" * 32
        resp = _build_mcs_connect_response(sr, key, [1004, 1005])
        assert resp[0] == _TPKT_VERSION
        pkt_len = struct.unpack(">H", resp[2:4])[0]
        assert pkt_len == len(resp)

    def test_contains_server_random(self):
        key = _generate_rsa_512()
        sr = b"\xDE\xAD" * 16  # distinctive 32 bytes
        resp = _build_mcs_connect_response(sr, key, [1004])
        assert sr in resp

    def test_contains_rsa_modulus(self):
        key = _generate_rsa_512()
        pub = key.public_key().public_numbers()
        modulus_le = pub.n.to_bytes(64, "little")
        sr = b"\x00" * 32
        resp = _build_mcs_connect_response(sr, key, [1004])
        assert modulus_le in resp


class TestAttachUserConfirm:
    """Test MCS Attach User Confirm builder."""

    def test_correct_structure(self):
        pdu = _build_mcs_attach_user_confirm(1007)
        assert pdu[0] == _TPKT_VERSION
        pkt_len = struct.unpack(">H", pdu[2:4])[0]
        assert pkt_len == len(pdu)
        # X.224 data header
        assert pdu[4] == 0x02
        assert pdu[5] == 0xF0
        # MCS tag
        assert pdu[7] == 0x2E  # AttachUserConfirm
        assert pdu[8] == 0x00  # result: success
        # initiator = 1007 - 1001 = 6
        initiator = struct.unpack(">H", pdu[9:11])[0]
        assert initiator == 6


class TestChannelJoinConfirm:
    """Test MCS Channel Join Confirm builder."""

    def test_correct_length(self):
        pdu = _build_mcs_channel_join_confirm(1007, 1003)
        assert pdu[0] == _TPKT_VERSION
        pkt_len = struct.unpack(">H", pdu[2:4])[0]
        assert pkt_len == len(pdu)
        # TPKT(4) + X.224(3) + PER(8) = 15
        # PER: tag(1) + result(1) + initiator(2) + requested(2) + joined(2)
        assert len(pdu) == 15

    def test_echoes_channel_id(self):
        pdu = _build_mcs_channel_join_confirm(1007, 1003)
        # Channel IDs in the PER payload (after TPKT+X.224 = 7 bytes)
        # tag(1) + result(1) + initiator(2) + requested(2) + joined(2)
        requested = struct.unpack(">H", pdu[11:13])[0]
        joined = struct.unpack(">H", pdu[13:15])[0]
        assert requested == 1003
        assert joined == 1003


# ======================================================================
# New tests: PDU parsers
# ======================================================================

class TestSecurityExchangeParsing:
    """Test Security Exchange PDU parsing."""

    def test_roundtrip_with_known_client_random(self):
        """Build a Security Exchange with a known client_random,
        verify the parser recovers it."""
        key = _generate_rsa_512()
        client_random = b"\x42" * 32

        # Encrypt client_random with the RSA public key
        # RDP sends little-endian, so we reverse after standard encryption
        ciphertext_be = key.public_key().encrypt(client_random, padding.PKCS1v15())
        ciphertext_le = bytes(reversed(ciphertext_be))

        # Build a minimal Security Exchange PDU
        # TPKT(4) + X.224(3) + MCS SendDataRequest header + security data
        mcs_header = bytearray()
        mcs_header.append(0x64)  # SendDataRequest tag
        mcs_header += struct.pack(">H", 6)  # initiator (1007 - 1001)
        mcs_header += struct.pack(">H", 1003)  # channelId (I/O)
        mcs_header.append(0x70)  # dataPriority + segmentation

        # Security data: flags(2) + flagsHi(2) + length(4) + blob
        sec_data = struct.pack("<H", 0x0001)  # SEC_EXCHANGE_PKT
        sec_data += struct.pack("<H", 0x0000)  # flagsHi
        sec_data += struct.pack("<I", len(ciphertext_le))
        sec_data += ciphertext_le

        # PER length of sec_data
        ud_len = len(sec_data)
        if ud_len >= 0x80:
            mcs_header += struct.pack(">H", ud_len | 0x8000)
        else:
            mcs_header.append(ud_len)

        payload = bytes(mcs_header) + sec_data
        x224_data = b"\x02\xf0\x80"
        total_len = 4 + len(x224_data) + len(payload)
        tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, total_len)
        pdu = tpkt + x224_data + payload

        result = _parse_security_exchange(pdu, key)
        assert result is not None
        assert result == client_random

    def test_malformed_returns_none(self):
        key = _generate_rsa_512()
        assert _parse_security_exchange(b"\x03\x00\x00\x08\x02\xf0\x80\x00", key) is None

    def test_too_short_returns_none(self):
        key = _generate_rsa_512()
        assert _parse_security_exchange(b"\x03\x00\x00\x04", key) is None


class TestClientInfoParsing:
    """Test Client Info PDU parsing (TS_INFO_PACKET)."""

    def _build_ts_info_packet(self, domain="WORKGROUP", username="admin",
                               password="pass123", unicode=True):
        """Build a raw TS_INFO_PACKET."""
        flags = _INFO_UNICODE if unicode else 0x0000
        encoding = "utf-16-le" if unicode else "ascii"
        null = b"\x00\x00" if unicode else b"\x00"

        domain_bytes = domain.encode(encoding)
        username_bytes = username.encode(encoding)
        password_bytes = password.encode(encoding)
        alt_shell = b""
        working_dir = b""

        header = struct.pack("<I", 0)  # codePage
        header += struct.pack("<I", flags)
        header += struct.pack("<H", len(domain_bytes))
        header += struct.pack("<H", len(username_bytes))
        header += struct.pack("<H", len(password_bytes))
        header += struct.pack("<H", len(alt_shell))
        header += struct.pack("<H", len(working_dir))

        body = domain_bytes + null
        body += username_bytes + null
        body += password_bytes + null
        body += alt_shell + null
        body += working_dir + null

        return header + body

    def _build_encrypted_client_info_pdu(self, ts_info, encrypt_key):
        """Wrap a TS_INFO_PACKET in a full encrypted Client Info PDU."""
        encrypted = _rc4(encrypt_key, ts_info)

        # Security header: SEC_INFO_PKT (0x0040) + flagsHi + 8-byte MAC
        sec_header = struct.pack("<H", 0x0040)
        sec_header += struct.pack("<H", 0x0000)
        sec_header += b"\x00" * 8  # fake MAC

        # MCS SendDataRequest header
        mcs_header = bytearray()
        mcs_header.append(0x64)  # SendDataRequest
        mcs_header += struct.pack(">H", 6)  # initiator
        mcs_header += struct.pack(">H", 1003)  # channelId
        mcs_header.append(0x70)  # priority/segmentation

        payload = sec_header + encrypted
        ud_len = len(payload)
        if ud_len >= 0x80:
            mcs_header += struct.pack(">H", ud_len | 0x8000)
        else:
            mcs_header.append(ud_len)

        inner = bytes(mcs_header) + payload
        x224_data = b"\x02\xf0\x80"
        total_len = 4 + len(x224_data) + len(inner)
        tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, total_len)
        return tpkt + x224_data + inner

    def test_unicode_credentials(self):
        ts_info = self._build_ts_info_packet(
            domain="CORP", username="admin", password="P@ssw0rd", unicode=True
        )
        key = b"\xAA" * 16
        pdu = self._build_encrypted_client_info_pdu(ts_info, key)
        result = _parse_client_info(pdu, key)
        assert result is not None
        assert result["username"] == "admin"
        assert result["password"] == "P@ssw0rd"
        assert result["domain"] == "CORP"

    def test_ascii_credentials(self):
        ts_info = self._build_ts_info_packet(
            domain="LOCAL", username="root", password="toor", unicode=False
        )
        key = b"\xBB" * 16
        pdu = self._build_encrypted_client_info_pdu(ts_info, key)
        result = _parse_client_info(pdu, key)
        assert result is not None
        assert result["username"] == "root"
        assert result["password"] == "toor"
        assert result["domain"] == "LOCAL"

    def test_empty_password(self):
        ts_info = self._build_ts_info_packet(
            domain="", username="scanner", password="", unicode=True
        )
        key = b"\xCC" * 16
        pdu = self._build_encrypted_client_info_pdu(ts_info, key)
        result = _parse_client_info(pdu, key)
        assert result is not None
        assert result["username"] == "scanner"
        assert result["password"] == ""

    def test_ts_info_packet_direct_parse(self):
        """Test _parse_ts_info_packet directly without encryption."""
        ts_info = self._build_ts_info_packet(
            domain="TEST", username="user1", password="secret", unicode=True
        )
        result = _parse_ts_info_packet(ts_info)
        assert result is not None
        assert result["domain"] == "TEST"
        assert result["username"] == "user1"
        assert result["password"] == "secret"

    def test_too_short_returns_none(self):
        assert _parse_ts_info_packet(b"\x00" * 10) is None
