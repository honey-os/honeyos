"""Tests for backend/services/protocols/smb_honeypot.py"""

import struct

from services.protocols.smb_honeypot import SMBHoneypot


def _make_smb():
    return SMBHoneypot(
        port=0,
        config={"server_name": "TESTSERVER", "domain": "TESTDOMAIN"},
    )


class TestFindNtlmsspType:
    def test_finds_negotiate(self):
        hp = _make_smb()
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 1)  # NEGOTIATE
        payload = b"\x00" * 20 + signature + msg_type
        result = hp._find_ntlmssp_type(payload)
        assert result == 1

    def test_finds_auth(self):
        hp = _make_smb()
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 3)  # AUTH
        payload = b"\x00" * 10 + signature + msg_type
        result = hp._find_ntlmssp_type(payload)
        assert result == 3

    def test_no_ntlmssp(self):
        hp = _make_smb()
        payload = b"\x00" * 50
        assert hp._find_ntlmssp_type(payload) is None

    def test_truncated_payload(self):
        hp = _make_smb()
        payload = b"NTLMSSP\x00"  # no type field following
        assert hp._find_ntlmssp_type(payload) is None


class TestBuildNtlmsspChallenge:
    def test_contains_signature(self):
        hp = _make_smb()
        challenge = hp._build_ntlmssp_challenge()
        assert b"NTLMSSP\x00" in challenge

    def test_message_type_is_challenge(self):
        hp = _make_smb()
        challenge = hp._build_ntlmssp_challenge()
        idx = challenge.find(b"NTLMSSP\x00")
        msg_type = struct.unpack_from("<I", challenge, idx + 8)[0]
        assert msg_type == 2  # CHALLENGE

    def test_contains_server_challenge_bytes(self):
        hp = _make_smb()
        challenge = hp._build_ntlmssp_challenge()
        # Challenge is 8 bytes, should be present
        assert len(challenge) > 32  # minimum expected size

    def test_contains_domain_in_target_info(self):
        hp = _make_smb()
        challenge = hp._build_ntlmssp_challenge()
        # Domain should be encoded as UTF-16LE somewhere in the message
        domain_le = "TESTDOMAIN".encode("utf-16-le")
        assert domain_le in challenge


class TestParseNtlmsspAuth:
    def test_extracts_credentials(self):
        hp = _make_smb()
        # Build a minimal Type 3 (Auth) message
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 3)

        domain = "TESTDOMAIN".encode("utf-16-le")
        username = "admin".encode("utf-16-le")
        workstation = "WORKPC".encode("utf-16-le")

        # Fixed header through workstation fields = 12 + 8*6 = 60 bytes
        # but _parse_ntlmssp_auth checks base + 72, so we need enough space
        # LmChallenge: offset 12 (8 bytes)
        # NtChallenge: offset 20 (8 bytes)
        # Domain: offset 28 (8 bytes)
        # User: offset 36 (8 bytes)
        # Workstation: offset 44 (8 bytes)
        # EncSession: offset 52 (8 bytes)
        # NegFlags: offset 60 (4 bytes)

        data_offset = 72  # data starts after the fixed fields

        # Build with proper offsets (offsets are relative to NTLMSSP start in payload)
        domain_off = data_offset
        user_off = domain_off + len(domain)
        ws_off = user_off + len(username)

        auth_msg = bytearray(ws_off + len(workstation))
        off = 0
        auth_msg[off:off + 8] = signature
        off += 8
        auth_msg[off:off + 4] = msg_type
        off += 4
        # LmChallengeResponse (len, maxlen, offset)
        struct.pack_into("<HHI", auth_msg, off, 0, 0, 0)
        off += 8
        # NtChallengeResponse
        struct.pack_into("<HHI", auth_msg, off, 0, 0, 0)
        off += 8
        # Domain
        struct.pack_into("<HHI", auth_msg, off, len(domain), len(domain), domain_off)
        off += 8
        # UserName
        struct.pack_into("<HHI", auth_msg, off, len(username), len(username), user_off)
        off += 8
        # Workstation
        struct.pack_into("<HHI", auth_msg, off, len(workstation), len(workstation), ws_off)

        # Place data
        auth_msg[domain_off:domain_off + len(domain)] = domain
        auth_msg[user_off:user_off + len(username)] = username
        auth_msg[ws_off:ws_off + len(workstation)] = workstation

        # Wrap in a payload with some prefix (simulating SMB header)
        payload = b"\x00" * 10 + bytes(auth_msg)
        creds = hp._parse_ntlmssp_auth(payload)
        assert creds["domain"] == "TESTDOMAIN"
        assert creds["username"] == "admin"
        assert creds["workstation"] == "WORKPC"

    def test_empty_payload(self):
        hp = _make_smb()
        creds = hp._parse_ntlmssp_auth(b"")
        assert creds["username"] == ""
        assert creds["domain"] == ""


class TestBuildSpnegoInit:
    def test_contains_ntlmssp_oid(self):
        hp = _make_smb()
        token = hp._build_spnego_init()
        # NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
        ntlmssp_oid = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
        assert ntlmssp_oid in token

    def test_is_valid_asn1(self):
        hp = _make_smb()
        token = hp._build_spnego_init()
        # Should start with ASN.1 context tag 0xa0
        assert token[0] == 0xA0


class TestExtractTreePath:
    def test_extracts_utf16_share_path(self):
        hp = _make_smb()
        # Build a payload with \\SERVER\share in UTF-16LE
        share_path = "\\\\SERVER\\share"
        encoded = share_path.encode("utf-16-le") + b"\x00\x00\x00"
        payload = b"\x00" * 20 + encoded
        result = hp._extract_tree_path(payload)
        assert "SERVER" in result
        assert "share" in result

    def test_no_share_path(self):
        hp = _make_smb()
        result = hp._extract_tree_path(b"\x00" * 50)
        assert result == "unknown"
