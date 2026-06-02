"""
RDPHoneypot -- fake RDP server capturing connection attempts, username
extraction from X.224 cookies, and credential capture via the Standard
RDP Security handshake (MCS Connect → Security Exchange → Client Info).

Implements the full negotiation path through the Client Info PDU where
brute-force tools transmit username/password pairs (RC4-encrypted with
keys we control via a 512-bit RSA handshake).
"""

import hashlib
import logging
import os
import secrets
import socket
import ssl
import struct
import threading
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
)

from utils.tls import ensure_self_signed_cert

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

# MCS / T.125 constants
_MCS_CONNECT_INITIAL = 0x7F65  # BER tag for MCS-Connect-Initial
_MCS_CONNECT_RESPONSE = 0x7F66  # BER tag for MCS-Connect-Response
_MCS_ERECT_DOMAIN = 0x04  # PER domain-MCSPDUs choice index
_MCS_ATTACH_USER_REQUEST = 0x28  # PER choice
_MCS_ATTACH_USER_CONFIRM = 0x2E  # PER choice
_MCS_CHANNEL_JOIN_REQUEST = 0x38  # PER choice
_MCS_CHANNEL_JOIN_CONFIRM = 0x3E  # PER choice

# Channel IDs
_IO_CHANNEL = 1003
_USER_CHANNEL_BASE = 1007

# Client Info flags
_INFO_UNICODE = 0x0010


# ======================================================================
# Crypto helpers
# ======================================================================

def _is_probably_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with *k* rounds."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime of *bits* bit-length."""
    while True:
        candidate = int.from_bytes(os.urandom(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | 1  # set high bit + odd
        if _is_probably_prime(candidate):
            return candidate


def _generate_rsa_512():
    """Generate a 512-bit RSA key via RSAPrivateNumbers.

    The ``cryptography`` library enforces 1024-bit minimum on
    ``generate_private_key()``, but ``RSAPrivateNumbers.private_key()``
    accepts any size -- which is exactly what we need for the proprietary
    RDP certificate format.
    """
    e = 65537
    while True:
        p = _generate_prime(256)
        q = _generate_prime(256)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        dp = rsa_crt_dmp1(d, p)
        dq = rsa_crt_dmq1(d, q)
        iq = rsa_crt_iqmp(p, q)
        pub = RSAPublicNumbers(e, n)
        priv = RSAPrivateNumbers(p, q, d, dp, dq, iq, pub)
        return priv.private_key()


def _rc4(key: bytes, data: bytes) -> bytes:
    """RC4 encrypt/decrypt (KSA + PRGA)."""
    # Key-Scheduling Algorithm
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # Pseudo-Random Generation Algorithm
    out = bytearray(len(data))
    i = j = 0
    for idx in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[idx] = data[idx] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


def _salted_hash(salt: bytes, input_data: bytes,
                 client_random: bytes, server_random: bytes) -> bytes:
    """SaltedHash per MS-RDPBCGR 5.3.5."""
    sha1 = hashlib.sha1(input_data + salt + client_random + server_random).digest()
    return hashlib.md5(salt + sha1).digest()


def _derive_keys(client_random: bytes, server_random: bytes):
    """Derive (mac_key, decrypt_key) from client_random + server_random.

    Follows MS-RDPBCGR 5.3.5 for 128-bit encryption level.
    Returns (mac_key_16, decrypt_key_16).
    """
    pre_master = client_random[:24] + server_random[:24]

    master = (
        _salted_hash(pre_master, b"A", client_random, server_random)
        + _salted_hash(pre_master, b"BB", client_random, server_random)
        + _salted_hash(pre_master, b"CCC", client_random, server_random)
    )

    session_blob = (
        _salted_hash(master, b"X", client_random, server_random)
        + _salted_hash(master, b"YY", client_random, server_random)
        + _salted_hash(master, b"ZZZ", client_random, server_random)
    )

    mac_key = session_blob[:16]
    # For 128-bit: final key = MD5(key_material + key_material)
    decrypt_key = hashlib.md5(
        session_blob[16:32] + session_blob[16:32]
    ).digest()

    return mac_key, decrypt_key


# ======================================================================
# PDU builders
# ======================================================================

def _build_proprietary_cert(rsa_key) -> bytes:
    """Build a SERVER_CERTIFICATE (proprietary format) containing the
    RSA public key.  Signature is zero-filled -- most brute-force tools
    skip validation.
    """
    pub = rsa_key.public_key().public_numbers()
    modulus_bytes = pub.n.to_bytes(64, "little")
    exponent = pub.e

    # RSAPUBKEY structure
    rsa_pub = struct.pack("<4sII", b"RSA1", 512, exponent)
    rsa_pub += modulus_bytes
    rsa_pub += b"\x00" * 8  # 8 zero padding bytes

    # SERVER_PUBLIC_KEY_DATA
    key_blob = struct.pack("<II", 0x00000006, len(rsa_pub))  # magic SEC_RSA, length
    key_blob += rsa_pub

    # Signature (zero-filled, 72 bytes: 8 header + 64 sig)
    sig_data = b"\x00" * 64
    sig_blob = struct.pack("<II", 0x00000008, len(sig_data))
    sig_blob += sig_data
    sig_blob += b"\x00" * 8  # padding

    # PROPRIETARYSERVERCERTIFICATE
    cert = struct.pack("<II", 0x00000001, 0x00000001)  # dwVersion, dwSigAlgId
    cert += struct.pack("<I", 0x00000001)  # dwKeyAlgId
    cert += struct.pack("<H", len(key_blob))  # wPublicKeyBlobLen
    cert += key_blob
    cert += struct.pack("<H", len(sig_blob))  # wSignatureBlobLen
    cert += sig_blob

    return cert


def _build_sc_security(server_random: bytes, rsa_key) -> bytes:
    """SC_SECURITY block: encryption method/level, server random, cert."""
    cert = _build_proprietary_cert(rsa_key)

    data = struct.pack("<II", 0x00000002, 0x00000002)  # 128-bit, CLIENT_COMPATIBLE
    data += struct.pack("<I", 32)  # serverRandomLen
    data += struct.pack("<I", len(cert))  # serverCertLen
    data += server_random
    data += cert

    # SC_SECURITY header: type=0x0C02, length includes header
    header = struct.pack("<HH", 0x0C02, len(data) + 4)
    return header + data


def _build_sc_core(selected_protocol: int = _PROTOCOL_RDP) -> bytes:
    """SC_CORE block: RDP version 5.0+."""
    data = struct.pack("<I", 0x00080004)  # version (5.0+)
    data += struct.pack("<I", selected_protocol)  # clientRequestedProtocols
    data += struct.pack("<I", 0)  # earlyCapabilityFlags
    header = struct.pack("<HH", 0x0C01, len(data) + 4)
    return header + data


def _build_sc_security_none() -> bytes:
    """SC_SECURITY block with no encryption (for TLS path).

    When TLS wraps the connection, the RDP-level encryption is disabled:
    ENCRYPTION_METHOD_NONE (0) and ENCRYPTION_LEVEL_NONE (0), with zero-
    length server random and certificate.
    """
    data = struct.pack("<II", 0x00000000, 0x00000000)  # method=NONE, level=NONE
    data += struct.pack("<I", 0)  # serverRandomLen
    data += struct.pack("<I", 0)  # serverCertLen
    header = struct.pack("<HH", 0x0C02, len(data) + 4)
    return header + data


def _build_sc_net(channel_ids: list[int]) -> bytes:
    """SC_NET block: I/O channel + virtual channel IDs."""
    data = struct.pack("<HH", _IO_CHANNEL, len(channel_ids))
    for cid in channel_ids:
        data += struct.pack("<H", cid)
    # Pad to 4-byte boundary
    if len(data) % 4:
        data += b"\x00" * (4 - len(data) % 4)
    header = struct.pack("<HH", 0x0C03, len(data) + 4)
    return header + data


def _ber_write_length(length: int) -> bytes:
    """BER definite-length encoding."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return struct.pack(">BH", 0x82, length)


def _build_gcc_conference_response(sc_core: bytes, sc_security: bytes,
                                    sc_net: bytes) -> bytes:
    """PER-encoded GCC Conference Create Response wrapping server data."""
    user_data = sc_core + sc_security + sc_net

    # GCC Conference Create Response (ConnectGCCPDU)
    # T.124 ConferenceCreateResponse
    gcc = bytearray()
    # ConferenceCreateResponse::nodeID = 0x79F3 (per MS-RDPBCGR 2.2.1.4)
    gcc += b"\x00\x05\x00\x14\x7c\x00\x01"
    # BER length of remaining data placeholder -- we'll wrap later
    inner = bytearray()
    inner += b"\x2a\x14\x76\x0a\x01\x01\x00\x01\x01\x00\x01\x0c\x00\x00"
    # userData length (PER)
    ud_len = len(user_data) + 2  # +2 for the H221Key header
    inner += struct.pack(">H", ud_len | 0x8000)
    inner += b"\x4d\x63"  # H221 non-standard key "McDn" (first 2 bytes)
    inner += user_data

    # Wrap inner with BER length
    gcc += _ber_write_length(len(inner))
    gcc += inner

    return bytes(gcc)


def _build_mcs_connect_response(server_random: bytes, rsa_key,
                                 channel_ids: list[int],
                                 tls_mode: bool = False) -> bytes:
    """Full TPKT + X.224 Data + BER MCS Connect-Response.

    When *tls_mode* is True the response uses ``_PROTOCOL_SSL`` in SC_CORE
    and ``_build_sc_security_none()`` instead of the RSA certificate, since
    TLS handles all transport-level encryption.
    """
    if tls_mode:
        sc_core = _build_sc_core(_PROTOCOL_SSL)
        sc_security = _build_sc_security_none()
    else:
        sc_core = _build_sc_core()
        sc_security = _build_sc_security(server_random, rsa_key)
    sc_net = _build_sc_net(channel_ids)
    gcc = _build_gcc_conference_response(sc_core, sc_security, sc_net)

    # MCS Connect-Response (BER encoded)
    # Result: rt-successful (0), calledConnectId: 0
    mcs_fields = b"\x0a\x01\x00"  # result ENUMERATED 0
    mcs_fields += b"\x02\x01\x00"  # calledConnectId INTEGER 0
    # domainParameters SEQUENCE
    domain_params = bytearray()
    domain_params += b"\x30"  # SEQUENCE tag
    dp_content = b""
    dp_content += b"\x02\x01\x22"  # maxChannelIds = 34
    dp_content += b"\x02\x01\x03"  # maxUserIds = 3
    dp_content += b"\x02\x01\x00"  # maxTokenIds = 0
    dp_content += b"\x02\x01\x01"  # numPriorities = 1
    dp_content += b"\x02\x01\x00"  # minThroughput = 0
    dp_content += b"\x02\x01\x01"  # maxHeight = 1
    dp_content += b"\x02\x02\xff\xff"  # maxMCSPDUsize = 65535
    dp_content += b"\x02\x01\x02"  # protocolVersion = 2
    domain_params += _ber_write_length(len(dp_content))
    domain_params += dp_content
    mcs_fields += bytes(domain_params)

    # userData OCTET STRING wrapping GCC
    mcs_fields += b"\x04"  # OCTET STRING tag
    mcs_fields += _ber_write_length(len(gcc))
    mcs_fields += gcc

    # MCS Connect-Response tag 0x7F66
    mcs = bytearray()
    mcs += b"\x7f\x66"
    mcs += _ber_write_length(len(mcs_fields))
    mcs += mcs_fields

    # X.224 Data header: 3 bytes (length=2, type=0xF0, EOT=0x80)
    x224_data = b"\x02\xf0\x80"

    # TPKT
    total_len = 4 + len(x224_data) + len(mcs)
    tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, total_len)

    return tpkt + x224_data + bytes(mcs)


def _build_mcs_attach_user_confirm(user_channel_id: int) -> bytes:
    """MCS Attach-User Confirm (TPKT + X.224 Data + PER payload)."""
    # PER: attachUserConfirm choice tag (0x2E), result=0 (rt-successful)
    # initiator = user_channel_id - 1001 (PER encoding)
    per = bytearray()
    per.append(_MCS_ATTACH_USER_CONFIRM)
    per.append(0x00)  # result: rt-successful
    per += struct.pack(">H", user_channel_id - 1001)

    x224_data = b"\x02\xf0\x80"
    total_len = 4 + len(x224_data) + len(per)
    tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, total_len)
    return tpkt + x224_data + bytes(per)


def _build_mcs_channel_join_confirm(initiator: int, channel_id: int) -> bytes:
    """MCS Channel-Join Confirm (TPKT + X.224 Data + PER payload)."""
    per = bytearray()
    per.append(_MCS_CHANNEL_JOIN_CONFIRM)
    per.append(0x00)  # result: rt-successful
    per += struct.pack(">H", initiator - 1001)
    per += struct.pack(">H", channel_id)
    per += struct.pack(">H", channel_id)

    x224_data = b"\x02\xf0\x80"
    total_len = 4 + len(x224_data) + len(per)
    tpkt = struct.pack(">BBH", _TPKT_VERSION, 0, total_len)
    return tpkt + x224_data + bytes(per)


# ======================================================================
# PDU parsers
# ======================================================================

def _recv_tpkt_pdu(sock: socket.socket) -> bytes | None:
    """Read one TPKT-framed PDU.  Returns full packet bytes or None."""
    hdr = _recv_exact(sock, 4)
    if not hdr or hdr[0] != _TPKT_VERSION:
        return None
    pkt_len = struct.unpack(">H", hdr[2:4])[0]
    if pkt_len < 4 or pkt_len > 65535:
        return None
    remaining = pkt_len - 4
    if remaining == 0:
        return hdr
    payload = _recv_exact(sock, remaining)
    if not payload:
        return None
    return hdr + payload


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


def _parse_mcs_connect_initial(data: bytes) -> dict | None:
    """Validate an MCS Connect Initial PDU.

    *data* is the full TPKT packet.  Returns dict with basic info
    or None if this isn't a valid Connect Initial.
    """
    # Skip TPKT (4) + X.224 Data (3) = offset 7
    if len(data) < 10:
        return None
    mcs_start = 7
    if data[mcs_start] == 0x7F and data[mcs_start + 1] == 0x65:
        return {"type": "mcs_connect_initial"}
    return None


def _parse_security_exchange(data: bytes, rsa_key) -> bytes | None:
    """Extract client_random from a Security Exchange PDU.

    *data* is the full TPKT packet.  Returns 32-byte client_random
    or None on failure.
    """
    # TPKT(4) + X.224(3) + MCS SendDataRequest header
    # The Security Exchange contains an RSA-encrypted blob
    if len(data) < 15:
        return None

    # Find the encrypted client random length and blob
    # MCS SendDataRequest: skip TPKT(4) + X.224(3) = 7
    # Then MCS header varies; we look for the security header
    # Security Exchange PDU: securityHeader(4 bytes flags+flagsHi) + length(4) + blob
    # The flags should have SEC_EXCHANGE_PKT (0x0001)
    offset = 7
    # Skip MCS SendDataRequest header: tag(1) + initiator(2) + channelId(2)
    # + dataPriority+segmentation(1) + userData length (2 or 3 bytes)
    if offset >= len(data):
        return None

    tag = data[offset]
    if (tag >> 2) != (0x64 >> 2):  # SendDataRequest
        # Try to find SEC_EXCHANGE_PKT flag in the payload
        pass

    # Scan for the security header with SEC_EXCHANGE_PKT flag
    # Strategy: look for 0x0001 (SEC_EXCHANGE_PKT) in the first few positions
    # after the MCS header, followed by a length field matching the remaining data
    try:
        # Skip past MCS SendDataRequest header to security data
        # tag(1) + initiator(2) + channelId(2) + priority/seg(1) + len(2)
        sec_offset = offset + 1 + 2 + 2 + 1
        # Read userData length (PER)
        if sec_offset >= len(data):
            return None
        ud_len_hi = data[sec_offset]
        if ud_len_hi & 0x80:
            sec_offset += 2  # 2-byte length
        else:
            sec_offset += 1  # 1-byte length but unlikely for this PDU
            # Actually for PER, if top 2 bits are 01xx, it's a 2-byte length
            # Let's handle both cases
            sec_offset -= 1
            if data[sec_offset] & 0x80:
                sec_offset += 2
            else:
                sec_offset += 1

        # Now at security header: flags(2) + flagsHi(2)
        if sec_offset + 4 > len(data):
            return None
        flags = struct.unpack_from("<H", data, sec_offset)[0]
        if flags & 0x0001 == 0:
            # Not SEC_EXCHANGE_PKT -- try alternate offset
            # Some implementations have slightly different MCS header lengths
            for alt in range(offset + 6, min(offset + 20, len(data) - 4)):
                f = struct.unpack_from("<H", data, alt)[0]
                if f & 0x0001 and f < 0x0010:  # SEC_EXCHANGE_PKT
                    sec_offset = alt
                    flags = f
                    break
            else:
                return None

        sec_offset += 4  # skip security header (flags + flagsHi)

        # encrypted client random length (LE u32)
        if sec_offset + 4 > len(data):
            return None
        enc_len = struct.unpack_from("<I", data, sec_offset)[0]
        sec_offset += 4

        if sec_offset + enc_len > len(data):
            # Try with just remaining data
            enc_len = len(data) - sec_offset

        if enc_len < 64:
            return None

        enc_blob = data[sec_offset:sec_offset + enc_len]

        # RSA decrypt (PKCS1v15, input is little-endian per MS-RDPBCGR)
        # The blob is in little-endian format, need to reverse for standard RSA
        enc_be = bytes(reversed(enc_blob[:64]))  # 512-bit RSA = 64 bytes
        client_random = rsa_key.decrypt(enc_be, padding.PKCS1v15())

        if len(client_random) == 32:
            return client_random
        return None

    except Exception:
        return None


def _parse_client_info(data: bytes, decrypt_key: bytes) -> dict | None:
    """Decrypt and parse Client Info PDU for credentials.

    *data* is the full TPKT packet.  Returns dict with domain/username/
    password or None on failure.
    """
    if len(data) < 15:
        return None

    # Find the security header + encrypted payload
    # TPKT(4) + X.224(3) = 7, then MCS SendDataRequest header
    offset = 7

    # Skip MCS SendDataRequest: tag(1) + initiator(2) + channelId(2) +
    # priority/seg(1) + userData PER length (variable)
    try:
        sec_offset = offset + 1 + 2 + 2 + 1
        if sec_offset >= len(data):
            return None
        # PER length
        if data[sec_offset] & 0x80:
            sec_offset += 2
        else:
            sec_offset += 1

        # Security header: flags(2) + flagsHi(2) + MAC(8)
        if sec_offset + 12 > len(data):
            return None
        flags = struct.unpack_from("<H", data, sec_offset)[0]

        # SEC_INFO_PKT = 0x0040
        if flags & 0x0040 == 0:
            # Try alternate offsets
            for alt in range(offset + 6, min(offset + 20, len(data) - 12)):
                f = struct.unpack_from("<H", data, alt)[0]
                if f & 0x0040:
                    sec_offset = alt
                    flags = f
                    break
            else:
                return None

        sec_offset += 4   # skip flags + flagsHi
        sec_offset += 8   # skip MAC signature

        # Everything from here is RC4-encrypted
        encrypted = data[sec_offset:]
        if len(encrypted) < 18:
            return None

        decrypted = _rc4(decrypt_key, encrypted)
        return _parse_ts_info_packet(decrypted)

    except Exception:
        return None


def _parse_client_info_tls(data: bytes) -> dict | None:
    """Parse a TLS-mode Client Info PDU for credentials.

    In the TLS path there is no RC4 encryption and the security header
    is only 4 bytes (flags + flagsHi) with **no** 8-byte MAC signature.
    The payload after the security header is a cleartext TS_INFO_PACKET.
    """
    if len(data) < 15:
        return None

    offset = 7  # TPKT(4) + X.224(3)

    try:
        # Skip MCS SendDataRequest: tag(1) + initiator(2) + channelId(2) +
        # priority/seg(1) + userData PER length (variable)
        sec_offset = offset + 1 + 2 + 2 + 1
        if sec_offset >= len(data):
            return None
        # PER length
        if data[sec_offset] & 0x80:
            sec_offset += 2
        else:
            sec_offset += 1

        # Security header: flags(2) + flagsHi(2) -- NO MAC in TLS mode
        if sec_offset + 4 > len(data):
            return None
        flags = struct.unpack_from("<H", data, sec_offset)[0]

        # SEC_INFO_PKT = 0x0040
        if flags & 0x0040 == 0:
            for alt in range(offset + 6, min(offset + 20, len(data) - 4)):
                f = struct.unpack_from("<H", data, alt)[0]
                if f & 0x0040:
                    sec_offset = alt
                    flags = f
                    break
            else:
                return None

        sec_offset += 4  # skip flags + flagsHi (no MAC to skip)

        cleartext = data[sec_offset:]
        if len(cleartext) < 18:
            return None

        return _parse_ts_info_packet(cleartext)

    except Exception:
        return None


def _parse_ts_info_packet(data: bytes) -> dict | None:
    """Parse a decrypted TS_INFO_PACKET for domain, username, password.

    Layout (MS-RDPBCGR 2.2.1.11.1.1):
      codePage(4) + flags(4) + cbDomain(2) + cbUserName(2) + cbPassword(2)
      + cbAlternateShell(2) + cbWorkingDir(2) + domain + username + password + ...
    """
    if len(data) < 18:
        return None

    try:
        flags = struct.unpack_from("<I", data, 4)[0]
        cb_domain = struct.unpack_from("<H", data, 8)[0]
        cb_username = struct.unpack_from("<H", data, 10)[0]
        cb_password = struct.unpack_from("<H", data, 12)[0]
        cb_alt_shell = struct.unpack_from("<H", data, 14)[0]
        cb_working_dir = struct.unpack_from("<H", data, 16)[0]

        is_unicode = bool(flags & _INFO_UNICODE)
        encoding = "utf-16-le" if is_unicode else "ascii"
        null_len = 2 if is_unicode else 1  # null terminator size

        offset = 18
        # Domain (cbDomain includes null terminator)
        domain_end = offset + cb_domain
        if domain_end > len(data):
            return None
        domain_raw = data[offset:domain_end]
        domain = domain_raw.decode(encoding, errors="replace").rstrip("\x00")
        offset = domain_end + null_len

        # Username
        username_end = offset + cb_username
        if username_end > len(data):
            return None
        username_raw = data[offset:username_end]
        username = username_raw.decode(encoding, errors="replace").rstrip("\x00")
        offset = username_end + null_len

        # Password
        password_end = offset + cb_password
        if password_end > len(data):
            password = ""
        else:
            password_raw = data[offset:password_end]
            password = password_raw.decode(encoding, errors="replace").rstrip("\x00")

        return {
            "domain": domain,
            "username": username,
            "password": password,
        }

    except Exception:
        return None


# ======================================================================
# RDPHoneypot class
# ======================================================================

class RDPHoneypot:
    """
    Socket-based RDP honeypot implementing X.224 negotiation and Standard
    RDP Security handshake to capture connection metadata, attacker
    usernames from mstshash cookies, and brute-forced credentials.
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
        self._rsa_key = _generate_rsa_512()
        self._tls_context = self._create_tls_context()

    @staticmethod
    def _create_tls_context() -> ssl.SSLContext:
        """Create a TLS server context using the shared self-signed cert."""
        cert_path, key_path = ensure_self_signed_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

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
        sock: socket.socket = client_sock  # may be replaced by TLS socket
        use_tls = False
        app_ctx = self.app.app_context() if self.app else None
        if app_ctx:
            app_ctx.push()
        try:
            client_sock.settimeout(30)

            # ---- Phase 1: X.224 Connection Request / Confirm ----
            tpkt = self._recv_exact(client_sock, 4)
            if not tpkt or tpkt[0] != _TPKT_VERSION:
                return

            pkt_len = struct.unpack(">H", tpkt[2:4])[0]
            if pkt_len < 7 or pkt_len > 8192:
                return

            remaining = pkt_len - 4
            payload = self._recv_exact(client_sock, remaining)
            if not payload:
                return

            cr_info = self._parse_x224_cr(payload)
            if cr_info is None:
                return

            # Decide negotiation path based on requested protocols
            req_protocols = cr_info.get("requested_protocols") or 0
            use_tls = bool(req_protocols & _PROTOCOL_SSL)

            # Create session
            if self.session_recorder:
                sess = self.session_recorder.start_session(addr[0], "rdp")
                session_id = sess.id

            # Emit connection event (mstshash username, protocols)
            self._emit_connection_event(addr, session_id, cr_info)

            if use_tls:
                # --- TLS negotiation path ---
                selected_protocol = _PROTOCOL_SSL
                cc_output = "X224_CC PROTOCOL_SSL"
            else:
                # --- Standard RDP security path ---
                selected_protocol = _PROTOCOL_RDP
                cc_output = "X224_CC PROTOCOL_RDP"

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
                    output=cc_output,
                )

            # Send X.224 Connection Confirm
            response = self._build_x224_cc(selected_protocol)
            client_sock.sendall(response)

            # ---- TLS handshake (if TLS path) ----
            if use_tls:
                try:
                    sock = self._tls_context.wrap_socket(
                        client_sock, server_side=True,
                    )
                except (ssl.SSLError, OSError):
                    logger.debug(
                        "RDP TLS handshake failed for %s", addr[0],
                    )
                    return

                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id,
                        "TLS handshake",
                        datetime.now(timezone.utc),
                        output="TLS handshake complete",
                    )

            # ---- Phase 2: MCS Connect Initial / Response ----
            pdu = _recv_tpkt_pdu(sock)
            if pdu is None:
                # Client disconnected -- scanner that only does X.224
                return

            mcs_info = _parse_mcs_connect_initial(pdu)
            if mcs_info is None:
                # Not a valid MCS Connect Initial -- log and bail
                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id,
                        f"POST_NEGOTIATE {len(pdu)} bytes (not MCS)",
                        datetime.now(timezone.utc),
                        output="(connection closed)",
                    )
                return

            # Generate server_random, build and send MCS Connect Response
            server_random = secrets.token_bytes(32)
            channel_ids = [1004, 1005, 1006]  # virtual channels
            mcs_resp = _build_mcs_connect_response(
                server_random, self._rsa_key, channel_ids,
                tls_mode=use_tls,
            )
            sock.sendall(mcs_resp)

            if self.session_recorder and session_id:
                self.session_recorder.record_command(
                    session_id,
                    "MCS_CONNECT phase",
                    datetime.now(timezone.utc),
                    output="MCS_CONNECT_RESPONSE sent",
                )

            # ---- Phase 3: Erect Domain Request (discard) ----
            pdu = _recv_tpkt_pdu(sock)
            if pdu is None:
                return

            # ---- Phase 4: Attach User Request → Confirm ----
            pdu = _recv_tpkt_pdu(sock)
            if pdu is None:
                return

            user_channel = _USER_CHANNEL_BASE
            confirm = _build_mcs_attach_user_confirm(user_channel)
            sock.sendall(confirm)

            # ---- Phase 5: Channel Join loop ----
            all_channels = [_IO_CHANNEL] + channel_ids + [user_channel]
            for _ in range(len(all_channels) + 5):  # generous limit
                pdu = _recv_tpkt_pdu(sock)
                if pdu is None:
                    return

                # Check if this is a Channel Join Request
                if len(pdu) > 7 and (pdu[7] >> 2) == (_MCS_CHANNEL_JOIN_REQUEST >> 2):
                    # Extract requested channel ID
                    if len(pdu) >= 12:
                        req_channel = struct.unpack(">H", pdu[10:12])[0]
                    else:
                        req_channel = _IO_CHANNEL
                    cj_confirm = _build_mcs_channel_join_confirm(
                        user_channel, req_channel
                    )
                    sock.sendall(cj_confirm)
                else:
                    # Not a Channel Join Request -- next phase
                    break

            if use_tls:
                # ---- TLS path: Client Info PDU (cleartext, no Security Exchange) ----
                # 'pdu' from the channel join loop break is the Client Info PDU
                creds = _parse_client_info_tls(pdu)
                if creds is None:
                    # Try reading one more PDU
                    pdu = _recv_tpkt_pdu(sock)
                    if pdu is None:
                        return
                    creds = _parse_client_info_tls(pdu)
            else:
                # ---- Standard RDP path: Security Exchange → Client Info ----
                # Phase 6: Security Exchange (RSA-encrypted client_random)
                # 'pdu' may already be the Security Exchange if the loop broke
                client_random = _parse_security_exchange(pdu, self._rsa_key)
                if client_random is None:
                    # Try reading one more PDU
                    pdu = _recv_tpkt_pdu(sock)
                    if pdu is None:
                        return
                    client_random = _parse_security_exchange(pdu, self._rsa_key)
                    if client_random is None:
                        return

                # Phase 7: Derive session keys
                _mac_key, decrypt_key = _derive_keys(client_random, server_random)

                # Phase 8: Client Info PDU (RC4-encrypted credentials)
                pdu = _recv_tpkt_pdu(sock)
                if pdu is None:
                    return

                creds = _parse_client_info(pdu, decrypt_key)

            if creds:
                self._emit_auth_event(
                    addr, session_id,
                    creds.get("username", ""),
                    creds.get("password", ""),
                    creds.get("domain", ""),
                )
                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id,
                        f"CLIENT_INFO user={creds.get('username', '')} "
                        f"domain={creds.get('domain', '')}",
                        datetime.now(timezone.utc),
                        output="(credentials captured, connection closed)",
                    )

        except (ssl.SSLError, socket.timeout, ConnectionResetError,
                BrokenPipeError, OSError):
            pass
        except Exception:
            logger.exception("RDP handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            try:
                sock.close()
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

    def _build_x224_cc(self, selected_protocol: int = _PROTOCOL_RDP) -> bytes:
        """Build a complete TPKT + X.224 Connection Confirm + RDP Negotiation
        Response.

        Total: 19 bytes
          TPKT header:    4 bytes (version=3, reserved=0, length=19)
          X.224 CC:       7 bytes (length=14, type=0xD0, dst/src/class)
          RDP Neg RSP:    8 bytes (type=0x02, flags=0, length=8, protocol)
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
        struct.pack_into("<I", pkt, 15, selected_protocol)

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

    def _emit_auth_event(self, addr: tuple, session_id: str | None,
                         username: str, password: str, domain: str) -> None:
        """Emit an authentication event with captured credentials."""
        logger.info(
            "RDP auth  user=%s  domain=%s  from=%s",
            username or "(none)",
            domain or "(none)",
            addr[0],
        )

        if self.event_processor:
            self.event_processor.process_event({
                "event_type": "authentication",
                "protocol": "rdp",
                "source_ip": addr[0],
                "source_port": addr[1],
                "destination_port": self.port,
                "severity": "high",
                "session_id": session_id,
                "details": {
                    "username": username,
                    "password": password,
                    "domain": domain,
                },
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
