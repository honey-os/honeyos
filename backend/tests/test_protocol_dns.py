"""Tests for backend/services/protocols/dns_honeypot.py"""

import struct

from services.protocols.dns_honeypot import (
    DNSHoneypot,
    QTYPE_A,
    QTYPE_AXFR,
    QTYPE_NS,
    QTYPE_SOA,
    QTYPE_TXT,
    QCLASS_IN,
    QCLASS_CH,
    _encode_name,
    _decode_name,
    _parse_query,
    _build_rr,
    _ip_to_bytes,
)


class TestEncodeName:
    def test_simple_domain(self):
        result = _encode_name("example.com")
        assert result == b"\x07example\x03com\x00"

    def test_subdomain(self):
        result = _encode_name("www.example.com")
        assert result == b"\x03www\x07example\x03com\x00"

    def test_trailing_dot_stripped(self):
        result = _encode_name("example.com.")
        assert result == b"\x07example\x03com\x00"

    def test_single_label(self):
        result = _encode_name("localhost")
        assert result == b"\x09localhost\x00"


class TestDecodeName:
    def test_simple_name(self):
        data = b"\x07example\x03com\x00"
        name, offset = _decode_name(data, 0)
        assert name == "example.com"
        assert offset == len(data)

    def test_with_offset(self):
        prefix = b"\x00\x00"
        data = prefix + b"\x03www\x07example\x03com\x00"
        name, offset = _decode_name(data, 2)
        assert name == "www.example.com"

    def test_compression_pointer(self):
        # Build data with a name at offset 0, then a pointer to it
        name_data = b"\x07example\x03com\x00"
        # Pointer at offset len(name_data): points to offset 0
        pointer = struct.pack("!H", 0xC000 | 0)
        data = name_data + pointer
        name, offset = _decode_name(data, len(name_data))
        assert name == "example.com"
        # After compression pointer, offset should advance past the 2-byte pointer
        assert offset == len(name_data) + 2

    def test_empty_name(self):
        data = b"\x00"
        name, offset = _decode_name(data, 0)
        assert name == ""


class TestParseQuery:
    def _build_query(self, name="example.com", qtype=QTYPE_A, qclass=QCLASS_IN):
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = _encode_name(name)
        question = qname + struct.pack("!HH", qtype, qclass)
        return header + question

    def test_parses_a_query(self):
        data = self._build_query("example.com", QTYPE_A)
        result = _parse_query(data)
        assert result is not None
        assert result["qname"] == "example.com"
        assert result["qtype"] == QTYPE_A

    def test_parses_txn_id(self):
        # Build with specific txn_id
        txn_id = 0x1234
        header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)
        qname = _encode_name("test.com")
        question = qname + struct.pack("!HH", QTYPE_A, QCLASS_IN)
        data = header + question
        result = _parse_query(data)
        assert result is not None
        assert result["txn_id"] == txn_id

    def test_rejects_short_data(self):
        assert _parse_query(b"\x00" * 5) is None

    def test_rejects_zero_qdcount(self):
        header = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
        assert _parse_query(header) is None


class TestBuildResponse:
    def test_a_record_response(self):
        hp = DNSHoneypot(port=0, config={"domain": "corp.local"})
        query = {
            "txn_id": 0x1234,
            "flags": 0x0100,
            "qname": "dc01.corp.local",
            "qtype": QTYPE_A,
            "qclass": QCLASS_IN,
        }
        response, count = hp._build_response(query)
        assert count >= 1
        # Response should start with txn_id
        assert struct.unpack("!H", response[0:2])[0] == 0x1234
        # QR bit should be set
        flags = struct.unpack("!H", response[2:4])[0]
        assert flags & 0x8000  # QR=1

    def test_axfr_response_has_multiple_records(self):
        hp = DNSHoneypot(port=0, config={"domain": "corp.local"})
        query = {
            "txn_id": 0xABCD,
            "flags": 0x0100,
            "qname": "corp.local",
            "qtype": QTYPE_AXFR,
            "qclass": QCLASS_IN,
        }
        response, count = hp._build_response(query)
        # AXFR should return many records (SOA + all zone + SOA)
        assert count > 5

    def test_fallback_a_record(self):
        hp = DNSHoneypot(port=0, config={"domain": "corp.local"})
        query = {
            "txn_id": 0x5678,
            "flags": 0x0100,
            "qname": "unknown.example.com",
            "qtype": QTYPE_A,
            "qclass": QCLASS_IN,
        }
        response, count = hp._build_response(query)
        assert count == 1  # generic fallback A record

    def test_chaos_version_bind(self):
        hp = DNSHoneypot(
            port=0, config={"domain": "corp.local", "version": "dnsmasq-2.90"}
        )
        query = {
            "txn_id": 0x9999,
            "flags": 0x0100,
            "qname": "version.bind",
            "qtype": QTYPE_TXT,
            "qclass": QCLASS_CH,
        }
        response, count = hp._build_response(query)
        assert count == 1


class TestZoneContent:
    def test_zone_has_apex_records(self):
        hp = DNSHoneypot(port=0, config={"domain": "corp.local"})
        zone = hp._zone
        apex = zone.get("corp.local", [])
        rtypes = [rt for rt, _ in apex]
        assert QTYPE_SOA in rtypes
        assert QTYPE_NS in rtypes
        assert QTYPE_A in rtypes

    def test_zone_has_hostnames(self):
        hp = DNSHoneypot(port=0, config={"domain": "corp.local"})
        assert "dc01.corp.local" in hp._zone
        assert "vpn.corp.local" in hp._zone
        assert "fileserver.corp.local" in hp._zone

    def test_custom_domain(self):
        hp = DNSHoneypot(port=0, config={"domain": "test.local"})
        assert "test.local" in hp._zone
        assert "dc01.test.local" in hp._zone
