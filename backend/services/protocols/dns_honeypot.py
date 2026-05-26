"""
DNSHoneypot -- fake DNS server that answers all queries with bogus records.

Acts like a wide-open, misconfigured DNS server to attract reconnaissance.
Supports both UDP and TCP transports, answers any query type, and allows
zone transfers (AXFR) to log attacker enumeration activity.

Pure-stdlib implementation -- parses DNS wire format with ``struct``.
"""

import logging
import socket
import struct
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DNS constants
# ---------------------------------------------------------------------------

QTYPE_A = 1
QTYPE_NS = 2
QTYPE_CNAME = 5
QTYPE_SOA = 6
QTYPE_PTR = 12
QTYPE_MX = 15
QTYPE_TXT = 16
QTYPE_AAAA = 28
QTYPE_SRV = 33
QTYPE_ANY = 255
QTYPE_AXFR = 252
QTYPE_IXFR = 251

QTYPE_NAMES: dict[int, str] = {
    QTYPE_A: "A",
    QTYPE_NS: "NS",
    QTYPE_CNAME: "CNAME",
    QTYPE_SOA: "SOA",
    QTYPE_PTR: "PTR",
    QTYPE_MX: "MX",
    QTYPE_TXT: "TXT",
    QTYPE_AAAA: "AAAA",
    QTYPE_SRV: "SRV",
    QTYPE_ANY: "ANY",
    QTYPE_AXFR: "AXFR",
    QTYPE_IXFR: "IXFR",
}

QCLASS_IN = 1
QCLASS_CH = 3  # CHAOS class (used for version.bind queries)
DEFAULT_TTL = 3600

# ---------------------------------------------------------------------------
# DNS wire-format helpers
# ---------------------------------------------------------------------------


def _encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format (label sequence)."""
    parts = name.rstrip(".").split(".")
    encoded = b""
    for label in parts:
        raw = label.encode("ascii")
        encoded += bytes([len(raw)]) + raw
    encoded += b"\x00"
    return encoded


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name from wire format, handling compression pointers."""
    labels: list[str] = []
    jumped = False
    original_offset = offset
    max_jumps = 20

    for _ in range(max_jumps):
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        # Compression pointer
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def _parse_query(data: bytes) -> dict | None:
    """Parse a DNS query message. Returns header info + question section."""
    if len(data) < 12:
        return None

    txn_id = struct.unpack("!H", data[0:2])[0]
    flags = struct.unpack("!H", data[2:4])[0]
    qdcount = struct.unpack("!H", data[4:6])[0]

    if qdcount < 1:
        return None

    qname, offset = _decode_name(data, 12)
    if offset + 4 > len(data):
        return None

    qtype = struct.unpack("!H", data[offset:offset + 2])[0]
    qclass = struct.unpack("!H", data[offset + 2:offset + 4])[0]

    return {
        "txn_id": txn_id,
        "flags": flags,
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
        "raw_question": data[12:offset + 4],
    }


def _build_rr(name: str, rtype: int, rdata: bytes, ttl: int = DEFAULT_TTL) -> bytes:
    """Build a single DNS resource record."""
    encoded_name = _encode_name(name)
    return (
        encoded_name
        + struct.pack("!HHI", rtype, QCLASS_IN, ttl)
        + struct.pack("!H", len(rdata))
        + rdata
    )


def _ip_to_bytes(ip: str) -> bytes:
    """Convert dotted-quad IPv4 to 4 bytes."""
    return socket.inet_aton(ip)


def _build_soa_rdata(mname: str, rname: str, serial: int = 2024010101) -> bytes:
    """Build SOA record RDATA."""
    return (
        _encode_name(mname)
        + _encode_name(rname)
        + struct.pack("!IIIII", serial, 3600, 900, 604800, 86400)
    )


def _build_mx_rdata(preference: int, exchange: str) -> bytes:
    return struct.pack("!H", preference) + _encode_name(exchange)


def _build_srv_rdata(priority: int, weight: int, port: int, target: str) -> bytes:
    return struct.pack("!HHH", priority, weight, port) + _encode_name(target)


def _build_txt_rdata(text: str) -> bytes:
    raw = text.encode("utf-8")
    # TXT is one or more <length><string> chunks (max 255 each)
    parts = b""
    for i in range(0, len(raw), 255):
        chunk = raw[i:i + 255]
        parts += bytes([len(chunk)]) + chunk
    return parts


# ---------------------------------------------------------------------------
# DNSHoneypot
# ---------------------------------------------------------------------------


class DNSHoneypot:
    """
    Fake DNS server listening on both UDP and TCP.

    Answers all queries with fake records from a configurable zone and
    logs every query as an event.
    """

    def __init__(self, port: int, config: dict | None = None,
                 event_processor=None, session_recorder=None, app=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder  # unused -- DNS is stateless
        self.app = app
        self._stop_event = threading.Event()
        self._udp_socket: socket.socket | None = None
        self._tcp_socket: socket.socket | None = None

        # --- Build fake zone data ---
        self.domain = self.config.get("domain", "corp.local")
        self.version_string = self.config.get("version", "dnsmasq-2.90")
        self._zone = self._build_zone()

    # ------------------------------------------------------------------
    # Fake zone
    # ------------------------------------------------------------------

    def _build_zone(self) -> dict[str, list[tuple[int, bytes]]]:
        """
        Build fake zone records.  Returns a dict mapping lowercase FQDN
        to a list of (rtype, rdata) tuples.
        """
        d = self.domain
        zone: dict[str, list[tuple[int, bytes]]] = {}

        def add(name: str, rtype: int, rdata: bytes):
            key = name.lower()
            zone.setdefault(key, []).append((rtype, rdata))

        # SOA
        add(d, QTYPE_SOA, _build_soa_rdata(f"ns1.{d}", f"admin.{d}"))

        # NS
        add(d, QTYPE_NS, _encode_name(f"ns1.{d}"))
        add(d, QTYPE_NS, _encode_name(f"ns2.{d}"))

        # MX
        add(d, QTYPE_MX, _build_mx_rdata(10, f"mail.{d}"))
        add(d, QTYPE_MX, _build_mx_rdata(20, f"mail2.{d}"))

        # TXT
        add(d, QTYPE_TXT, _build_txt_rdata("v=spf1 include:corp.local ~all"))
        add(d, QTYPE_TXT, _build_txt_rdata("google-site-verification=fake12345"))

        # A record for apex
        add(d, QTYPE_A, _ip_to_bytes("10.0.0.1"))

        # AAAA for apex
        add(d, QTYPE_AAAA, socket.inet_pton(socket.AF_INET6, "fd00::1"))

        # Fake hosts
        hosts = {
            "ns1": "10.0.0.2",
            "ns2": "10.0.0.3",
            "mail": "10.0.0.10",
            "mail2": "10.0.0.11",
            "vpn": "10.0.0.20",
            "dc01": "10.0.0.100",
            "dc02": "10.0.0.101",
            "intranet": "10.0.0.50",
            "fileserver": "10.0.0.60",
            "gitlab": "10.0.0.70",
            "jenkins": "10.0.0.71",
            "wiki": "10.0.0.80",
            "backup": "10.0.0.90",
            "monitoring": "10.0.0.91",
            "db01": "10.0.0.110",
            "db02": "10.0.0.111",
            "web01": "10.0.0.120",
            "web02": "10.0.0.121",
            "dev": "10.0.0.200",
            "staging": "10.0.0.201",
        }
        for hostname, ip in hosts.items():
            fqdn = f"{hostname}.{d}"
            add(fqdn, QTYPE_A, _ip_to_bytes(ip))
            add(fqdn, QTYPE_AAAA, socket.inet_pton(
                socket.AF_INET6, f"fd00::{ip.split('.')[-1]}"))

        # SRV records
        add(f"_ldap._tcp.{d}", QTYPE_SRV, _build_srv_rdata(0, 100, 389, f"dc01.{d}"))
        add(f"_kerberos._tcp.{d}", QTYPE_SRV, _build_srv_rdata(0, 100, 88, f"dc01.{d}"))

        # PTR for a few IPs (reverse zone, simplified)
        add("1.0.0.10.in-addr.arpa", QTYPE_PTR, _encode_name(d))
        add("100.0.0.10.in-addr.arpa", QTYPE_PTR, _encode_name(f"dc01.{d}"))

        # CNAME
        add(f"www.{d}", QTYPE_CNAME, _encode_name(f"web01.{d}"))
        add(f"webmail.{d}", QTYPE_CNAME, _encode_name(f"mail.{d}"))

        return zone

    # ------------------------------------------------------------------
    # Response builder
    # ------------------------------------------------------------------

    def _build_response(self, query: dict) -> tuple[bytes, int]:
        """
        Build a DNS response for the given parsed query.
        Returns (response_bytes, record_count).
        """
        txn_id = query["txn_id"]
        qname = query["qname"].lower()
        qtype = query["qtype"]
        qclass = query["qclass"]

        records: list[bytes] = []

        # CHAOS class queries (version.bind, hostname.bind, etc.)
        if qclass == QCLASS_CH and qtype == QTYPE_TXT:
            txt = None
            if qname in ("version.bind", "version.server"):
                txt = self.version_string
            elif qname in ("hostname.bind", "id.server"):
                txt = self.config.get("hostname", "ns1")
            if txt is not None:
                rdata = _build_txt_rdata(txt)
                encoded_name = _encode_name(query["qname"])
                rr = (
                    encoded_name
                    + struct.pack("!HHI", QTYPE_TXT, QCLASS_CH, 0)
                    + struct.pack("!H", len(rdata))
                    + rdata
                )
                records.append(rr)

                flags = 0x8400
                if query["flags"] & 0x0100:
                    flags |= 0x0100
                header = struct.pack("!HHHHHH", txn_id, flags, 1, 1, 0, 0)
                response = header + _encode_name(query["qname"]) + struct.pack(
                    "!HH", qtype, QCLASS_CH
                )
                response += records[0]
                return response, 1

        # Gather matching records
        zone_entry = self._zone.get(qname, [])

        if qtype == QTYPE_AXFR or qtype == QTYPE_IXFR:
            # Zone transfer: dump everything, wrapped in SOA
            soa_rr = self._get_soa_rr()
            records.append(soa_rr)
            for name, rr_list in self._zone.items():
                for rtype, rdata in rr_list:
                    if rtype != QTYPE_SOA:
                        records.append(_build_rr(name, rtype, rdata))
            records.append(soa_rr)  # closing SOA
        elif qtype == QTYPE_ANY:
            # Return all records for this name
            if zone_entry:
                for rtype, rdata in zone_entry:
                    records.append(_build_rr(qname, rtype, rdata))
            else:
                # Fallback: generic A record
                records.append(_build_rr(qname, QTYPE_A, _ip_to_bytes("10.0.0.1")))
        else:
            # Specific type
            matched = [(rt, rd) for rt, rd in zone_entry if rt == qtype]
            if matched:
                for rtype, rdata in matched:
                    records.append(_build_rr(qname, rtype, rdata))
            else:
                # Fallback: return a generic A record for any A query,
                # empty for other types we don't have
                if qtype == QTYPE_A:
                    records.append(_build_rr(qname, QTYPE_A, _ip_to_bytes("10.0.0.1")))
                elif qtype == QTYPE_AAAA:
                    records.append(_build_rr(
                        qname, QTYPE_AAAA,
                        socket.inet_pton(socket.AF_INET6, "fd00::1"),
                    ))

        # Build header
        # Flags: QR=1, AA=1, RD=1 (copied from query), RA=1
        flags = 0x8400  # QR + AA
        if query["flags"] & 0x0100:  # RD bit
            flags |= 0x0100
        flags |= 0x0080  # RA

        ancount = len(records)
        header = struct.pack("!HHHHHH", txn_id, flags, 1, ancount, 0, 0)

        response = header + _encode_name(query["qname"]) + struct.pack(
            "!HH", qtype, QCLASS_IN
        )
        for rr in records:
            response += rr

        return response, ancount

    def _get_soa_rr(self) -> bytes:
        """Build the SOA RR for the zone apex."""
        soa_entries = self._zone.get(self.domain.lower(), [])
        for rtype, rdata in soa_entries:
            if rtype == QTYPE_SOA:
                return _build_rr(self.domain, QTYPE_SOA, rdata)
        # Fallback
        return _build_rr(
            self.domain, QTYPE_SOA,
            _build_soa_rdata(f"ns1.{self.domain}", f"admin.{self.domain}"),
        )

    # ------------------------------------------------------------------
    # Event logging
    # ------------------------------------------------------------------

    def _log_event(self, source_ip: str, source_port: int,
                   query_name: str, query_type: str, transport: str,
                   response_records: int, is_zone_transfer: bool) -> None:
        """Log a DNS query event."""
        if not self.event_processor or not self.app:
            return

        event_type = "dns_zone_transfer" if is_zone_transfer else "dns_query"
        severity = "high" if is_zone_transfer else "low"

        with self.app.app_context():
            self.event_processor.process_event({
                "event_type": event_type,
                "protocol": "dns",
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_port": self.port,
                "severity": severity,
                "details": {
                    "query_name": query_name,
                    "query_type": query_type,
                    "transport": transport,
                    "response_records": response_records,
                },
            })

    # ------------------------------------------------------------------
    # UDP listener
    # ------------------------------------------------------------------

    def _run_udp(self) -> None:
        """UDP listener thread."""
        self._udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp_socket.settimeout(1.0)

        try:
            self._udp_socket.bind(("0.0.0.0", self.port))
            logger.info("DNS honeypot UDP listening on port %d", self.port)
        except OSError as exc:
            logger.error("DNS honeypot could not bind UDP port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                data, addr = self._udp_socket.recvfrom(4096)
                self._handle_dns_message(data, addr, "udp")
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("DNS UDP recv error")
                break

    def _handle_dns_message(self, data: bytes, addr: tuple,
                            transport: str) -> bytes | None:
        """Parse, respond to, and log a single DNS message."""
        query = _parse_query(data)
        if query is None:
            return None

        qtype = query["qtype"]
        qtype_name = QTYPE_NAMES.get(qtype, str(qtype))
        qname = query["qname"]
        is_zone_transfer = qtype in (QTYPE_AXFR, QTYPE_IXFR)

        response, record_count = self._build_response(query)

        logger.info(
            "DNS %s query from %s:%d  %s %s  (%d records)",
            transport.upper(), addr[0], addr[1], qname, qtype_name, record_count,
        )

        self._log_event(
            source_ip=addr[0],
            source_port=addr[1],
            query_name=qname,
            query_type=qtype_name,
            transport=transport,
            response_records=record_count,
            is_zone_transfer=is_zone_transfer,
        )

        if transport == "udp" and self._udp_socket:
            try:
                self._udp_socket.sendto(response, addr)
            except OSError:
                logger.debug("DNS UDP send error to %s", addr)

        return response

    # ------------------------------------------------------------------
    # TCP listener
    # ------------------------------------------------------------------

    def _run_tcp(self) -> None:
        """TCP listener thread."""
        self._tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_socket.settimeout(1.0)

        try:
            self._tcp_socket.bind(("0.0.0.0", self.port))
            self._tcp_socket.listen(5)
            logger.info("DNS honeypot TCP listening on port %d", self.port)
        except OSError as exc:
            logger.error("DNS honeypot could not bind TCP port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._tcp_socket.accept()
                t = threading.Thread(
                    target=self._handle_tcp_client,
                    args=(client, addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("DNS TCP accept error")
                break

    def _handle_tcp_client(self, client_sock: socket.socket,
                           addr: tuple) -> None:
        """Handle one TCP DNS connection (may contain multiple queries)."""
        try:
            client_sock.settimeout(30)

            while not self._stop_event.is_set():
                # TCP DNS: 2-byte length prefix (RFC 1035 section 4.2.2)
                len_buf = self._tcp_recv_exact(client_sock, 2)
                if len_buf is None:
                    break

                msg_len = struct.unpack("!H", len_buf)[0]
                if msg_len == 0 or msg_len > 65535:
                    break

                msg_data = self._tcp_recv_exact(client_sock, msg_len)
                if msg_data is None:
                    break

                response = self._handle_dns_message(msg_data, addr, "tcp")
                if response is None:
                    break

                # Send with 2-byte length prefix
                tcp_response = struct.pack("!H", len(response)) + response
                client_sock.sendall(tcp_response)

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            logger.exception("DNS TCP handler error for %s", addr)
        finally:
            try:
                client_sock.close()
            except OSError:
                pass

    @staticmethod
    def _tcp_recv_exact(sock: socket.socket, length: int) -> bytes | None:
        """Receive exactly *length* bytes from a TCP socket."""
        buf = b""
        while len(buf) < length:
            chunk = sock.recv(length - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start both UDP and TCP listeners."""
        udp_thread = threading.Thread(
            target=self._run_udp,
            name=f"dns-udp-{self.port}",
            daemon=True,
        )
        tcp_thread = threading.Thread(
            target=self._run_tcp,
            name=f"dns-tcp-{self.port}",
            daemon=True,
        )

        udp_thread.start()
        tcp_thread.start()

        # Block until stop is requested (so the manager's thread stays alive)
        self._stop_event.wait()

    def stop(self) -> None:
        """Shut down both listeners."""
        self._stop_event.set()
        if self._udp_socket:
            try:
                self._udp_socket.close()
            except OSError:
                pass
        if self._tcp_socket:
            try:
                self._tcp_socket.close()
            except OSError:
                pass
