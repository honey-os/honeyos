"""
HTTPSHoneypot -- TLS-wrapped HTTP honeypot.

Reuses the same fake pages and request logging as the HTTP honeypot,
but listens over TLS with an auto-generated self-signed certificate.
"""

import logging
import os
import socket
import ssl
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

# Import page templates and logging helper from the HTTP honeypot
from services import deception
from services.protocols.http_honeypot import (
    _LOGIN_PAGE,
    _NOT_FOUND,
    _LOGIN_RESPONSE,
)
from utils.tls import ensure_self_signed_cert


class HTTPSHoneypot:
    """
    HTTPS honeypot -- identical behaviour to HTTPHoneypot but served
    over TLS with a self-signed certificate.
    """

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None, connection_throttler=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self.connection_throttler = connection_throttler
        self._server: HTTPServer | None = None
        self._stop_event = threading.Event()
        self._bait: dict = {}

    def run(self) -> None:
        honeypot = self
        self._bait = deception.build_site_for(self.app)

        class Handler(BaseHTTPRequestHandler):
            server_version = "Apache/2.4.52"
            sys_version = "(Ubuntu)"

            def log_message(self, format, *args):
                logger.debug("HTTPS %s", format % args)

            def _check_throttle(self):
                if honeypot.connection_throttler and honeypot.connection_throttler.is_blocked(
                    self.client_address[0], "https"
                ):
                    self._send(429, "Too Many Requests", content_type="text/plain")
                    return True
                return False

            def do_GET(self):
                if self._check_throttle():
                    return
                honeypot._log_request(self, body=None)
                bait = honeypot._bait.get(self.path)
                if bait is not None:
                    self._send(200, bait[0], content_type=bait[1])
                elif self.path in ("/login", "/admin", "/wp-login.php",
                                   "/administrator"):
                    self._send(200, _LOGIN_PAGE)
                else:
                    self._send(404, _NOT_FOUND)

            def do_POST(self):
                if self._check_throttle():
                    return
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                honeypot._log_request(self, body=body)
                if self.path in ("/login", "/admin", "/wp-login.php"):
                    self._send(200, _LOGIN_RESPONSE)
                else:
                    self._send(404, _NOT_FOUND)

            def do_PUT(self):
                if self._check_throttle():
                    return
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""
                honeypot._log_request(self, body=body)
                self._send(403, "<h1>403 Forbidden</h1>")

            def do_DELETE(self):
                if self._check_throttle():
                    return
                honeypot._log_request(self, body=None)
                self._send(403, "<h1>403 Forbidden</h1>")

            def _send(self, code, content, content_type="text/html"):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                if isinstance(content, str):
                    content = content.encode()
                self.wfile.write(content)

        try:
            cert_path, key_path = ensure_self_signed_cert()

            self._server = HTTPServer(("0.0.0.0", self.port), Handler)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            self._server.socket = ctx.wrap_socket(
                self._server.socket, server_side=True,
            )

            self._server.timeout = 1.0
            logger.info("HTTPS honeypot listening on port %d", self.port)

            while not self._stop_event.is_set():
                self._server.handle_request()
        except OSError as exc:
            logger.error("HTTPS honeypot could not bind port %d: %s",
                         self.port, exc)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Event logging
    # ------------------------------------------------------------------

    def _log_request(self, handler: BaseHTTPRequestHandler,
                     body: bytes | None) -> None:
        client_ip = handler.client_address[0]
        client_port = handler.client_address[1]
        user_agent = handler.headers.get("User-Agent", "")
        path = handler.path
        method = handler.command

        details: dict = {
            "method": method,
            "path": path,
            "headers": dict(handler.headers),
        }

        severity = "low"

        if body:
            try:
                body_str = body.decode("utf-8", errors="replace")
                details["body"] = body_str[:4096]
                if "password" in body_str.lower() or "passwd" in body_str.lower():
                    severity = "high"
                    details["credential_attempt"] = True
            except Exception:
                details["body_size"] = len(body)

        if path in deception.SENSITIVE_PATHS:
            severity = "high"
            details["bait_accessed"] = True

        if self.event_processor and self.app:
            with self.app.app_context():
                self.event_processor.process_event({
                    "event_type": "http_request",
                    "protocol": "https",
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "destination_port": self.port,
                    "severity": severity,
                    "user_agent": user_agent,
                    "details": details,
                    "raw_payload": body.decode("utf-8", errors="replace")[:8192] if body else None,
                })
