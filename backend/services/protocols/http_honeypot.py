"""
HTTPHoneypot -- serves fake web pages and captures all requests.
"""

import json
import logging
import socket
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from io import BytesIO

from services import deception

logger = logging.getLogger(__name__)


# Default pages served by the honeypot
_LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Login</title>
<style>
  body { font-family: Arial, sans-serif; background: #f4f4f4; display: flex;
         justify-content: center; align-items: center; height: 100vh; margin: 0; }
  .login-box { background: white; padding: 40px; border-radius: 8px;
               box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 320px; }
  h2 { text-align: center; color: #333; }
  input { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box;
          border: 1px solid #ddd; border-radius: 4px; }
  button { width: 100%; padding: 10px; background: #007bff; color: white;
           border: none; border-radius: 4px; cursor: pointer; }
</style>
</head>
<body>
<div class="login-box">
  <h2>System Login</h2>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign In</button>
  </form>
</div>
</body>
</html>
"""

_NOT_FOUND = """<!DOCTYPE html>
<html><head><title>404 Not Found</title></head>
<body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server</address>
</body></html>
"""

_LOGIN_RESPONSE = """<!DOCTYPE html>
<html><head><title>Login</title></head>
<body><h2>Invalid credentials. Please try again.</h2>
<a href="/login">Back to login</a>
</body></html>
"""


class HTTPHoneypot:
    """
    Lightweight HTTP honeypot using the stdlib http.server module.
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
        honeypot = self  # capture reference for the handler
        self._bait = deception.build_site_for(self.app)

        class Handler(BaseHTTPRequestHandler):
            server_version = "Apache/2.4.52"
            sys_version = "(Ubuntu)"

            def log_message(self, format, *args):
                logger.debug("HTTP %s", format % args)

            def _check_throttle(self):
                if honeypot.connection_throttler and honeypot.connection_throttler.is_blocked(
                    self.client_address[0], "http"
                ):
                    self._send(429, "Too Many Requests", content_type="text/plain")
                    return True
                return False

            # -- GET ---------------------------------------------------------
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

            # -- POST --------------------------------------------------------
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

            # -- PUT / DELETE / etc. ----------------------------------------
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

            # -- helper ------------------------------------------------------
            def _send(self, code, content, content_type="text/html"):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                if isinstance(content, str):
                    content = content.encode()
                self.wfile.write(content)

        try:
            self._server = HTTPServer(("0.0.0.0", self.port), Handler)
            self._server.timeout = 1.0
            logger.info("HTTP honeypot listening on port %d", self.port)

            while not self._stop_event.is_set():
                self._server.handle_request()
        except OSError as exc:
            logger.error("HTTP honeypot could not bind port %d: %s", self.port, exc)

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

    def _log_request(self, handler: BaseHTTPRequestHandler, body: bytes | None) -> None:
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
                # Credential capture
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
                    "protocol": "http",
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "destination_port": self.port,
                    "severity": severity,
                    "user_agent": user_agent,
                    "details": details,
                    "raw_payload": body.decode("utf-8", errors="replace")[:8192] if body else None,
                })
