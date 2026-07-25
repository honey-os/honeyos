"""
CanaryWebhookServer -- standalone HTTP listener for canarytokens.org triggers.

Runs on its own port (Config.WEBHOOK_PORT, default 7779), deliberately
separate from the admin API and every honeypot port, so inbound triggers
never interact with admin authentication and never look like honeypot
traffic.  Authentication is the per-install random path secret
(/canarytokens/<secret>); a miss returns 404.
"""

import hmac
import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


class CanaryWebhookServer:
    def __init__(self, port, app=None, event_processor=None):
        self.port = port
        self.app = app
        self.event_processor = event_processor
        self._server: HTTPServer | None = None
        self._stop_event = threading.Event()

    # -- Core dispatch (socket-free, unit-testable) ---------------------
    def dispatch(self, path: str, body: bytes) -> tuple[int, dict]:
        """Validate the path secret and record the trigger.
        Returns (status_code, json_body)."""
        from api.webhooks import get_webhook_secret, record_canary_trigger

        prefix = "/canarytokens/"
        if not path.startswith(prefix):
            return 404, {"error": "not found"}
        supplied = path[len(prefix):].split("?", 1)[0]

        if self.app is None or self.event_processor is None:
            return 503, {"error": "unavailable"}

        with self.app.app_context():
            if not hmac.compare_digest(supplied, get_webhook_secret()):
                return 404, {"error": "not found"}
            try:
                payload = json.loads(body.decode("utf-8")) if body else {}
                if not isinstance(payload, dict):
                    payload = {}
            except (ValueError, UnicodeDecodeError):
                payload = {}
            record_canary_trigger(payload, self.event_processor)
        return 200, {"status": "ok"}

    def run(self) -> None:
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "nginx"
            sys_version = ""

            def log_message(self, fmt, *args):
                logger.debug("WEBHOOK %s", fmt % args)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b""
                try:
                    code, payload = server.dispatch(self.path, body)
                except Exception:
                    logger.exception("Webhook dispatch failed")
                    code, payload = 500, {"error": "internal"}
                self._send(code, payload)

            def do_GET(self):
                # Nothing to enumerate here; look like an ordinary 404.
                self._send(404, {"error": "not found"})

            def _send(self, code, payload):
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        try:
            self._server = HTTPServer(("0.0.0.0", self.port), Handler)
            self._server.timeout = 1.0
            logger.info("Canary webhook listening on port %d", self.port)
            while not self._stop_event.is_set():
                self._server.handle_request()
        except OSError as exc:
            logger.error("Webhook server could not bind port %d: %s", self.port, exc)

    def start(self) -> None:
        threading.Thread(target=self.run, daemon=True, name="webhook").start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
