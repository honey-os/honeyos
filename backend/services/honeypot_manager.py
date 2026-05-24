"""
HoneypotManager -- start / stop / query protocol-specific listeners.

Uses real OS threads (not eventlet green threads) so that blocking socket
operations in the honeypot listeners don't starve the eventlet event loop
that gunicorn relies on for heartbeats and request handling.
"""

import logging
from typing import Any

from eventlet.patcher import original

from models import Honeypot, db

# Get the *real* threading module before eventlet monkey-patches it.
_threading = original("threading")

logger = logging.getLogger(__name__)


class HoneypotManager:
    """
    Manages the lifecycle of honeypot listener threads.

    Each honeypot is identified by its database ID and mapped to a
    protocol-specific listener class.
    """

    PROTOCOL_MAP: dict[str, str] = {
        "ssh": "services.protocols.ssh_honeypot.SSHHoneypot",
        "http": "services.protocols.http_honeypot.HTTPHoneypot",
        "telnet": "services.protocols.telnet_honeypot.TelnetHoneypot",
        "ftp": "services.protocols.ftp_honeypot.FTPHoneypot",
        "mysql": "services.protocols.mysql_honeypot.MySQLHoneypot",
    }

    def __init__(self, app=None, event_processor=None, session_recorder=None):
        self.app = app
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        # honeypot_id -> {"thread": Thread, "instance": listener, "running": bool}
        self._running: dict[str, dict[str, Any]] = {}
        self._lock = _threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_honeypot(self, honeypot_config: dict) -> bool:
        """
        Launch the listener for a honeypot described by *honeypot_config*.

        Expected keys: id, protocol, port, config (optional dict).
        Returns True if started, False on error or already running.
        """
        hp_id = honeypot_config["id"]
        protocol = honeypot_config["protocol"].lower()

        with self._lock:
            if hp_id in self._running and self._running[hp_id].get("running"):
                logger.warning("Honeypot %s is already running", hp_id)
                return False

        listener_cls = self._resolve_class(protocol)
        if listener_cls is None:
            logger.error("No listener class for protocol '%s'", protocol)
            return False

        instance = listener_cls(
            port=honeypot_config["port"],
            config=honeypot_config.get("config") or {},
            event_processor=self.event_processor,
            session_recorder=self.session_recorder,
            app=self.app,
        )

        thread = _threading.Thread(
            target=instance.run,
            name=f"honeypot-{protocol}-{honeypot_config['port']}",
            daemon=True,
        )
        thread.start()

        with self._lock:
            self._running[hp_id] = {
                "thread": thread,
                "instance": instance,
                "running": True,
            }

        logger.info("Honeypot %s (%s:%d) started", hp_id, protocol, honeypot_config["port"])
        return True

    def stop_honeypot(self, honeypot_id: str) -> bool:
        """Stop a running honeypot listener."""
        with self._lock:
            entry = self._running.get(honeypot_id)
            if not entry or not entry.get("running"):
                logger.warning("Honeypot %s is not running", honeypot_id)
                return False

            instance = entry["instance"]
            try:
                instance.stop()
            except Exception:
                logger.exception("Error stopping honeypot %s", honeypot_id)

            entry["running"] = False
            logger.info("Honeypot %s stopped", honeypot_id)
            return True

    def get_status(self, honeypot_id: str) -> dict:
        """Return the running status for a honeypot."""
        with self._lock:
            entry = self._running.get(honeypot_id)
            if not entry:
                return {"id": honeypot_id, "running": False}
            return {
                "id": honeypot_id,
                "running": entry.get("running", False),
                "thread_alive": entry["thread"].is_alive() if entry.get("thread") else False,
            }

    def start_all_enabled(self) -> None:
        """Query the database for enabled honeypots and start them all."""
        honeypots = Honeypot.query.filter_by(enabled=True).all()
        for hp in honeypots:
            try:
                self.start_honeypot(hp.to_dict())
            except Exception:
                logger.exception("Failed to start honeypot %s", hp.id)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_class(protocol: str):
        """Dynamically import and return the listener class for *protocol*."""
        mapping = {
            "ssh": ("services.protocols.ssh_honeypot", "SSHHoneypot"),
            "http": ("services.protocols.http_honeypot", "HTTPHoneypot"),
            "telnet": ("services.protocols.telnet_honeypot", "TelnetHoneypot"),
            "ftp": ("services.protocols.ftp_honeypot", "FTPHoneypot"),
            "mysql": ("services.protocols.mysql_honeypot", "MySQLHoneypot"),
        }
        entry = mapping.get(protocol)
        if not entry:
            return None

        module_path, class_name = entry
        import importlib

        try:
            mod = importlib.import_module(module_path)
            return getattr(mod, class_name)
        except (ImportError, AttributeError) as exc:
            logger.error("Could not import %s.%s: %s", module_path, class_name, exc)
            return None
