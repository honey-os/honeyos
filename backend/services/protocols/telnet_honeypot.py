"""
TelnetHoneypot -- socket-based telnet server capturing credentials and commands.
"""

import json
import logging
import socket
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Fake command responses
_COMMAND_RESPONSES = {
    "whoami": "admin",
    "id": "uid=0(root) gid=0(root)",
    "uname -a": "Linux gateway 4.15.0-20-generic #21 SMP x86_64 GNU/Linux",
    "hostname": "gateway",
    "pwd": "/home/admin",
    "ls": "bin  etc  log  tmp  www",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/sh\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/sh\n"
    ),
    "ifconfig": (
        "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55\n"
        "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
    ),
    "help": "Available commands: ls, cat, cd, whoami, id, uname, hostname, ifconfig, exit",
    "?": "Available commands: ls, cat, cd, whoami, id, uname, hostname, ifconfig, exit",
}


class TelnetHoneypot:
    """Fake telnet server recording credentials and commands."""

    BANNER = "\r\nWelcome to Gateway Management Console\r\n"
    FAKE_HOSTNAME = "gateway"

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()

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
            logger.info("Telnet honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("Telnet honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("Telnet accept error")
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
        session_id = None
        try:
            client_sock.settimeout(120)

            # Banner
            client_sock.sendall(self.BANNER.encode())

            # Login
            username = self._readline(client_sock, prompt="login: ")
            password = self._readline(client_sock, prompt="Password: ", echo=False)

            # Log credential attempt
            if self.event_processor and self.app:
                with self.app.app_context():
                    self.event_processor.process_event({
                        "event_type": "authentication",
                        "protocol": "telnet",
                        "source_ip": addr[0],
                        "source_port": addr[1],
                        "destination_port": self.port,
                        "severity": "high",
                        "details": {"username": username, "password": password},
                    })

            # Start session
            if self.session_recorder and self.app:
                with self.app.app_context():
                    sess = self.session_recorder.start_session(addr[0], "telnet")
                    session_id = sess.id

            client_sock.sendall(b"\r\nLogin successful.\r\n")
            prompt = f"{self.FAKE_HOSTNAME}> ".encode()
            client_sock.sendall(prompt)

            # Command loop
            while not self._stop_event.is_set():
                try:
                    command = self._readline(client_sock, prompt="")
                except (socket.timeout, ConnectionResetError, BrokenPipeError):
                    break

                if command is None:
                    break

                cmd = command.strip()
                if not cmd:
                    client_sock.sendall(prompt)
                    continue

                # Record
                if self.session_recorder and session_id and self.app:
                    with self.app.app_context():
                        self.session_recorder.record_command(
                            session_id, cmd, datetime.now(timezone.utc)
                        )

                if self.event_processor and self.app:
                    with self.app.app_context():
                        self.event_processor.process_event({
                            "event_type": "command",
                            "protocol": "telnet",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "medium",
                            "session_id": session_id,
                            "details": {"command": cmd},
                        })

                if cmd in ("exit", "quit", "logout"):
                    client_sock.sendall(b"Goodbye.\r\n")
                    break

                response = _COMMAND_RESPONSES.get(cmd)
                if response is None:
                    base = cmd.split()[0] if cmd.split() else cmd
                    if base in ("cd",):
                        response = ""
                    else:
                        response = f"-sh: {cmd}: not found"

                client_sock.sendall((response + "\r\n").encode())
                client_sock.sendall(prompt)

        except Exception:
            logger.exception("Telnet handler error for %s", addr)
        finally:
            if session_id and self.session_recorder and self.app:
                with self.app.app_context():
                    self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _readline(sock: socket.socket, prompt: str = "", echo: bool = True) -> str | None:
        """Read a line from the socket, optionally sending a prompt first."""
        if prompt:
            sock.sendall(prompt.encode())

        buf = b""
        while True:
            try:
                data = sock.recv(1)
            except (socket.timeout, ConnectionResetError, OSError):
                return None
            if not data:
                return None

            if data in (b"\r", b"\n"):
                sock.sendall(b"\r\n")
                break
            elif data in (b"\x7f", b"\x08"):
                if buf:
                    buf = buf[:-1]
                    if echo:
                        sock.sendall(b"\x08 \x08")
            else:
                buf += data
                if echo:
                    sock.sendall(data)

        return buf.decode("utf-8", errors="replace")
