"""
FTPHoneypot -- minimal FTP protocol emulation that captures credentials
and file-transfer attempts.
"""

import logging
import os
import socket
import ssl
import threading
from datetime import datetime, timezone

from utils.tls import ensure_self_signed_cert

logger = logging.getLogger(__name__)

# Fake directory listing in UNIX ls format
_DIR_LISTING = (
    "drwxr-xr-x   2 root  root   4096 Jan 12 08:30 backups\r\n"
    "drwxr-xr-x   3 root  root   4096 Jan 10 14:22 config\r\n"
    "-rw-r--r--   1 root  root   2048 Jan 11 09:15 readme.txt\r\n"
    "-rw-r--r--   1 root  root  15360 Jan 13 16:00 database.sql\r\n"
)


class FTPHoneypot:
    """
    Socket-based FTP honeypot implementing the minimum set of FTP
    commands needed to lure and log attackers.
    """

    BANNER = "220 FTP Server Ready\r\n"

    def __init__(self, port, config=None, event_processor=None,
                 session_recorder=None, app=None, connection_throttler=None):
        self.port = port
        self.config = config or {}
        self.event_processor = event_processor
        self.session_recorder = session_recorder
        self.app = app
        self.connection_throttler = connection_throttler
        self._server_socket: socket.socket | None = None
        self._stop_event = threading.Event()

        # Passive-mode data channel settings.
        # pasv_address: IP to advertise in PASV responses.  Inside Docker the
        # socket's local address is the container IP (unreachable from outside),
        # so set FTP_PASV_ADDRESS to the host/public IP.
        self._pasv_address = (
            self.config.get("pasv_address")
            or os.getenv("FTP_PASV_ADDRESS", "")
        )
        # Fixed port range for PASV data connections.  These must be mapped
        # through Docker (e.g. 4400-4404:4400-4404).  Using ephemeral port 0
        # doesn't work in Docker because the random port isn't exposed.
        self._pasv_port_min = int(self.config.get("pasv_port_min", 4400))
        self._pasv_port_max = int(self.config.get("pasv_port_max", 4404))

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
            logger.info("FTP honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("FTP honeypot could not bind port %d: %s", self.port, exc)
            return

        while not self._stop_event.is_set():
            try:
                client, addr = self._server_socket.accept()
                if self.connection_throttler and self.connection_throttler.is_blocked(addr[0], "ftp"):
                    client.close()
                    continue
                t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if not self._stop_event.is_set():
                    logger.exception("FTP accept error")
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

    # ------------------------------------------------------------------
    # Data channel helpers
    # ------------------------------------------------------------------

    def _open_pasv_socket(self) -> tuple[socket.socket, int]:
        """Open a TCP listener for PASV data connections.

        Tries each port in the configured fixed range first (required for
        Docker, where only mapped ports are reachable).  Falls back to an
        ephemeral port if the entire range is busy.
        """
        for port in range(self._pasv_port_min, self._pasv_port_max + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
                s.listen(1)
                s.settimeout(10)
                return s, port
            except OSError:
                s.close()

        # Range exhausted — fall back to ephemeral (works outside Docker)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 0))
        s.listen(1)
        s.settimeout(10)
        return s, s.getsockname()[1]

    @staticmethod
    def _send_via_data(data_sock: socket.socket, payload: bytes) -> None:
        """Accept one connection on *data_sock*, send *payload*, close."""
        try:
            conn, _ = data_sock.accept()
            try:
                conn.sendall(payload)
            finally:
                conn.close()
        finally:
            data_sock.close()

    @staticmethod
    def _connect_active(host: str, port: int) -> socket.socket | None:
        """Connect to the client's PORT address for active-mode transfers."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            return s
        except OSError:
            return None

    # ------------------------------------------------------------------
    # Connection handler
    # ------------------------------------------------------------------

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        from models import db as _db
        session_id = None
        username = ""
        # Pending PASV listener (socket, port) or None
        pasv_sock: socket.socket | None = None
        # Pending PORT target (host, port) or None
        active_addr: tuple[str, int] | None = None
        app_ctx = self.app.app_context() if self.app else None
        if app_ctx:
            app_ctx.push()
        try:
            client_sock.settimeout(120)
            client_sock.sendall(self.BANNER.encode())

            # Start session
            if self.session_recorder:
                sess = self.session_recorder.start_session(addr[0], "ftp")
                session_id = sess.id

            authenticated = False
            tls_active = False

            while not self._stop_event.is_set():
                try:
                    data = client_sock.recv(1024)
                except (socket.timeout, ConnectionResetError, OSError, ssl.SSLError):
                    break
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                logger.debug("FTP %s from %s: %s", cmd, addr[0], line)

                # Record command
                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id, line, datetime.now(timezone.utc)
                    )

                # --- FTP command handling --------------------------------

                if cmd == "USER":
                    username = arg
                    client_sock.sendall(b"331 Password required\r\n")

                elif cmd == "PASS":
                    password = arg
                    authenticated = True
                    client_sock.sendall(b"230 Login successful\r\n")
                    logger.info("FTP login  user=%s  pass=%s  from=%s", username, password, addr[0])

                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "authentication",
                            "protocol": "ftp",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "high",
                            "session_id": session_id,
                            "details": {"username": username, "password": password},
                        })

                elif cmd == "SYST":
                    client_sock.sendall(b"215 UNIX Type: L8\r\n")

                elif cmd == "FEAT":
                    client_sock.sendall(b"211-Features:\r\n AUTH TLS\r\n PASV\r\n PBSZ\r\n PROT\r\n UTF8\r\n211 End\r\n")

                elif cmd == "AUTH":
                    auth_type = arg.upper()
                    if tls_active:
                        client_sock.sendall(b"503 TLS already active\r\n")
                    elif auth_type in ("TLS", "SSL"):
                        try:
                            cert_path, key_path = ensure_self_signed_cert()
                            client_sock.sendall(b"234 AUTH TLS successful\r\n")
                            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
                            client_sock = ctx.wrap_socket(client_sock, server_side=True)
                            tls_active = True
                            logger.info("FTP TLS handshake completed for %s", addr[0])
                        except ssl.SSLError as exc:
                            logger.warning("FTP TLS handshake failed for %s: %s", addr[0], exc)
                            break
                    else:
                        client_sock.sendall(f"504 AUTH {auth_type} not supported\r\n".encode())

                elif cmd == "PBSZ":
                    client_sock.sendall(b"200 PBSZ=0\r\n")

                elif cmd == "PROT":
                    prot_level = arg.upper()
                    if prot_level in ("P", "C"):
                        client_sock.sendall(f"200 Protection level set to {prot_level}\r\n".encode())
                    else:
                        client_sock.sendall(f"504 Protection level {prot_level} not supported\r\n".encode())

                elif cmd == "PWD":
                    client_sock.sendall(b'257 "/" is current directory\r\n')

                elif cmd == "CWD":
                    client_sock.sendall(b"250 Directory changed\r\n")

                elif cmd == "TYPE":
                    client_sock.sendall(b"200 Type set\r\n")

                elif cmd == "PASV":
                    # Close any previous PASV socket
                    if pasv_sock:
                        try:
                            pasv_sock.close()
                        except OSError:
                            pass
                    active_addr = None
                    pasv_sock, pasv_port = self._open_pasv_socket()
                    # Use configured address (for Docker) or the socket's
                    # local address (for bare-metal / dev).
                    pasv_ip = self._pasv_address or client_sock.getsockname()[0]
                    ip_parts = pasv_ip.replace(".", ",")
                    p1, p2 = pasv_port >> 8, pasv_port & 0xFF
                    client_sock.sendall(
                        f"227 Entering Passive Mode ({ip_parts},{p1},{p2})\r\n".encode()
                    )

                elif cmd == "PORT":
                    # Parse PORT h1,h2,h3,h4,p1,p2
                    if pasv_sock:
                        try:
                            pasv_sock.close()
                        except OSError:
                            pass
                        pasv_sock = None
                    try:
                        nums = [int(x) for x in arg.split(",")]
                        host = f"{nums[0]}.{nums[1]}.{nums[2]}.{nums[3]}"
                        port_num = nums[4] * 256 + nums[5]
                        active_addr = (host, port_num)
                        client_sock.sendall(b"200 PORT command successful\r\n")
                    except (ValueError, IndexError):
                        client_sock.sendall(b"501 Syntax error in PORT\r\n")

                elif cmd == "EPSV":
                    if pasv_sock:
                        try:
                            pasv_sock.close()
                        except OSError:
                            pass
                    active_addr = None
                    pasv_sock, pasv_port = self._open_pasv_socket()
                    client_sock.sendall(
                        f"229 Entering Extended Passive Mode (|||{pasv_port}|)\r\n".encode()
                    )

                elif cmd == "LIST" or cmd == "NLST":
                    listing = _DIR_LISTING.encode() if cmd == "LIST" else b"backups\r\nconfig\r\nreadme.txt\r\ndatabase.sql\r\n"
                    sent = False

                    if pasv_sock:
                        client_sock.sendall(b"150 Opening data connection\r\n")
                        try:
                            self._send_via_data(pasv_sock, listing)
                            sent = True
                        except OSError:
                            pass
                        pasv_sock = None
                    elif active_addr:
                        client_sock.sendall(b"150 Opening data connection\r\n")
                        conn = self._connect_active(*active_addr)
                        if conn:
                            try:
                                conn.sendall(listing)
                            finally:
                                conn.close()
                            sent = True
                        active_addr = None

                    if sent:
                        client_sock.sendall(b"226 Transfer complete\r\n")
                    else:
                        client_sock.sendall(b"425 Can't open data connection\r\n")

                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "directory_listing",
                            "protocol": "ftp",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "low",
                            "session_id": session_id,
                            "details": {"command": line},
                        })

                elif cmd in ("RETR", "STOR", "DELE", "MKD", "RMD"):
                    # File-transfer or modification attempt
                    if cmd == "RETR":
                        client_sock.sendall(b"550 File not found\r\n")
                        severity = "medium"
                    elif cmd == "STOR":
                        client_sock.sendall(b"553 Permission denied\r\n")
                        severity = "high"
                    elif cmd == "DELE":
                        client_sock.sendall(b"550 Permission denied\r\n")
                        severity = "high"
                    else:
                        client_sock.sendall(b"550 Permission denied\r\n")
                        severity = "medium"

                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "file_operation",
                            "protocol": "ftp",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": severity,
                            "session_id": session_id,
                            "details": {"command": cmd, "argument": arg},
                        })

                    if self.session_recorder and session_id:
                        direction = "download" if cmd == "RETR" else "upload"
                        self.session_recorder.record_file_transfer(
                            session_id, arg, direction
                        )

                elif cmd == "QUIT":
                    client_sock.sendall(b"221 Goodbye\r\n")
                    break

                elif cmd == "NOOP":
                    client_sock.sendall(b"200 OK\r\n")

                else:
                    client_sock.sendall(f"502 Command not implemented: {cmd}\r\n".encode())

        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            logger.debug("FTP connection lost for %s (scanner/probe)", addr[0])
        except Exception:
            logger.exception("FTP handler error for %s", addr)
        finally:
            if pasv_sock:
                try:
                    pasv_sock.close()
                except OSError:
                    pass
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
            if app_ctx:
                _db.session.remove()
                app_ctx.pop()
