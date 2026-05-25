"""
FTPHoneypot -- minimal FTP protocol emulation that captures credentials
and file-transfer attempts.
"""

import logging
import socket
import threading
from datetime import datetime, timezone

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
            logger.info("FTP honeypot listening on port %d", self.port)
        except OSError as exc:
            logger.error("FTP honeypot could not bind port %d: %s", self.port, exc)
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

    @staticmethod
    def _open_pasv_socket() -> tuple[socket.socket, int]:
        """Open an ephemeral TCP socket for PASV data connections.
        Returns (socket, port)."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 0))
        s.listen(1)
        s.settimeout(10)
        port = s.getsockname()[1]
        return s, port

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
        session_id = None
        username = ""
        # Pending PASV listener (socket, port) or None
        pasv_sock: socket.socket | None = None
        # Pending PORT target (host, port) or None
        active_addr: tuple[str, int] | None = None
        try:
            client_sock.settimeout(120)
            client_sock.sendall(self.BANNER.encode())

            # Start session
            if self.session_recorder and self.app:
                with self.app.app_context():
                    sess = self.session_recorder.start_session(addr[0], "ftp")
                    session_id = sess.id

            authenticated = False

            while not self._stop_event.is_set():
                try:
                    data = client_sock.recv(1024)
                except (socket.timeout, ConnectionResetError, OSError):
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
                if self.session_recorder and session_id and self.app:
                    with self.app.app_context():
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

                    if self.event_processor and self.app:
                        with self.app.app_context():
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
                    client_sock.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")

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
                    # Encode the local IP and port into the PASV response
                    local_ip = client_sock.getsockname()[0]
                    ip_parts = local_ip.replace(".", ",")
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

                    if self.event_processor and self.app:
                        with self.app.app_context():
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

                    if self.event_processor and self.app:
                        with self.app.app_context():
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

                    if self.session_recorder and session_id and self.app:
                        direction = "download" if cmd == "RETR" else "upload"
                        with self.app.app_context():
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

        except Exception:
            logger.exception("FTP handler error for %s", addr)
        finally:
            if pasv_sock:
                try:
                    pasv_sock.close()
                except OSError:
                    pass
            if session_id and self.session_recorder and self.app:
                with self.app.app_context():
                    self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
