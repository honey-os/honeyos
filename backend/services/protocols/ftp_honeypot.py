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

    def _handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        session_id = None
        username = ""
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
                    # Send a fake PASV response (connection will fail for
                    # actual data transfer, which is fine -- we log the intent)
                    client_sock.sendall(b"227 Entering Passive Mode (127,0,0,1,0,0)\r\n")

                elif cmd == "LIST" or cmd == "NLST":
                    client_sock.sendall(b"150 Opening data connection\r\n")
                    # We cannot actually send data over a data channel without
                    # a real PASV socket, but we log the attempt.
                    client_sock.sendall(b"226 Transfer complete\r\n")

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
            if session_id and self.session_recorder and self.app:
                with self.app.app_context():
                    self.session_recorder.end_session(session_id)
            try:
                client_sock.close()
            except OSError:
                pass
