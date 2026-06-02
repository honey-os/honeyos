"""
FTPHoneypot -- minimal FTP protocol emulation that captures credentials
and file-transfer attempts.
"""

import logging
import os
import posixpath
import socket
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fake filesystem tree
# ---------------------------------------------------------------------------
_FAKE_FS: dict = {
    "/": {
        "type": "dir",
        "children": {
            "backups": {"type": "dir", "children": {
                "db-2026-05-28.sql.gz": {"type": "file", "size": 245760},
                "db-2026-05-30.sql.gz": {"type": "file", "size": 251904},
            }},
            "config": {"type": "dir", "children": {
                "app.conf": {"type": "file", "size": 1024},
                "credentials.txt": {"type": "file", "size": 512},
            }},
            "www": {"type": "dir", "children": {
                "index.html": {"type": "file", "size": 4096},
                "upload": {"type": "dir", "children": {}},
            }},
            "readme.txt": {"type": "file", "size": 2048},
            "database.sql": {"type": "file", "size": 15360},
        },
    },
}


def _resolve_path(cwd: str, arg: str) -> str:
    """Resolve *arg* relative to *cwd*, returning an absolute POSIX path.

    Handles ``/absolute``, ``relative``, ``.`` and ``..``.  The result is
    always normalised and never escapes the root ``/``.
    """
    if not arg or arg == ".":
        return cwd
    if arg.startswith("/"):
        raw = arg
    else:
        raw = cwd.rstrip("/") + "/" + arg
    resolved = posixpath.normpath(raw)
    # normpath("//foo") can return "//foo" — force single leading slash
    if not resolved.startswith("/"):
        resolved = "/" + resolved
    return resolved


def _get_node(path: str) -> dict | None:
    """Walk *_FAKE_FS* and return the node at *path*, or ``None``."""
    path = posixpath.normpath(path)
    if path == "/":
        return _FAKE_FS["/"]
    parts = [p for p in path.split("/") if p]
    node = _FAKE_FS["/"]
    for part in parts:
        if node.get("type") != "dir":
            return None
        children = node.get("children", {})
        if part not in children:
            return None
        node = children[part]
    return node


def _format_listing(path: str) -> str:
    """Return an ``ls -l`` style listing for the directory at *path*."""
    node = _get_node(path)
    if node is None or node.get("type") != "dir":
        return ""
    lines: list[str] = []
    children = node.get("children", {})
    for name, info in sorted(children.items()):
        if info["type"] == "dir":
            lines.append(
                f"drwxr-xr-x   2 root  root   4096 May 28 10:30 {name}"
            )
        else:
            size = info.get("size", 0)
            lines.append(
                f"-rw-r--r--   1 root  root  {size:>5} May 28 10:30 {name}"
            )
    return "\r\n".join(lines) + "\r\n" if lines else ""


def _format_nlst(path: str) -> str:
    """Return a plain filename listing (NLST) for the directory at *path*."""
    node = _get_node(path)
    if node is None or node.get("type") != "dir":
        return ""
    names = sorted(node.get("children", {}).keys())
    return "\r\n".join(names) + "\r\n" if names else ""


def _fake_file_content(filename: str, size: int = 0) -> bytes:
    """Generate plausible fake content based on the file extension."""
    lower = filename.lower()
    if lower == "credentials.txt":
        return (
            b"# Internal service credentials -- DO NOT SHARE\n"
            b"admin_user=sysadmin\n"
            b"admin_pass=Pr0d#Secret!42\n"
            b"db_host=10.0.3.12\n"
            b"db_user=app_rw\n"
            b"db_pass=xK9$mQ2wL7!\n"
            b"api_key=sk-live-4f8a2b1c9e3d7f6a0b5c8d2e1f4a7b3c\n"
        )
    if lower.endswith((".sql", ".sql.gz")):
        return (
            b"-- MySQL dump 10.13  Distrib 8.0.36\n"
            b"-- Host: localhost    Database: production\n\n"
            b"CREATE TABLE `users` (\n"
            b"  `id` int NOT NULL AUTO_INCREMENT,\n"
            b"  `email` varchar(255) DEFAULT NULL,\n"
            b"  `password_hash` varchar(255) DEFAULT NULL,\n"
            b"  PRIMARY KEY (`id`)\n"
            b") ENGINE=InnoDB;\n"
        )
    if lower.endswith(".conf"):
        return (
            b"[server]\n"
            b"listen = 0.0.0.0\n"
            b"port = 8080\n"
            b"workers = 4\n"
            b"debug = false\n"
            b"secret_key = change-me-in-production\n"
        )
    if lower.endswith(".html"):
        return (
            b"<!DOCTYPE html>\n<html>\n<head><title>Welcome</title></head>\n"
            b"<body><h1>It works!</h1></body>\n</html>\n"
        )
    # Generic fallback
    target = max(size, 64)
    line = b"The quick brown fox jumps over the lazy dog.\n"
    reps = max(target // len(line), 1)
    return line * reps


class FTPHoneypot:
    """
    Socket-based FTP honeypot implementing the minimum set of FTP
    commands needed to lure and log attackers.
    """

    BANNER = "220 (vsFTPd 3.0.5)\r\n"

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
        # so set FTP_PASV_ADDRESS or PUBLIC_IP to the host/public IP.
        self._pasv_address = (
            self.config.get("pasv_address")
            or os.getenv("FTP_PASV_ADDRESS", "")
            or os.getenv("PUBLIC_IP", "")
        )
        if not self._pasv_address:
            self._pasv_address = self._detect_public_ip()
        # Fixed port range for PASV data connections.  These must be mapped
        # through Docker (e.g. 40000-40004:40000-40004).  Using ephemeral
        # port 0 doesn't work in Docker because the random port isn't exposed.
        self._pasv_port_min = int(self.config.get("pasv_port_min", 40000))
        self._pasv_port_max = int(self.config.get("pasv_port_max", 40049))

    # ------------------------------------------------------------------
    # Public IP detection (same pattern as PostgreSQL honeypot)
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_public_ip() -> str:
        """Query ipify for the real public IP.

        Returns the IP string on success, or empty string on failure so
        the PASV handler can fall back to the socket's local address.
        """
        try:
            import requests as _req
            resp = _req.get("https://api.ipify.org?format=json", timeout=5)
            resp.raise_for_status()
            ip = resp.json().get("ip")
            if ip:
                return ip
        except Exception:
            pass
        return ""

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
                if self.connection_throttler and (
                    self.connection_throttler.is_blocked(addr[0], "ftp")
                    or not self.connection_throttler.track_connect(addr[0], "ftp")
                ):
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
    # Data channel helpers
    # ------------------------------------------------------------------

    def _open_pasv_socket(self) -> tuple[socket.socket, int] | tuple[None, int]:
        """Open a TCP listener for PASV data connections.

        Only uses ports from the configured fixed range (required for Docker,
        where only mapped ports are reachable).  Returns ``(None, 0)`` if the
        entire range is busy — callers must handle this gracefully.
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

        logger.warning("FTP PASV port range %d-%d exhausted",
                        self._pasv_port_min, self._pasv_port_max)
        return None, 0

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
    def _recv_via_data(data_sock: socket.socket, max_bytes: int = 1048576) -> bytes:
        """Accept one connection on *data_sock*, recv up to *max_bytes*, close."""
        try:
            conn, _ = data_sock.accept()
            try:
                chunks: list[bytes] = []
                total = 0
                while total < max_bytes:
                    chunk = conn.recv(min(8192, max_bytes - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                return b"".join(chunks)
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
        cwd = "/"
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
                cmd_time = datetime.now(timezone.utc)
                reply: str | None = None  # control-channel reply text

                # --- FTP command handling --------------------------------

                if cmd == "USER":
                    username = arg
                    reply = "331 Password required"
                    client_sock.sendall(b"331 Password required\r\n")

                elif cmd == "PASS":
                    password = arg
                    authenticated = True
                    reply = "230 Login successful"
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
                    reply = "215 UNIX Type: L8"
                    client_sock.sendall(b"215 UNIX Type: L8\r\n")

                elif cmd == "FEAT":
                    reply = "211-Features:\n PASV\n UTF8\n211 End"
                    client_sock.sendall(b"211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n")

                elif cmd == "OPTS":
                    reply = f"200 {arg} OK"
                    client_sock.sendall(f"200 {arg} OK\r\n".encode())

                elif cmd == "AUTH":
                    auth_type = arg.upper()
                    reply = f"504 AUTH {auth_type} not supported"
                    client_sock.sendall(f"504 AUTH {auth_type} not supported\r\n".encode())

                elif cmd == "PWD":
                    reply = f'257 "{cwd}" is current directory'
                    client_sock.sendall(f'257 "{cwd}" is current directory\r\n'.encode())

                elif cmd == "CWD":
                    target = _resolve_path(cwd, arg)
                    node = _get_node(target)
                    if node and node.get("type") == "dir":
                        cwd = target
                        reply = f"250 Directory changed to {cwd}"
                        client_sock.sendall(f"250 Directory changed to {cwd}\r\n".encode())
                    else:
                        reply = "550 No such directory"
                        client_sock.sendall(b"550 No such directory\r\n")

                elif cmd == "CDUP":
                    cwd = posixpath.dirname(cwd) or "/"
                    reply = f'250 Directory changed to {cwd}'
                    client_sock.sendall(f"250 Directory changed to {cwd}\r\n".encode())

                elif cmd == "TYPE":
                    reply = "200 Type set"
                    client_sock.sendall(b"200 Type set\r\n")

                elif cmd == "SIZE":
                    target = _resolve_path(cwd, arg)
                    node = _get_node(target)
                    if node and node.get("type") == "file":
                        sz = node.get("size", 0)
                        reply = f"213 {sz}"
                        client_sock.sendall(f"213 {sz}\r\n".encode())
                    else:
                        reply = "550 File not found"
                        client_sock.sendall(b"550 File not found\r\n")

                elif cmd == "MDTM":
                    target = _resolve_path(cwd, arg)
                    node = _get_node(target)
                    if node and node.get("type") == "file":
                        reply = "213 20260528103000"
                        client_sock.sendall(b"213 20260528103000\r\n")
                    else:
                        reply = "550 File not found"
                        client_sock.sendall(b"550 File not found\r\n")

                elif cmd == "REST":
                    reply = "350 Restart position accepted"
                    client_sock.sendall(b"350 Restart position accepted\r\n")

                elif cmd == "PASV":
                    # Close any previous PASV socket
                    if pasv_sock:
                        try:
                            pasv_sock.close()
                        except OSError:
                            pass
                    active_addr = None
                    pasv_sock, pasv_port = self._open_pasv_socket()
                    if pasv_sock is None:
                        reply = "425 No data ports available"
                        client_sock.sendall(b"425 No data ports available\r\n")
                    else:
                        # Use configured address (for Docker) or the socket's
                        # local address (for bare-metal / dev).
                        pasv_ip = self._pasv_address or client_sock.getsockname()[0]
                        ip_parts = pasv_ip.replace(".", ",")
                        p1, p2 = pasv_port >> 8, pasv_port & 0xFF
                        reply = f"227 Entering Passive Mode ({ip_parts},{p1},{p2})"
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
                        reply = "200 PORT command successful"
                        client_sock.sendall(b"200 PORT command successful\r\n")
                    except (ValueError, IndexError):
                        reply = "501 Syntax error in PORT"
                        client_sock.sendall(b"501 Syntax error in PORT\r\n")

                elif cmd == "EPSV":
                    if pasv_sock:
                        try:
                            pasv_sock.close()
                        except OSError:
                            pass
                    active_addr = None
                    pasv_sock, pasv_port = self._open_pasv_socket()
                    if pasv_sock is None:
                        reply = "425 No data ports available"
                        client_sock.sendall(b"425 No data ports available\r\n")
                    else:
                        reply = f"229 Entering Extended Passive Mode (|||{pasv_port}|)"
                        client_sock.sendall(
                            f"229 Entering Extended Passive Mode (|||{pasv_port}|)\r\n".encode()
                        )

                elif cmd == "LIST" or cmd == "NLST":
                    # Determine which path to list
                    list_path = _resolve_path(cwd, arg) if arg else cwd
                    if cmd == "LIST":
                        listing = _format_listing(list_path).encode()
                    else:
                        listing = _format_nlst(list_path).encode()
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
                        reply = "150 Opening data connection\n226 Transfer complete"
                        client_sock.sendall(b"226 Transfer complete\r\n")
                    else:
                        reply = "425 Can't open data connection"
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
                            "details": {"command": line, "path": list_path},
                        })

                elif cmd == "RETR":
                    target = _resolve_path(cwd, arg)
                    node = _get_node(target)
                    if node and node.get("type") == "file":
                        content = _fake_file_content(
                            posixpath.basename(target),
                            node.get("size", 0),
                        )
                        sent = False
                        if pasv_sock:
                            client_sock.sendall(b"150 Opening data connection\r\n")
                            try:
                                self._send_via_data(pasv_sock, content)
                                sent = True
                            except OSError:
                                pass
                            pasv_sock = None
                        elif active_addr:
                            client_sock.sendall(b"150 Opening data connection\r\n")
                            conn = self._connect_active(*active_addr)
                            if conn:
                                try:
                                    conn.sendall(content)
                                finally:
                                    conn.close()
                                sent = True
                            active_addr = None

                        if sent:
                            reply = "150 Opening data connection\n226 Transfer complete"
                            client_sock.sendall(b"226 Transfer complete\r\n")
                        else:
                            reply = "425 Can't open data connection"
                            client_sock.sendall(b"425 Can't open data connection\r\n")

                        severity = "medium"
                    else:
                        reply = "550 File not found"
                        client_sock.sendall(b"550 File not found\r\n")
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
                            "details": {"command": "RETR", "argument": arg},
                        })

                    if self.session_recorder and session_id:
                        self.session_recorder.record_file_transfer(
                            session_id, arg, "download"
                        )

                elif cmd == "STOR":
                    # Accept upload — this is the highest-value capture
                    uploaded = b""
                    sent = False
                    if pasv_sock:
                        client_sock.sendall(b"150 Opening data connection\r\n")
                        try:
                            uploaded = self._recv_via_data(pasv_sock)
                            sent = True
                        except OSError:
                            pass
                        pasv_sock = None
                    elif active_addr:
                        client_sock.sendall(b"150 Opening data connection\r\n")
                        conn = self._connect_active(*active_addr)
                        if conn:
                            try:
                                chunks: list[bytes] = []
                                total = 0
                                max_bytes = 1048576
                                while total < max_bytes:
                                    chunk = conn.recv(min(8192, max_bytes - total))
                                    if not chunk:
                                        break
                                    chunks.append(chunk)
                                    total += len(chunk)
                                uploaded = b"".join(chunks)
                                sent = True
                            finally:
                                conn.close()
                        active_addr = None

                    if sent:
                        client_sock.sendall(b"226 Transfer complete\r\n")
                        logger.info(
                            "FTP STOR captured %d bytes from %s: %s",
                            len(uploaded), addr[0], arg,
                        )
                        # Build a readable preview for session replay
                        text_preview = ""
                        if uploaded:
                            try:
                                text_preview = uploaded[:512].decode("utf-8", errors="replace")
                            except Exception:
                                text_preview = uploaded[:256].hex()
                        reply = (
                            f"226 Transfer complete\n"
                            f"[Captured {len(uploaded)} bytes]\n"
                            f"{text_preview}"
                        )
                    else:
                        reply = "425 Can't open data connection"
                        client_sock.sendall(b"425 Can't open data connection\r\n")

                    upload_preview = uploaded[:4096].hex() if uploaded else ""
                    if self.event_processor:
                        self.event_processor.process_event({
                            "event_type": "file_operation",
                            "protocol": "ftp",
                            "source_ip": addr[0],
                            "source_port": addr[1],
                            "destination_port": self.port,
                            "severity": "critical",
                            "session_id": session_id,
                            "details": {
                                "command": "STOR",
                                "argument": arg,
                                "upload_size": len(uploaded),
                                "upload_preview": upload_preview,
                            },
                        })

                    if self.session_recorder and session_id:
                        self.session_recorder.record_file_transfer(
                            session_id, arg, "upload"
                        )

                elif cmd in ("DELE", "MKD", "RMD"):
                    reply = "550 Permission denied"
                    client_sock.sendall(b"550 Permission denied\r\n")
                    severity = "high" if cmd == "DELE" else "medium"

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
                    # Record before breaking
                    if self.session_recorder and session_id:
                        self.session_recorder.record_command(
                            session_id, line, cmd_time, output="221 Goodbye",
                        )
                    break

                elif cmd == "NOOP":
                    reply = "200 OK"
                    client_sock.sendall(b"200 OK\r\n")

                else:
                    reply = f"502 Command not implemented: {cmd}"
                    client_sock.sendall(f"502 Command not implemented: {cmd}\r\n".encode())

                # Record command with server reply
                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id, line, cmd_time, output=reply,
                    )

        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            logger.debug("FTP connection lost for %s (scanner/probe)", addr[0])
        except Exception:
            logger.exception("FTP handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
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
