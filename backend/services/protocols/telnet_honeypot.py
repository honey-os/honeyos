"""
TelnetHoneypot -- socket-based telnet server capturing credentials and commands.

The shell emulation is deliberately realistic enough to fool automated loaders
(Mirai-family, etc.) that probe via compound commands, busybox echo canaries,
and writable-directory discovery.
"""

import logging
import re
import socket
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fake command responses
# ---------------------------------------------------------------------------

_COMMAND_RESPONSES = {
    "whoami": "admin",
    "id": "uid=0(root) gid=0(root)",
    "uname -a": "Linux gateway 4.15.0-20-generic #21 SMP x86_64 GNU/Linux",
    "uname -m": "x86_64",
    "uname": "Linux",
    "hostname": "gateway",
    "pwd": "/home/admin",
    "ls": "bin  etc  log  tmp  www",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/sh\n"
        "admin:x:1000:1000:Admin:/home/admin:/bin/sh\n"
    ),
    "cat /proc/cpuinfo": (
        "processor\t: 0\n"
        "model name\t: Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz\n"
        "cpu MHz\t\t: 2300.000\n"
    ),
    "ifconfig": (
        "eth0      Link encap:Ethernet  HWaddr 00:11:22:33:44:55\n"
        "          inet addr:192.168.1.1  Bcast:192.168.1.255  Mask:255.255.255.0\n"
    ),
    "ps": (
        "  PID TTY      TIME CMD\n"
        "    1 ?    00:00:02 init\n"
        "  312 ?    00:00:00 syslogd\n"
        "  315 ?    00:00:00 telnetd\n"
        "  501 pts/0 00:00:00 sh"
    ),
    "mount": (
        "rootfs on / type rootfs (rw)\n"
        "proc on /proc type proc (rw)\n"
        "tmpfs on /tmp type tmpfs (rw)\n"
        "tmpfs on /var/run type tmpfs (rw)\n"
        "tmpfs on /dev/shm type tmpfs (rw)"
    ),
    "help": "Available commands: ls, cat, cd, whoami, id, uname, hostname, ifconfig, exit",
    "?": "Available commands: ls, cat, cd, whoami, id, uname, hostname, ifconfig, exit",
}

# Commands that succeed silently (exit code 0, no output)
_SILENT_OK_PREFIXES = ("cd", "chmod", "rm", "cp", "mv", "mkdir", "touch")


def _interpret_escapes(text: str) -> str:
    r"""Interpret C-style escape sequences: \xNN, \n, \t, \r, \\, etc."""
    _SIMPLE = {
        "\\n": "\n", "\\t": "\t", "\\r": "\r",
        "\\a": "\a", "\\b": "\b", "\\\\": "\\",
    }

    def _replace(m: re.Match) -> str:
        seq = m.group(0)
        if seq.startswith("\\x"):
            try:
                return chr(int(seq[2:4], 16))
            except ValueError:
                return seq
        return _SIMPLE.get(seq, seq)

    return re.sub(r"\\x[0-9a-fA-F]{2}|\\[ntrba\\]", _replace, text)


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

                # Record the raw line
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

                response = self._execute_line(cmd)
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
    # Shell emulation
    # ------------------------------------------------------------------

    def _execute_line(self, line: str) -> str:
        """Execute a compound command line, handling ``;``, ``&&``, ``||``."""
        output_parts: list[str] = []

        # Split on ; for independent command groups
        for group in line.split(";"):
            group = group.strip()
            if not group:
                continue

            # Split on && and || while preserving the operator
            tokens = re.split(r"(&&|\|\|)", group)

            prev_ok = True
            pending_op: str | None = None

            for token in tokens:
                token = token.strip()
                if not token:
                    continue

                if token in ("&&", "||"):
                    pending_op = token
                    continue

                # Decide whether to run based on the preceding operator
                should_run = True
                if pending_op == "&&" and not prev_ok:
                    should_run = False
                elif pending_op == "||" and prev_ok:
                    should_run = False

                if should_run:
                    result, ok = self._execute_single(token)
                    prev_ok = ok
                    if result:
                        output_parts.append(result)

                pending_op = None

        return "\n".join(output_parts)

    def _execute_single(self, cmd: str) -> tuple[str, bool]:
        """Execute one simple command.  Returns ``(output, success)``."""
        cmd = cmd.strip()
        if not cmd:
            return "", True

        # --- Output redirect: >file (create empty file, silent success) ---
        if cmd.startswith(">"):
            return "", True

        # --- Strip busybox path prefixes ---
        for prefix in ("/bin/busybox ", "/usr/bin/busybox "):
            if cmd.startswith(prefix):
                cmd = cmd[len(prefix):]
                break

        # --- Pipes: execute first command only (best-effort) ---
        if "|" in cmd:
            cmd = cmd.split("|", 1)[0].strip()

        # --- Built-in: echo ---
        if cmd == "echo" or cmd.startswith("echo "):
            return self._handle_echo(cmd), True

        # --- Built-in: printf (common in Mirai loaders) ---
        if cmd.startswith("printf "):
            return self._handle_printf(cmd), True

        # --- Silent-success commands: cd, chmod, rm, cp, mv, mkdir, touch ---
        base = cmd.split()[0] if cmd.split() else cmd
        # strip any path prefix on the command name (e.g. /bin/rm -> rm)
        base_name = base.rsplit("/", 1)[-1]
        if base_name in _SILENT_OK_PREFIXES:
            return "", True

        # --- Download commands: log the URL, return realistic failure ---
        if base_name in ("wget", "curl", "tftp"):
            return self._handle_download(cmd, base_name), False

        # --- Static response table ---
        response = _COMMAND_RESPONSES.get(cmd)
        if response is not None:
            return response, True

        # Also try with resolved base path (e.g. "/bin/ls" -> "ls")
        if "/" in base:
            short_cmd = base_name + cmd[len(base):]
            response = _COMMAND_RESPONSES.get(short_cmd)
            if response is not None:
                return response, True

        # --- Unknown command ---
        return f"-sh: {base_name}: not found", False

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    @staticmethod
    def _handle_echo(cmd: str) -> str:
        """Handle ``echo`` including ``-e`` with hex/C escape sequences."""
        args = cmd[5:] if len(cmd) > 5 else ""
        interpret_escapes = False

        # Consume leading flag arguments (-e, -n, -ne, -en, etc.)
        while args.startswith("-"):
            flag, _, rest = args.partition(" ")
            flag_chars = flag[1:]
            if flag_chars and all(c in "neE" for c in flag_chars):
                if "e" in flag_chars or "E" in flag_chars:
                    interpret_escapes = True
                args = rest
            else:
                break  # not a flag, treat as argument

        # Strip surrounding quotes
        text = args
        if len(text) >= 2 and (
            (text[0] == "'" and text[-1] == "'")
            or (text[0] == '"' and text[-1] == '"')
        ):
            text = text[1:-1]

        if interpret_escapes:
            text = _interpret_escapes(text)

        return text

    @staticmethod
    def _handle_printf(cmd: str) -> str:
        """Handle ``printf`` (always interprets escapes)."""
        args = cmd[7:]  # strip "printf "
        text = args.strip()
        if len(text) >= 2 and (
            (text[0] == "'" and text[-1] == "'")
            or (text[0] == '"' and text[-1] == '"')
        ):
            text = text[1:-1]
        return _interpret_escapes(text)

    @staticmethod
    def _handle_download(cmd: str, tool: str) -> str:
        """Return a realistic connection-refused error for wget/curl/tftp."""
        if tool == "wget":
            return "wget: can't connect to remote host: Connection refused"
        elif tool == "curl":
            return "curl: (7) Failed to connect: Connection refused"
        return ""  # tftp fails silently

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
