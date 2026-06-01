"""
TelnetHoneypot -- socket-based telnet server capturing credentials and commands.

The shell emulation is deliberately realistic enough to fool automated loaders
(Mirai-family, etc.) that probe via compound commands, busybox echo canaries,
and writable-directory discovery.
"""

import logging
import re
import socket
import struct
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fake command responses
# ---------------------------------------------------------------------------

_COMMAND_RESPONSES = {
    "whoami": "admin",
    "id": "uid=0(root) gid=0(root)",
    "uname -a": "Linux gateway 3.10.14 #1 SMP armv7l GNU/Linux",
    "uname -m": "armv7l",
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
        "model name\t: ARMv7 Processor rev 4 (v7l)\n"
        "BogoMIPS\t: 38.40\n"
        "Features\t: half thumb fastmult vfp edsp neon vfpv3 tls vfpv4 "
        "idiva idivt vfpd32 lpae evtstrm\n"
        "CPU implementer\t: 0x41\n"
        "CPU architecture: 7\n"
        "CPU variant\t: 0x0\n"
        "CPU part\t: 0xd03\n"
        "CPU revision\t: 4\n"
        "\n"
        "Hardware\t: BCM2835\n"
        "Revision\t: a02082\n"
        "Serial\t\t: 00000000deadbeef"
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
_SILENT_OK_PREFIXES = ("cd", "rm", "cp", "mv", "mkdir", "touch")

# Valid 52-byte ARM 32-bit little-endian ELF header.
# Bots read this via cat/hexdump/dd to determine CPU architecture before
# downloading the matching payload.
_ARM_ELF_HEADER: bytes = (
    b"\x7fELF"              # e_ident: magic
    b"\x01\x01\x01\x00"     # ELFCLASS32, ELFDATA2LSB, EV_CURRENT, SYSV ABI
    + b"\x00" * 8            # EI_ABIVERSION + padding (completes 16-byte e_ident)
    + struct.pack(
        "<HHIIIIIHHHHHH",
        2,            # e_type: ET_EXEC
        0x28,         # e_machine: EM_ARM (40)
        1,            # e_version: EV_CURRENT
        0x00008354,   # e_entry
        0x34,         # e_phoff (52)
        0x0001A4F0,   # e_shoff
        0x05000000,   # e_flags: EF_ARM_ABI_VER5
        0x34,         # e_ehsize (52)
        0x20,         # e_phentsize (32)
        8,            # e_phnum
        0x28,         # e_shentsize (40)
        30,           # e_shnum
        27,           # e_shstrndx
    )
)


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



# ---------------------------------------------------------------------------
# Telnet IAC (Interpret As Command) constants
# ---------------------------------------------------------------------------
_IAC = bytes([255])   # Interpret As Command
_WILL = bytes([251])
_WONT = bytes([252])
_DO = bytes([253])
_DONT = bytes([254])

# Telnet options
_OPT_ECHO = bytes([1])
_OPT_SUPPRESS_GO_AHEAD = bytes([3])
_OPT_LINEMODE = bytes([34])
_OPT_NAWS = bytes([31])   # Negotiate About Window Size
_OPT_TTYPE = bytes([24])  # Terminal Type

# Standard IAC negotiation sent on connect -- mimics a BusyBox/Linux telnetd
_IAC_NEGOTIATION = (
    _IAC + _WILL + _OPT_ECHO
    + _IAC + _WILL + _OPT_SUPPRESS_GO_AHEAD
    + _IAC + _WONT + _OPT_LINEMODE
    + _IAC + _DO + _OPT_NAWS
    + _IAC + _DO + _OPT_TTYPE
)


class TelnetHoneypot:
    """Fake telnet server recording credentials and commands."""

    BANNER = "\r\nWelcome to Gateway Management Console\r\n"
    FAKE_HOSTNAME = "gateway"

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
                if self.connection_throttler and (
                    self.connection_throttler.is_blocked(addr[0], "telnet")
                    or not self.connection_throttler.track_connect(addr[0], "telnet")
                ):
                    client.close()
                    continue
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
        from models import db as _db

        session_id = None
        ctx = self.app.app_context() if self.app else None
        if ctx:
            ctx.push()
        try:
            client_sock.settimeout(120)

            # IAC option negotiation (required for scanners to identify as telnet)
            client_sock.sendall(_IAC_NEGOTIATION)

            # Drain any IAC responses the client sends back (DO/DONT/WILL/WONT)
            self._drain_iac(client_sock)

            # Banner
            client_sock.sendall(self.BANNER.encode())

            # Login
            username = self._readline(client_sock, prompt="login: ")
            password = self._readline(client_sock, prompt="Password: ", echo=False)

            # Log credential attempt
            if self.event_processor:
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
            if self.session_recorder:
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

                cmd_time = datetime.now(timezone.utc)

                if self.event_processor:
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
                if isinstance(response, bytes):
                    client_sock.sendall(response + b"\r\n")
                    response_text = response.decode("utf-8", errors="replace")
                else:
                    client_sock.sendall((response + "\r\n").encode())
                    response_text = response
                client_sock.sendall(prompt)

                # Record command with server response
                if self.session_recorder and session_id:
                    self.session_recorder.record_command(
                        session_id, cmd, cmd_time,
                        output=response_text or None,
                    )

        except (ConnectionResetError, BrokenPipeError, OSError):
            logger.debug("Telnet connection lost for %s", addr[0])
        except Exception:
            logger.exception("Telnet handler error for %s", addr)
        finally:
            if self.connection_throttler:
                self.connection_throttler.track_disconnect(addr[0])
            if session_id and self.session_recorder:
                self.session_recorder.end_session(session_id)
            if ctx:
                _db.session.remove()
                ctx.pop()
            try:
                client_sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Shell emulation
    # ------------------------------------------------------------------

    def _execute_line(self, line: str) -> str | bytes:
        """Execute a compound command line, handling ``;``, ``&&``, ``||``."""
        output_parts: list[str | bytes] = []

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

        # If any part is bytes, convert everything to bytes
        if any(isinstance(p, bytes) for p in output_parts):
            return b"\n".join(
                p if isinstance(p, bytes) else p.encode()
                for p in output_parts
            )
        return "\n".join(output_parts)  # type: ignore[arg-type]

    def _execute_single(self, cmd: str) -> tuple[str | bytes, bool]:
        """Execute one simple command.  Returns ``(output, success)``."""
        cmd = cmd.strip()
        if not cmd:
            return "", True

        # --- Output redirect: >file (create empty file, silent success) ---
        if cmd.startswith(">"):
            return "", True

        # --- Strip busybox path prefixes ---
        for prefix in ("/bin/busybox ", "/usr/bin/busybox ", "busybox "):
            if cmd.startswith(prefix):
                cmd = cmd[len(prefix):]
                break

        # --- Pipes: execute first command only (best-effort) ---
        if "|" in cmd:
            cmd = cmd.split("|", 1)[0].strip()

        # --- Architecture probes (ELF header reads) ---
        arch_result = self._handle_arch_probe(cmd)
        if arch_result is not None:
            return arch_result

        # --- Built-in: echo ---
        if cmd == "echo" or cmd.startswith("echo "):
            return self._handle_echo(cmd), True

        # --- Built-in: printf (common in Mirai loaders) ---
        if cmd.startswith("printf "):
            return self._handle_printf(cmd), True

        # --- Silent-success commands: cd, rm, cp, mv, mkdir, touch ---
        base = cmd.split()[0] if cmd.split() else cmd
        # strip any path prefix on the command name (e.g. /bin/rm -> rm)
        base_name = base.rsplit("/", 1)[-1]
        if base_name in _SILENT_OK_PREFIXES:
            return "", True

        # --- Built-in: cat (file-not-found for unknown files) ---
        if base_name == "cat":
            return self._handle_cat(cmd)

        # --- Built-in: chmod (error on missing files) ---
        if base_name == "chmod":
            return self._handle_chmod(cmd)

        # --- Download commands: log the URL, return realistic failure ---
        if base_name in ("wget", "curl", "tftp"):
            return self._handle_download(cmd, base_name)

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

        # --- Unknown command / file execution ---
        # Preserve the typed path (e.g. "./i" not "i") and use the
        # correct error for path-based execution attempts.
        if "/" in base:
            return f"-sh: {base}: No such file or directory", False
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

    def _handle_cat(self, cmd: str) -> tuple[str | bytes, bool]:
        """Handle ``cat`` with realistic file-not-found errors.

        Known files (from the static response table and arch probes) return
        their content; everything else returns the standard BusyBox error.
        """
        # Check static responses first (e.g. "cat /etc/passwd")
        response = _COMMAND_RESPONSES.get(cmd)
        if response is not None:
            return response, True

        # Arch probes handled separately (returns bytes)
        arch_result = self._handle_arch_probe(cmd)
        if arch_result is not None:
            return arch_result

        # Extract the filename argument, stripping any output redirect
        args = cmd.split(None, 1)[1] if " " in cmd else ""
        if ">" in args:
            args = args[:args.index(">")].strip()
        if not args:
            return "", True

        return f"cat: {args}: No such file or directory", False

    @staticmethod
    def _handle_chmod(cmd: str) -> tuple[str, bool]:
        """Handle ``chmod`` with error on missing files.

        Real BusyBox chmod returns an error and exit code 1 when the
        target doesn't exist, which is important for ``||`` fallback
        chains in bot loaders.
        """
        parts = cmd.split()
        if len(parts) >= 3:
            target = parts[-1]
            return f"chmod: cannot access '{target}': No such file or directory", False
        return "", True

    def _handle_arch_probe(self, cmd: str) -> tuple[str | bytes, bool] | None:
        """Handle ELF architecture-probe commands.

        Mirai-family bots read the first 52 bytes of a system binary to
        extract the ``e_machine`` field and determine CPU architecture.
        Returns ``None`` if *cmd* is not an arch-probe command.
        """
        # cat /bin/ls  or  cat /bin/busybox  (pipe already stripped)
        if cmd in ("cat /bin/ls", "cat /bin/busybox"):
            return _ARM_ELF_HEADER + b"\x00" * 200, True

        # hexdump with /bin/ls or /bin/busybox
        if cmd.startswith("hexdump") and (
            "/bin/ls" in cmd or "/bin/busybox" in cmd
        ):
            return self._format_hexdump(_ARM_ELF_HEADER), True

        # dd with if=/bin/ls or if=/bin/busybox
        if cmd.startswith("dd") and (
            "if=/bin/ls" in cmd or "if=/bin/busybox" in cmd
        ):
            stats = b"1+0 records in\n1+0 records out\n52 bytes transferred"
            return _ARM_ELF_HEADER + b"\n" + stats, True

        return None

    @staticmethod
    def _format_hexdump(data: bytes) -> str:
        """Format *data* as BusyBox-style ``hexdump`` output.

        Default hexdump format: 7-digit hex offset followed by eight
        little-endian 16-bit words per line.
        """
        lines: list[str] = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset + 16]
            words: list[str] = []
            for i in range(0, len(chunk), 2):
                if i + 1 < len(chunk):
                    word = chunk[i] | (chunk[i + 1] << 8)
                    words.append(f"{word:04x}")
                else:
                    words.append(f"  {chunk[i]:02x}")
            lines.append(f"{offset:07x} " + " ".join(words))
        lines.append(f"{len(data):07x}")
        return "\n".join(lines)

    @staticmethod
    def _handle_download(cmd: str, tool: str) -> tuple[str, bool]:
        """Return realistic output for wget/curl/tftp.

        For ``wget`` without a URL (or with ``--help``), return BusyBox usage
        text with ``success=True`` so the bot believes wget is available.
        """
        if tool == "wget":
            parts = cmd.split()
            has_url = any(p.startswith("http") for p in parts[1:])
            if not has_url or "--help" in cmd:
                usage = (
                    "BusyBox v1.26.2 (2018-01-10 12:57:09 UTC) multi-call binary.\n"
                    "\n"
                    "Usage: wget [-c|--continue] [-s|--spider] [-q|--quiet] "
                    "[-O|--output-document FILE]\n"
                    "        [--header 'header: value'] [-Y|--proxy on/off] [-P DIR]\n"
                    "        [-U|--user-agent AGENT] [-T SEC] URL..."
                )
                return usage, True
            return "wget: can't connect to remote host: Connection refused", False
        elif tool == "curl":
            return "curl: (7) Failed to connect: Connection refused", False
        return "", False  # tftp fails silently

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _drain_iac(sock: socket.socket) -> None:
        """Consume any IAC responses the client sends after negotiation.

        Reads with a short timeout so we don't block if the client sends
        nothing (e.g. a scanner that just reads the banner).  IAC sequences
        are 3 bytes each (IAC + verb + option).  Subnegotiation (IAC SB ...)
        is consumed until IAC SE.
        """
        sock.settimeout(0.5)
        try:
            while True:
                b = sock.recv(1)
                if not b:
                    break
                if b[0] == 255:  # IAC
                    verb = sock.recv(1)
                    if not verb:
                        break
                    if verb[0] == 250:  # SB (subnegotiation)
                        # Read until IAC SE (255, 240)
                        while True:
                            c = sock.recv(1)
                            if not c:
                                return
                            if c[0] == 255:
                                se = sock.recv(1)
                                if not se or se[0] == 240:
                                    break
                    else:
                        # WILL/WONT/DO/DONT + option byte
                        sock.recv(1)
                else:
                    # Non-IAC data before login — ignore
                    break
        except (socket.timeout, OSError):
            pass
        finally:
            sock.settimeout(120)

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
