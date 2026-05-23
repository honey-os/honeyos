"""
SessionRecorder -- manages interactive session lifecycle and replay data.
"""

import json
import logging
from datetime import datetime, timezone

from models import Session, db
from utils.helpers import generate_id, parse_json_field

logger = logging.getLogger(__name__)


class SessionRecorder:
    """Create, update, and query interactive attacker sessions."""

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start_session(self, source_ip: str, protocol: str) -> Session:
        """Create and persist a new active session."""
        session = Session(
            id=generate_id(),
            source_ip=source_ip,
            protocol=protocol,
            start_time=datetime.now(timezone.utc),
            status="active",
            commands_count=0,
            keystrokes=json.dumps([]),
            commands=json.dumps([]),
            file_transfers=json.dumps([]),
        )
        db.session.add(session)
        db.session.commit()
        logger.info("Session %s started  ip=%s  proto=%s", session.id, source_ip, protocol)
        return session

    def end_session(self, session_id: str) -> Session | None:
        """Mark a session as completed and calculate its duration."""
        session = Session.query.get(session_id)
        if session is None:
            logger.warning("end_session called for unknown id %s", session_id)
            return None

        now = datetime.now(timezone.utc)
        session.end_time = now
        session.status = "completed"

        start = session.start_time
        if start and start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        session.duration_seconds = (now - start).total_seconds() if start else 0

        db.session.commit()
        logger.info("Session %s ended  duration=%.1fs", session_id, session.duration_seconds)
        return session

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_keystroke(self, session_id: str, keystroke: str, timestamp: datetime | None = None) -> bool:
        """Append a keystroke entry to the session's keystrokes JSON array."""
        session = Session.query.get(session_id)
        if session is None:
            return False

        ts = timestamp or datetime.now(timezone.utc)
        keystrokes = parse_json_field(session.keystrokes) or []
        keystrokes.append({
            "key": keystroke,
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })
        session.keystrokes = json.dumps(keystrokes)
        db.session.commit()
        return True

    def record_command(self, session_id: str, command: str, timestamp: datetime | None = None) -> bool:
        """Append a command entry and bump the counter."""
        session = Session.query.get(session_id)
        if session is None:
            return False

        ts = timestamp or datetime.now(timezone.utc)
        commands = parse_json_field(session.commands) or []
        commands.append({
            "command": command,
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })
        session.commands = json.dumps(commands)
        session.commands_count = len(commands)
        db.session.commit()
        return True

    def record_file_transfer(self, session_id: str, filename: str, direction: str, size: int = 0) -> bool:
        """Record a file transfer attempt."""
        session = Session.query.get(session_id)
        if session is None:
            return False

        transfers = parse_json_field(session.file_transfers) or []
        transfers.append({
            "filename": filename,
            "direction": direction,
            "size": size,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        session.file_transfers = json.dumps(transfers)
        db.session.commit()
        return True

    # ------------------------------------------------------------------
    # Replay
    # ------------------------------------------------------------------

    def get_replay_data(self, session_id: str) -> dict | None:
        """
        Build a replay-friendly structure for the frontend player.

        Returns a dict with metadata and a unified, time-sorted list of
        entries (keystrokes and commands interleaved).
        """
        session = Session.query.get(session_id)
        if session is None:
            return None

        keystrokes = parse_json_field(session.keystrokes) or []
        commands = parse_json_field(session.commands) or []

        # Build a unified timeline
        entries: list[dict] = []
        for ks in keystrokes:
            entries.append({
                "type": "keystroke",
                "data": ks.get("key", ""),
                "timestamp": ks.get("timestamp", ""),
            })
        for cmd in commands:
            entries.append({
                "type": "command",
                "data": cmd.get("command", ""),
                "timestamp": cmd.get("timestamp", ""),
            })

        # Sort by timestamp string (ISO-8601 sorts lexicographically)
        entries.sort(key=lambda e: e["timestamp"])

        return {
            "session_id": session.id,
            "source_ip": session.source_ip,
            "protocol": session.protocol,
            "start_time": session.start_time.isoformat() if session.start_time else None,
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "duration_seconds": session.duration_seconds,
            "status": session.status,
            "entries": entries,
        }
