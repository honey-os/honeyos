"""
System Configuration API blueprint.
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from models import Alert, Honeypot, SystemConfig, db
from utils.helpers import generate_id
from api.auth import AUTH_INTERNAL_KEYS

config_bp = Blueprint("config", __name__)


@config_bp.route("/api/config", methods=["GET"])
def get_all_config():
    """Return all system configuration entries."""
    configs = SystemConfig.query.order_by(SystemConfig.key).all()
    return jsonify([c.to_dict() for c in configs if c.key not in AUTH_INTERNAL_KEYS])


@config_bp.route("/api/config", methods=["PUT"])
def update_config():
    """
    Bulk update configuration entries.

    Body (JSON):
        { "key1": "value1", "key2": "value2", ... }
    """
    data = request.get_json(force=True)

    updated = []
    for key, value in data.items():
        if key in AUTH_INTERNAL_KEYS:
            continue
        config_entry = SystemConfig.query.get(key)
        if config_entry:
            config_entry.value = str(value) if not isinstance(value, str) else value
        else:
            config_entry = SystemConfig(
                key=key,
                value=str(value) if not isinstance(value, str) else value,
                description="",
                config_type="string",
            )
            db.session.add(config_entry)
        updated.append(key)

    db.session.commit()

    return jsonify({
        "message": "Configuration updated",
        "updated_keys": updated,
    })


@config_bp.route("/api/config/export", methods=["GET"])
def export_config():
    """
    Export all configuration, honeypots, and alerts as a single JSON blob.
    """
    configs = SystemConfig.query.all()
    honeypots = Honeypot.query.all()
    alerts = Alert.query.all()

    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "version": "1.0",
        "config": [c.to_dict() for c in configs if c.key not in AUTH_INTERNAL_KEYS],
        "honeypots": [h.to_dict() for h in honeypots],
        "alerts": [a.to_dict() for a in alerts],
    }

    return jsonify(export_data)


@config_bp.route("/api/config/import", methods=["POST"])
def import_config():
    """
    Import configuration from a previously exported JSON blob.

    Replaces all config entries, honeypots, and alerts with the imported data.
    """
    data = request.get_json(force=True)

    imported_counts = {"config": 0, "honeypots": 0, "alerts": 0}

    # --- System config ---
    if "config" in data:
        # Preserve auth keys across import
        saved_auth = {
            row.key: row
            for row in SystemConfig.query.filter(
                SystemConfig.key.in_(AUTH_INTERNAL_KEYS)
            ).all()
        }
        # Remove existing entries
        SystemConfig.query.delete()
        # Re-add auth keys
        for row in saved_auth.values():
            db.session.add(SystemConfig(
                key=row.key, value=row.value,
                description=row.description, config_type=row.config_type,
            ))
        for entry in data["config"]:
            if entry.get("key") in AUTH_INTERNAL_KEYS:
                continue
            sc = SystemConfig(
                key=entry["key"],
                value=entry.get("value", ""),
                description=entry.get("description", ""),
                config_type=entry.get("config_type", "string"),
            )
            db.session.add(sc)
            imported_counts["config"] += 1

    # --- Honeypots ---
    if "honeypots" in data:
        Honeypot.query.delete()
        for entry in data["honeypots"]:
            hp = Honeypot(
                id=entry.get("id") or generate_id(),
                name=entry["name"],
                protocol=entry["protocol"],
                port=int(entry["port"]),
                enabled=entry.get("enabled", True),
                description=entry.get("description", ""),
                config=json.dumps(entry.get("config", {})),
                total_interactions=entry.get("total_interactions", 0),
            )
            db.session.add(hp)
            imported_counts["honeypots"] += 1

    # --- Alerts ---
    if "alerts" in data:
        Alert.query.delete()
        for entry in data["alerts"]:
            al = Alert(
                id=entry.get("id") or generate_id(),
                name=entry["name"],
                enabled=entry.get("enabled", True),
                alert_type=entry["alert_type"],
                config=json.dumps(entry.get("config", {})),
                conditions=json.dumps(entry.get("conditions", {})),
                send_count=entry.get("send_count", 0),
            )
            db.session.add(al)
            imported_counts["alerts"] += 1

    db.session.commit()

    return jsonify({
        "message": "Import completed",
        "imported": imported_counts,
    })
