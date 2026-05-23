"""
Honeypots API blueprint.
"""

import json

from flask import Blueprint, jsonify, request

from models import Honeypot, db
from utils.helpers import generate_id

honeypots_bp = Blueprint("honeypots", __name__)


@honeypots_bp.route("/api/honeypots", methods=["GET"])
def list_honeypots():
    """List all honeypots."""
    honeypots = Honeypot.query.order_by(Honeypot.name).all()
    return jsonify({
        "honeypots": [h.to_dict() for h in honeypots],
        "total": len(honeypots),
    })


@honeypots_bp.route("/api/honeypots", methods=["POST"])
def create_honeypot():
    """Create a new honeypot configuration."""
    data = request.get_json(force=True)

    # Validate required fields
    for field in ("name", "protocol", "port"):
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Check for port conflict
    existing = Honeypot.query.filter_by(port=data["port"]).first()
    if existing:
        return jsonify({"error": f"Port {data['port']} is already in use"}), 409

    honeypot = Honeypot(
        id=generate_id(),
        name=data["name"],
        protocol=data["protocol"],
        port=int(data["port"]),
        enabled=data.get("enabled", True),
        description=data.get("description", ""),
        config=json.dumps(data.get("config", {})),
        total_interactions=0,
    )
    db.session.add(honeypot)
    db.session.commit()

    return jsonify(honeypot.to_dict()), 201


@honeypots_bp.route("/api/honeypots/<honeypot_id>", methods=["PUT"])
def update_honeypot(honeypot_id: str):
    """Update an existing honeypot."""
    honeypot = Honeypot.query.get(honeypot_id)
    if honeypot is None:
        return jsonify({"error": "Honeypot not found"}), 404

    data = request.get_json(force=True)

    if "name" in data:
        honeypot.name = data["name"]
    if "protocol" in data:
        honeypot.protocol = data["protocol"]
    if "port" in data:
        new_port = int(data["port"])
        conflict = Honeypot.query.filter(
            Honeypot.port == new_port, Honeypot.id != honeypot_id
        ).first()
        if conflict:
            return jsonify({"error": f"Port {new_port} is already in use"}), 409
        honeypot.port = new_port
    if "enabled" in data:
        honeypot.enabled = bool(data["enabled"])
    if "description" in data:
        honeypot.description = data["description"]
    if "config" in data:
        honeypot.config = json.dumps(data["config"])

    db.session.commit()
    return jsonify(honeypot.to_dict())


@honeypots_bp.route("/api/honeypots/<honeypot_id>", methods=["DELETE"])
def delete_honeypot(honeypot_id: str):
    """Delete a honeypot."""
    honeypot = Honeypot.query.get(honeypot_id)
    if honeypot is None:
        return jsonify({"error": "Honeypot not found"}), 404

    db.session.delete(honeypot)
    db.session.commit()
    return jsonify({"message": "Honeypot deleted", "id": honeypot_id})
