"""
Honeypots API blueprint.
"""

from flask import Blueprint, jsonify

from models import Honeypot

honeypots_bp = Blueprint("honeypots", __name__)


@honeypots_bp.route("/api/honeypots", methods=["GET"])
def list_honeypots():
    """List all honeypots."""
    honeypots = Honeypot.query.order_by(Honeypot.name).all()
    return jsonify([h.to_dict() for h in honeypots])
