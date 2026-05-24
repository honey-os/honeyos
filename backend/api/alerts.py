"""
Alerts API blueprint.
"""

import json
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from models import Alert, Event, db
from services.alert_service import AlertService
from utils.helpers import generate_id

alerts_bp = Blueprint("alerts", __name__)


@alerts_bp.route("/api/alerts", methods=["GET"])
def list_alerts():
    """List all alert rules."""
    alerts = Alert.query.order_by(Alert.name).all()
    return jsonify([a.to_dict() for a in alerts])


@alerts_bp.route("/api/alerts", methods=["POST"])
def create_alert():
    """Create a new alert rule."""
    data = request.get_json(force=True)

    for field in ("name", "alert_type"):
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    alert = Alert(
        id=generate_id(),
        name=data["name"],
        enabled=data.get("enabled", True),
        alert_type=data["alert_type"],
        config=json.dumps(data.get("config", {})),
        conditions=json.dumps(data.get("conditions", {})),
        send_count=0,
    )
    db.session.add(alert)
    db.session.commit()

    return jsonify(alert.to_dict()), 201


@alerts_bp.route("/api/alerts/<alert_id>", methods=["PUT"])
def update_alert(alert_id: str):
    """Update an existing alert rule."""
    alert = Alert.query.get(alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404

    data = request.get_json(force=True)

    if "name" in data:
        alert.name = data["name"]
    if "enabled" in data:
        alert.enabled = bool(data["enabled"])
    if "alert_type" in data:
        alert.alert_type = data["alert_type"]
    if "config" in data:
        alert.config = json.dumps(data["config"])
    if "conditions" in data:
        alert.conditions = json.dumps(data["conditions"])

    db.session.commit()
    return jsonify(alert.to_dict())


@alerts_bp.route("/api/alerts/<alert_id>/test", methods=["POST"])
def test_alert(alert_id: str):
    """Send a test notification for an alert rule."""
    alert = Alert.query.get(alert_id)
    if alert is None:
        return jsonify({"error": "Alert not found"}), 404

    # Create a synthetic event for testing
    test_event = Event(
        id="test-" + generate_id(),
        event_type="test",
        protocol="test",
        source_ip="127.0.0.1",
        source_port=0,
        destination_port=0,
        timestamp=datetime.now(timezone.utc),
        severity="medium",
    )

    from flask import current_app
    service = AlertService(config=current_app.config)
    success = service.send_alert(alert, test_event)

    if success:
        return jsonify({"message": "Test alert sent successfully"})
    else:
        return jsonify({"error": "Failed to send test alert"}), 500
