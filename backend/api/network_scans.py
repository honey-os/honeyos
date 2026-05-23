"""
Network Scans API blueprint.
"""

import threading

from flask import Blueprint, current_app, jsonify, request

from models import NetworkScan, db
from services.network_scanner import NetworkScanner
from utils.helpers import parse_json_field

network_scans_bp = Blueprint("network_scans", __name__)


@network_scans_bp.route("/api/network-scans", methods=["GET"])
def list_scans():
    """
    List network scans with pagination.

    Query params:
        limit  (int) default 50
        offset (int) default 0
    """
    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))

    total = NetworkScan.query.count()
    scans = (
        NetworkScan.query
        .order_by(NetworkScan.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return jsonify({
        "scans": [s.to_dict() for s in scans],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@network_scans_bp.route("/api/network-scans", methods=["POST"])
def initiate_scan():
    """
    Initiate a network scan.  Runs in a background thread.

    Body (JSON):
        target_host   (str)  required
        port_start    (int)  default 1
        port_end      (int)  default 1024
        scan_type     (str)  default "tcp"
    """
    data = request.get_json(force=True)
    target_host = data.get("target_host")
    if not target_host:
        return jsonify({"error": "target_host is required"}), 400

    port_start = int(data.get("port_start", 1))
    port_end = int(data.get("port_end", 1024))
    scan_type = data.get("scan_type", "tcp")

    # Capture a reference to the app for background thread context
    app = current_app._get_current_object()

    def _run_scan():
        with app.app_context():
            scanner = NetworkScanner()
            result = scanner.scan_ports(target_host, (port_start, port_end))
            result["scan_type"] = scan_type
            scanner.save_scan_result(result)

    thread = threading.Thread(target=_run_scan, daemon=True)
    thread.start()

    return jsonify({
        "message": "Scan initiated",
        "target_host": target_host,
        "port_range": [port_start, port_end],
        "scan_type": scan_type,
    }), 202


@network_scans_bp.route("/api/network-scans/<scan_id>/changes", methods=["GET"])
def get_scan_changes(scan_id: str):
    """Compare a scan with its predecessor and return changes."""
    scan = NetworkScan.query.get(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404

    current_ports = parse_json_field(scan.discovered_ports) or []

    if not scan.previous_scan_id:
        return jsonify({
            "scan_id": scan_id,
            "previous_scan_id": None,
            "changes_detected": False,
            "new_ports": current_ports,
            "closed_ports": [],
            "unchanged_ports": [],
            "message": "No previous scan to compare against",
        })

    previous = NetworkScan.query.get(scan.previous_scan_id)
    previous_ports = parse_json_field(previous.discovered_ports) if previous else []

    scanner = NetworkScanner()
    changes = scanner.detect_changes(current_ports, previous_ports or [])

    return jsonify({
        "scan_id": scan_id,
        "previous_scan_id": scan.previous_scan_id,
        **changes,
    })
