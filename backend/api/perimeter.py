"""
Perimeter API blueprint.

Provides endpoints for declared port management, drift detection,
Shodan exposure lookups, and banner comparison.
"""

from flask import Blueprint, current_app, jsonify, request

from models import DeclaredPort, PerimeterScan, ShodanSnapshot, db
from models import _iso_utc

perimeter_bp = Blueprint("perimeter", __name__)


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

@perimeter_bp.route("/api/perimeter/status", methods=["GET"])
def perimeter_status():
    """Summary of current perimeter state."""
    from config import Config

    svc = current_app.perimeter_service
    ip = svc.detect_public_ip()

    last_scan = PerimeterScan.query.order_by(PerimeterScan.timestamp.desc()).first()
    declared_count = DeclaredPort.query.count()

    snapshot = ShodanSnapshot.query.filter_by(ip=ip).first() if ip else None

    return jsonify({
        "public_ip": ip,
        "shodan_configured": bool(Config.SHODAN_API_KEY),
        "drift_detected": last_scan.drift_detected if last_scan else False,
        "honeypot_flagged": snapshot.honeypot_flagged if snapshot else False,
        "last_scan": _iso_utc(last_scan.timestamp) if last_scan else None,
        "declared_count": declared_count,
        "unexpected_count": len(last_scan.to_dict().get("unexpected_ports") or []) if last_scan else 0,
        "missing_count": len(last_scan.to_dict().get("missing_ports") or []) if last_scan else 0,
    })


# ---------------------------------------------------------------------------
# Declared Ports
# ---------------------------------------------------------------------------

@perimeter_bp.route("/api/perimeter/declared-ports", methods=["GET"])
def list_declared_ports():
    """List all declared ports."""
    ports = DeclaredPort.query.order_by(DeclaredPort.port).all()
    return jsonify({"items": [p.to_dict() for p in ports]})


@perimeter_bp.route("/api/perimeter/declared-ports", methods=["POST"])
def add_declared_port():
    """Add a user-declared port."""
    data = request.get_json(force=True)
    port = data.get("port")
    label = data.get("label", "")
    transport = data.get("transport", "tcp")

    if not port or not label:
        return jsonify({"error": "validation", "message": "port and label are required"}), 400

    existing = DeclaredPort.query.filter_by(port=port, transport=transport).first()
    if existing:
        return jsonify({"error": "conflict", "message": f"Port {port}/{transport} already declared"}), 409

    dp = DeclaredPort(port=port, transport=transport, label=label, source="user")
    db.session.add(dp)
    db.session.commit()
    return jsonify(dp.to_dict()), 201


@perimeter_bp.route("/api/perimeter/declared-ports/<int:port_id>", methods=["DELETE"])
def remove_declared_port(port_id: int):
    """Remove a user-declared port. Rejects honeypot-sourced entries."""
    dp = DeclaredPort.query.get(port_id)
    if not dp:
        return jsonify({"error": "not_found", "message": "Declared port not found"}), 404
    if dp.source == "honeypot":
        return jsonify({"error": "forbidden", "message": "Cannot remove honeypot-managed port. Disable the honeypot instead."}), 403

    db.session.delete(dp)
    db.session.commit()
    return "", 204


@perimeter_bp.route("/api/perimeter/declared-ports/sync", methods=["POST"])
def sync_declared_ports():
    """Re-sync declared ports from enabled honeypots."""
    svc = current_app.perimeter_service
    svc.sync_honeypot_ports()
    ports = DeclaredPort.query.order_by(DeclaredPort.port).all()
    return jsonify({"items": [p.to_dict() for p in ports]})


# ---------------------------------------------------------------------------
# Drift Scans
# ---------------------------------------------------------------------------

@perimeter_bp.route("/api/perimeter/scans", methods=["GET"])
def list_scans():
    """Paginated list of drift scan results."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    q = PerimeterScan.query.order_by(PerimeterScan.timestamp.desc())
    pagination = q.paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        "items": [s.to_dict() for s in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    })


@perimeter_bp.route("/api/perimeter/scan", methods=["POST"])
def trigger_scan():
    """Trigger a drift check and return the result."""
    svc = current_app.perimeter_service
    scan = svc.run_drift_check()
    if not scan:
        return jsonify({"error": "failed", "message": "Could not detect public IP"}), 500
    return jsonify(scan.to_dict()), 201


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------

@perimeter_bp.route("/api/perimeter/shodan", methods=["GET"])
def get_shodan():
    """Latest ShodanSnapshot for our public IP."""
    svc = current_app.perimeter_service
    ip = svc.detect_public_ip()
    if not ip:
        return jsonify(None)

    snapshot = ShodanSnapshot.query.filter_by(ip=ip).first()
    return jsonify(snapshot.to_dict() if snapshot else None)


@perimeter_bp.route("/api/perimeter/shodan/refresh", methods=["POST"])
def refresh_shodan():
    """Trigger a fresh Shodan lookup."""
    from config import Config

    if not Config.SHODAN_API_KEY:
        return jsonify({"error": "not_configured", "message": "SHODAN_API_KEY not set"}), 400

    svc = current_app.perimeter_service
    ip = svc.detect_public_ip()
    if not ip:
        return jsonify({"error": "failed", "message": "Could not detect public IP"}), 500

    with current_app.app_context():
        snapshot = svc.lookup_shodan(ip)
    if not snapshot:
        return jsonify({"error": "failed", "message": "Shodan lookup returned no data"}), 404
    return jsonify(snapshot.to_dict())


# ---------------------------------------------------------------------------
# Banner Comparison
# ---------------------------------------------------------------------------

@perimeter_bp.route("/api/perimeter/banners", methods=["GET"])
def banner_comparison():
    """Compare configured honeypot banners against Shodan-captured banners."""
    svc = current_app.perimeter_service
    with current_app.app_context():
        results = svc.get_banner_comparison()
    return jsonify({"items": results})
