"""Tests for /health endpoint."""


class TestHealth:
    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"

    def test_health_includes_service_name(self, client):
        resp = client.get("/health")
        data = resp.get_json()
        assert data["service"] == "honeyos-backend"
