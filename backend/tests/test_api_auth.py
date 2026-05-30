"""Tests for backend/api/auth.py"""

import json


class TestAuthStatus:
    def test_no_admin_configured(self, client):
        resp = client.get("/api/auth/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["has_admin"] is False
        assert data["authenticated"] is False


class TestAuthSetup:
    def test_setup_creates_admin(self, client):
        resp = client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["message"] == "Admin account created"
        # Should set session cookie
        assert "honeyos_session" in resp.headers.get("Set-Cookie", "")

    def test_duplicate_setup_returns_403(self, client):
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "anotherpass123"}),
            content_type="application/json",
        )
        assert resp.status_code == 403

    def test_short_password_returns_400(self, client):
        resp = client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "short"}),
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "8 characters" in resp.get_json()["message"]


class TestAuthLogin:
    def _setup_admin(self, client):
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )

    def test_successful_login(self, client):
        self._setup_admin(client)
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        assert "honeyos_session" in resp.headers.get("Set-Cookie", "")

    def test_wrong_password_returns_401(self, client):
        self._setup_admin(client)
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({"password": "wrongpassword"}),
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_no_admin_returns_401(self, client):
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({"password": "anything"}),
            content_type="application/json",
        )
        assert resp.status_code == 401


class TestAuthLogout:
    def test_logout(self, client):
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["message"] == "Logged out"

    def test_clears_session_cookie(self, client):
        # Setup and login first
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        client.post(
            "/api/auth/login",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 200


class TestAuthStatusAfterSetup:
    def test_has_admin_after_setup(self, client):
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.get("/api/auth/status")
        data = resp.get_json()
        assert data["has_admin"] is True


class TestChangePassword:
    def test_change_password(self, client):
        # Setup admin
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.post(
            "/api/auth/change-password",
            data=json.dumps({
                "current_password": "securepass123",
                "new_password": "newsecurepass123",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 200
        # Verify new password works
        resp = client.post(
            "/api/auth/login",
            data=json.dumps({"password": "newsecurepass123"}),
            content_type="application/json",
        )
        assert resp.status_code == 200

    def test_wrong_current_password_returns_401(self, client):
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.post(
            "/api/auth/change-password",
            data=json.dumps({
                "current_password": "wrongpass",
                "new_password": "newsecurepass123",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 401

    def test_short_new_password_returns_400(self, client):
        client.post(
            "/api/auth/setup",
            data=json.dumps({"password": "securepass123"}),
            content_type="application/json",
        )
        resp = client.post(
            "/api/auth/change-password",
            data=json.dumps({
                "current_password": "securepass123",
                "new_password": "short",
            }),
            content_type="application/json",
        )
        assert resp.status_code == 400
