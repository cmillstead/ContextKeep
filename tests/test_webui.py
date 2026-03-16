import json
import re
import pytest
from webui import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def _get_csrf_token(client):
    page = client.get("/")
    html = page.data.decode()
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert match, "CSRF token not found in page"
    return match.group(1)


class TestSecurityHeaders:
    def test_x_content_type_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        resp = client.get("/")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_content_security_policy(self, client):
        resp = client.get("/")
        csp = resp.headers.get("Content-Security-Policy")
        assert csp is not None
        assert "default-src 'self'" in csp


class TestCSRF:
    def test_get_requests_work_without_csrf(self, client):
        resp = client.get("/api/memories")
        assert resp.status_code == 200

    def test_post_without_csrf_returns_403(self, client):
        resp = client.post("/api/memories",
                           json={"key": "test", "content": "test"},
                           content_type="application/json")
        assert resp.status_code == 403

    def test_post_with_valid_csrf_works(self, client):
        token = _get_csrf_token(client)
        resp = client.post("/api/memories",
                           json={"key": "csrf-test", "content": "test content"},
                           headers={"X-CSRF-Token": token},
                           content_type="application/json")
        assert resp.status_code == 200

    def test_delete_without_csrf_returns_403(self, client):
        resp = client.delete("/api/memories/some-key")
        assert resp.status_code == 403


class TestGenericErrors:
    def test_404_returns_json_without_traceback(self, client):
        resp = client.get("/api/memories/nonexistent-key-12345")
        data = json.loads(resp.data)
        assert data["success"] is False
        assert "Traceback" not in data.get("error", "")


class TestImmutabilityToggle:
    def test_put_with_immutable_field(self, client):
        token = _get_csrf_token(client)
        client.post("/api/memories",
                     json={"key": "lock-test", "content": "test"},
                     headers={"X-CSRF-Token": token},
                     content_type="application/json")
        resp = client.put("/api/memories/lock-test",
                          json={"content": "test", "title": "test", "tags": [], "immutable": True},
                          headers={"X-CSRF-Token": token},
                          content_type="application/json")
        assert resp.status_code == 200
        resp = client.get("/api/memories/lock-test")
        data = json.loads(resp.data)
        assert data["memory"]["immutable"] is True
