from fastapi.testclient import TestClient

from proxy.config import settings
from proxy.main import app


client = TestClient(app)


def test_health_endpoints():
    assert client.get("/healthz").status_code == 200
    assert client.get("/readyz").status_code == 200


def test_production_requires_api_key():
    original_env = settings.APP_ENV
    original_key = settings.PROXY_API_KEY
    settings.APP_ENV = "production"
    settings.PROXY_API_KEY = "test-secret"
    try:
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert response.status_code == 401

        response = client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": "test-secret"},
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
        )
        assert response.status_code == 200
    finally:
        settings.APP_ENV = original_env
        settings.PROXY_API_KEY = original_key


def test_large_request_is_rejected():
    original_limit = settings.MAX_MESSAGE_CHARS
    settings.MAX_MESSAGE_CHARS = 5
    try:
        response = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4", "messages": [{"role": "user", "content": "123456"}]},
        )
        assert response.status_code == 413
    finally:
        settings.MAX_MESSAGE_CHARS = original_limit
