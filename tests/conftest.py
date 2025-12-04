import pytest
import requests
import os
from tests.constants import (
    KEYCLOAK_URL, REALM, CLIENT_ID, CLIENT_SECRET, 
    USERNAME, PASSWORD, SERVICE_A_URL, SERVICE_B_URL,
    APISIX_ADMIN_URL, APISIX_ADMIN_KEY, APISIX_GATEWAY_URL
)

@pytest.fixture(scope="session")
def settings():
    """Global settings for the test suite."""
    return {
        KEYCLOAK_URL: os.getenv("KEYCLOAK_URL", "http://localhost:8080"),
        REALM: "zero-trust",
        CLIENT_ID: "test-client",
        CLIENT_SECRET: "test-client-secret",
        USERNAME: "testuser",
        PASSWORD: "testpassword123",
        SERVICE_A_URL: os.getenv("SERVICE_A_URL", "http://localhost:8003"),
        SERVICE_B_URL: os.getenv("SERVICE_B_URL", "http://localhost:8004"),
        APISIX_ADMIN_URL: os.getenv("APISIX_ADMIN_URL", "http://localhost:9180"),
        APISIX_ADMIN_KEY: os.getenv("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1"),
        APISIX_GATEWAY_URL: os.getenv("APISIX_GATEWAY_URL", "http://localhost:9080"),
    }

@pytest.fixture(scope="session")
def auth_token(settings):
    """Authenticate with Keycloak and return access token (session scoped)."""
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": settings[USERNAME],
        "password": settings[PASSWORD],
        "grant_type": "password"
    }
    
    try:
        response = requests.post(token_url, data=payload)
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Authentication failed: {e}")

@pytest.fixture(scope="session")
def auth_headers(auth_token):
    """Return headers with Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}
