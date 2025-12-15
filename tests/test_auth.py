import pytest
import requests
from tests.constants import (
    KEYCLOAK_URL, REALM, CLIENT_ID, CLIENT_SECRET, 
    USERNAME, PASSWORD, APISIX_GATEWAY_URL
)

def login(settings, username, password):
    """Helper function to perform login via APISIX Gateway."""
    gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
    token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
    
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": username,
        "password": password,
        "grant_type": "password"
    }
    
    return requests.post(token_url, data=payload)

@pytest.mark.usefixtures("init_apisix_routes")
class TestAuthentication:
    
    def test_auth_valid_user_login(self, settings):
        """
        ID: AUTH-1
        Scenario: Valid User login via APISIX
        Expect: Login successful (HTTP 200 + access_token)
        """
        response = login(settings, settings[USERNAME], settings[PASSWORD])
        assert response.status_code == 200, f"Login failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"].lower() == "bearer"

    def test_auth_valid_admin_login(self, settings):
        """
        ID: AUTH-2
        Scenario: Valid Admin login via APISIX
        Expect: Login successful (HTTP 200 + access_token)
        """
        admin_username = "admin"
        admin_password = "adminpassword123"
        
        response = login(settings, admin_username, admin_password)
        assert response.status_code == 200, f"Admin login failed: {response.text}"
        data = response.json()
        assert "access_token" in data

    def test_auth_invalid_user_login(self, settings):
        """
        ID: AUTH-3
        Scenario: Invalid User login (wrong password) via APISIX
        Expect: Login failed (HTTP 401)
        """
        response = login(settings, settings[USERNAME], "wrongpassword123")
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
