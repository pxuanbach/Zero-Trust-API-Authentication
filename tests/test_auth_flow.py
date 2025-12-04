import pytest
import requests
from tests.constants import (
    KEYCLOAK_URL, REALM, CLIENT_ID, CLIENT_SECRET, 
    USERNAME, PASSWORD
)

def test_login_success(settings):
    """Test successful authentication with valid credentials."""
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": settings[USERNAME],
        "password": settings[PASSWORD],
        "grant_type": "password",
        "scope": "openid"
    }
    
    response = requests.post(token_url, data=payload)
    assert response.status_code == 200, f"Login failed: {response.text}"
    
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "id_token" in data
    assert data["token_type"].lower() == "bearer"
    assert data["expires_in"] > 0

def test_login_invalid_credentials(settings):
    """Test authentication failure with invalid password."""
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": settings[USERNAME],
        "password": "wrongpassword",
        "grant_type": "password",
        "scope": "openid"
    }
    
    response = requests.post(token_url, data=payload)
    assert response.status_code == 401
    
    data = response.json()
    assert "error" in data
    assert data["error"] == "invalid_grant"

def test_login_invalid_client(settings):
    """Test authentication failure with invalid client secret."""
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": "wrongsecret",
        "username": settings[USERNAME],
        "password": settings[PASSWORD],
        "grant_type": "password",
        "scope": "openid"
    }
    
    response = requests.post(token_url, data=payload)
    assert response.status_code == 401
    
    data = response.json()
    assert "error" in data
    assert data["error"] == "unauthorized_client"

def test_refresh_token_flow(settings):
    """Test refreshing an access token using a refresh token."""
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    
    # 1. Login to get refresh token
    login_payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": settings[USERNAME],
        "password": settings[PASSWORD],
        "grant_type": "password",
        "scope": "openid"
    }
    login_response = requests.post(token_url, data=login_payload)
    assert login_response.status_code == 200
    refresh_token = login_response.json()["refresh_token"]
    original_access_token = login_response.json()["access_token"]

    # 2. Use refresh token to get new access token
    refresh_payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    
    refresh_response = requests.post(token_url, data=refresh_payload)
    assert refresh_response.status_code == 200, f"Refresh failed: {refresh_response.text}"
    
    refresh_data = refresh_response.json()
    assert "access_token" in refresh_data
    assert "refresh_token" in refresh_data
    assert refresh_data["access_token"] != original_access_token

def test_user_info_endpoint(settings):
    """Test accessing the UserInfo endpoint with a valid token."""
    # 1. Get Token
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    login_payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": settings[USERNAME],
        "password": settings[PASSWORD],
        "grant_type": "password",
        "scope": "openid"
    }
    token = requests.post(token_url, data=login_payload).json()["access_token"]

    # 2. Call UserInfo
    userinfo_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/userinfo"
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.get(userinfo_url, headers=headers)
    assert response.status_code == 200
    
    user_data = response.json()
    assert user_data["preferred_username"] == settings[USERNAME]
    assert "email" in user_data
    assert "sub" in user_data  # Subject identifier
