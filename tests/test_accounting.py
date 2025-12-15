import pytest
import requests
import time
from tests.constants import (
    USERNAME, PASSWORD, APISIX_GATEWAY_URL, REALM, CLIENT_ID, CLIENT_SECRET
)

@pytest.mark.usefixtures("init_apisix_routes")
class TestAccounting:
    """Test Keycloak Accounting (Event Logging) functionality."""

    def test_acct_1_login_event_recorded(self, settings, clear_keycloak_events, keycloak_events):
        """
        ID: ACCT-1
        Scenario: User login event is recorded in Keycloak
        Expect: LOGIN event exists with correct user information
        """
        # Clear existing events for clean test
        clear_keycloak_events()
        time.sleep(1)  # Wait for clear to complete
        
        # Perform login via APISIX Gateway
        gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
        token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
        
        payload = {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "username": settings[USERNAME],
            "password": settings[PASSWORD],
            "grant_type": "password"
        }
        
        response = requests.post(token_url, data=payload)
        assert response.status_code == 200, f"Login failed: {response.text}"
        
        # Wait for event to be recorded
        time.sleep(2)
        
        # Query LOGIN events
        events = keycloak_events(event_type="LOGIN")
        
        # Verify LOGIN event exists
        assert len(events) > 0, "No LOGIN events found"
        
        # Verify event details
        login_event = events[0]
        assert login_event["type"] == "LOGIN"
        assert login_event["clientId"] == settings[CLIENT_ID]
        assert "userId" in login_event
        assert "ipAddress" in login_event

    def test_acct_2_failed_login_recorded(self, settings, clear_keycloak_events, keycloak_events):
        """
        ID: ACCT-2
        Scenario: Failed login attempt is recorded
        Expect: LOGIN_ERROR event exists
        """
        # Clear existing events
        clear_keycloak_events()
        time.sleep(1)
        
        # Attempt login with wrong password
        gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
        token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
        
        payload = {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "username": settings[USERNAME],
            "password": "wrongpassword",
            "grant_type": "password"
        }
        
        response = requests.post(token_url, data=payload)
        assert response.status_code == 401, "Expected 401 for wrong password"
        
        # Wait for event
        time.sleep(2)
        
        # Query LOGIN_ERROR events
        events = keycloak_events(event_type="LOGIN_ERROR")
        
        # Verify LOGIN_ERROR event exists
        assert len(events) > 0, "No LOGIN_ERROR events found"
        
        login_error_event = events[0]
        assert login_error_event["type"] == "LOGIN_ERROR"
        assert login_error_event["error"] == "invalid_user_credentials"

    def test_acct_3_token_refresh_recorded(self, settings, auth_token, clear_keycloak_events, keycloak_events):
        """
        ID: ACCT-3
        Scenario: Token refresh event is recorded
        Expect: REFRESH_TOKEN event exists
        """
        # Clear existing events
        clear_keycloak_events()
        time.sleep(1)
        
        # Get initial token (this will create LOGIN event)
        gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
        token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
        
        payload = {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "username": settings[USERNAME],
            "password": settings[PASSWORD],
            "grant_type": "password"
        }
        
        response = requests.post(token_url, data=payload)
        assert response.status_code == 200
        refresh_token = response.json()["refresh_token"]
        
        # Wait a bit
        time.sleep(1)
        
        # Refresh the token
        refresh_payload = {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        
        refresh_response = requests.post(token_url, data=refresh_payload)
        assert refresh_response.status_code == 200, f"Refresh failed: {refresh_response.text}"
        
        # Wait for event
        time.sleep(2)
        
        # Query REFRESH_TOKEN events
        events = keycloak_events(event_type="REFRESH_TOKEN")
        
        # Verify REFRESH_TOKEN event exists
        assert len(events) > 0, "No REFRESH_TOKEN events found"
        
        refresh_event = events[0]
        assert refresh_event["type"] == "REFRESH_TOKEN"
        assert refresh_event["clientId"] == settings[CLIENT_ID]

    def test_acct_4_multiple_logins_recorded(self, settings, clear_keycloak_events, keycloak_events):
        """
        ID: ACCT-4
        Scenario: Multiple login events are recorded separately
        Expect: Multiple LOGIN events exist
        """
        # Clear existing events
        clear_keycloak_events()
        time.sleep(1)
        
        gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
        token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
        
        payload = {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "username": settings[USERNAME],
            "password": settings[PASSWORD],
            "grant_type": "password"
        }
        
        # Perform 3 logins
        login_count = 3
        for i in range(login_count):
            response = requests.post(token_url, data=payload)
            assert response.status_code == 200
            time.sleep(0.5)
        
        # Wait for all events to be recorded
        time.sleep(2)
        
        # Query LOGIN events
        events = keycloak_events(event_type="LOGIN", max_results=10)
        
        # Verify we have at least the expected number of LOGIN events
        assert len(events) >= login_count, f"Expected at least {login_count} LOGIN events, got {len(events)}"

    def test_acct_5_introspection_event_recorded(self, settings, auth_headers, clear_keycloak_events, keycloak_events):
        """
        ID: ACCT-5
        Scenario: Token introspection event is recorded when accessing protected resource
        Expect: INTROSPECT_TOKEN event exists (triggered by openid-connect plugin)
        """
        # Clear existing events
        clear_keycloak_events()
        time.sleep(1)
        
        # Access a protected resource (this triggers token introspection by APISIX)
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        response = requests.get(ext_url, headers=auth_headers)
        assert response.status_code == 200
        
        # Wait for event
        time.sleep(2)
        
        # Query INTROSPECT_TOKEN events
        events = keycloak_events(event_type="INTROSPECT_TOKEN")
        
        # Verify INTROSPECT_TOKEN event exists
        assert len(events) > 0, "No INTROSPECT_TOKEN events found"
        
        introspect_event = events[0]
        assert introspect_event["type"] == "INTROSPECT_TOKEN"
        assert introspect_event["clientId"] == settings[CLIENT_ID]
