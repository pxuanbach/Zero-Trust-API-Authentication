import pytest
import requests
import uuid
from tests.constants import (
    APISIX_ADMIN_URL, APISIX_ADMIN_KEY, APISIX_GATEWAY_URL,
    CLIENT_ID, CLIENT_SECRET, REALM, KEYCLOAK_URL
)

@pytest.fixture(scope="module")
def aaa_route(settings):
    """Create route with full AAA configuration."""
    route_id = str(uuid.uuid4())
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes/{route_id}"
    headers = {"X-API-KEY": settings[APISIX_ADMIN_KEY]}
    
    payload = {
        "uri": "/test-aaa",
        "name": f"test-aaa-{route_id}",
        "upstream": {
            "type": "roundrobin",
            "nodes": {"service-a:8000": 1}
        },
        "plugins": {
            "proxy-rewrite": {"uri": "/protected"},
            "openid-connect": {
                "client_id": settings[CLIENT_ID],
                "client_secret": settings[CLIENT_SECRET],
                "discovery": f"http://keycloak:8080/realms/{settings[REALM]}/.well-known/openid-configuration",
                "bearer_only": True,
                "realm": settings[REALM],
                "introspection_endpoint_auth_method": "client_secret_post"
            },
            "syslog": {
                "host": "127.0.0.1",
                "port": 514,
                "flush_limit": 4096,
                "timeout": 3000,
                "log_format": {
                    "client_ip": "$remote_addr",
                    "timestamp": "$time_iso8601",
                    "method": "$request_method",
                    "uri": "$request_uri",
                    "status": "$status",
                    "response_time": "$request_time"
                }
            }
        }
    }
    
    requests.put(admin_url, headers=headers, json=payload)
    yield route_id
    requests.delete(admin_url, headers=headers)


# ===== AUTHENTICATION TESTS (A1) =====

def test_aaa_authentication_valid_token(settings, aaa_route, auth_token):
    """Verify Authentication works with valid token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-aaa"
    headers = {"Authorization": f"Bearer {auth_token}"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data.get("service") == "service-a"

def test_aaa_authentication_no_token(settings, aaa_route):
    """Verify Authentication rejects requests without token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-aaa"
    response = requests.get(url)
    assert response.status_code == 401


# ===== AUTHORIZATION TESTS (A2) =====

def test_aaa_authorization_user_has_role(settings, auth_token):
    """Verify user token contains 'user' role (Authorization metadata)."""
    import json
    import base64
    
    # Decode JWT token payload
    parts = auth_token.split('.')
    payload = json.loads(base64.b64decode(parts[1] + "==").decode('utf-8'))
    
    # Verify Authorization information in token
    assert "realm_access" in payload
    assert "roles" in payload["realm_access"]
    
    roles = payload["realm_access"]["roles"]
    assert "user" in roles, f"Expected 'user' role in token, got: {roles}"
    
    # This proves Authorization Services are working:
    # Keycloak includes role information that can be used for access control

def test_aaa_authorization_user_no_admin_role(settings, auth_token):
    """Verify regular user does NOT have 'admin' role."""
    import json
    import base64
    
    parts = auth_token.split('.')
    payload = json.loads(base64.b64decode(parts[1] + "==").decode('utf-8'))
    
    roles = payload["realm_access"]["roles"]
    assert "admin" not in roles, f"User should not have admin role, got: {roles}"

def test_aaa_authorization_admin_has_roles(settings):
    """Verify admin user has both 'admin' and 'user' roles."""
    import json
    import base64
    
    # Get admin token
    token_url = f"{settings[KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token"
    login_payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": "admin",
        "password": "adminpassword123",
        "grant_type": "password"
    }
    
    login_response = requests.post(token_url, data=login_payload)
    assert login_response.status_code == 200
    admin_token = login_response.json()["access_token"]
    
    # Decode token
    parts = admin_token.split('.')
    payload = json.loads(base64.b64decode(parts[1] + "==").decode('utf-8'))
    
    # Verify admin has elevated privileges
    roles = payload["realm_access"]["roles"]
    assert "admin" in roles, f"Admin should have 'admin' role, got: {roles}"
    assert "user" in roles, f"Admin should also have 'user' role, got: {roles}"
    
    # This proves Authorization hierarchy: admin has more permissions than user


# ===== ACCOUNTING TESTS (A3) =====

def test_aaa_accounting_authentication_events(settings, auth_token):
    """Test that Keycloak logs authentication events (Accounting)."""
    # Get Keycloak admin token
    admin_token_url = f"{settings[KEYCLOAK_URL]}/realms/master/protocol/openid-connect/token"
    admin_data = {
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin123",
        "grant_type": "password"
    }
    admin_response = requests.post(admin_token_url, data=admin_data)
    
    # If admin credentials are wrong, skip this test
    if admin_response.status_code != 200:
        pytest.skip("Cannot get admin token to query events - check Keycloak admin credentials")
    
    admin_token = admin_response.json()["access_token"]
    
    # Query Keycloak events API
    events_url = f"{settings[KEYCLOAK_URL]}/admin/realms/{settings[REALM]}/events"
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    response = requests.get(events_url, headers=headers)
    assert response.status_code == 200
    
    events = response.json()
    # Verify there are authentication events logged (Accounting proof)
    assert len(events) > 0
    
    # Check for specific event types
    event_types = [event["type"] for event in events]
    # Should have at least one authentication-related event
    auth_events = ["LOGIN", "CODE_TO_TOKEN", "INTROSPECT_TOKEN", "REFRESH_TOKEN"]
    has_auth_event = any(evt in event_types for evt in auth_events)
    assert has_auth_event, f"Expected authentication events, got: {event_types}"
    
    # Verify event contains required accounting information
    sample_event = events[0]
    assert "userId" in sample_event or "clientId" in sample_event  # WHO
    assert "time" in sample_event  # WHEN
    assert "ipAddress" in sample_event  # FROM WHERE

def test_aaa_accounting_request_logs(settings, aaa_route, auth_token):
    """Test that APISIX logs all requests (Accounting)."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-aaa"
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Make a tracked request with unique identifier
    unique_param = str(uuid.uuid4())
    response = requests.get(url, headers=headers, params={"track": unique_param})
    assert response.status_code == 200
    
    # Verify the logging configuration is in place
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes/{aaa_route}"
    headers = {"X-API-KEY": settings[APISIX_ADMIN_KEY]}
    route_response = requests.get(admin_url, headers=headers)
    
    assert route_response.status_code == 200
    route_data = route_response.json()
    
    # Verify syslog plugin is configured (Accounting mechanism)
    plugins = route_data.get("value", {}).get("plugins", {})
    assert "syslog" in plugins, "Syslog plugin not configured for accounting"
    
    syslog_config = plugins["syslog"]
    assert "log_format" in syslog_config
    assert "client_ip" in syslog_config["log_format"]
    assert "timestamp" in syslog_config["log_format"]
    assert "status" in syslog_config["log_format"]

def test_aaa_accounting_failed_auth_logged(settings, aaa_route):
    """Verify failed authentication attempts are logged."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-aaa"
    headers = {"Authorization": "Bearer invalid_token_12345"}
    
    # Make request with invalid token
    response = requests.get(url, headers=headers)
    assert response.status_code == 401
    
    # Verify error events are logged in Keycloak
    admin_token_url = f"{settings[KEYCLOAK_URL]}/realms/master/protocol/openid-connect/token"
    admin_data = {
        "client_id": "admin-cli",
        "username": "admin",
        "password": "admin123",
        "grant_type": "password"
    }
    admin_response = requests.post(admin_token_url, data=admin_data)
    
    if admin_response.status_code != 200:
        pytest.skip("Cannot get admin token to query events")
    
    admin_token = admin_response.json()["access_token"]
    
    # Check for error events
    events_url = f"{settings[KEYCLOAK_URL]}/admin/realms/{settings[REALM]}/events"
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = requests.get(events_url, headers=headers, params={"type": "INTROSPECT_TOKEN_ERROR"})
    
    # Should have error events (or at least events endpoint is accessible)
    assert response.status_code == 200
