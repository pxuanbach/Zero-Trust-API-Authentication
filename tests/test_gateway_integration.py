import pytest
import requests
import uuid
from tests.constants import (
    APISIX_ADMIN_URL, APISIX_ADMIN_KEY, APISIX_GATEWAY_URL,
    CLIENT_ID, CLIENT_SECRET, REALM
)

@pytest.fixture(scope="module")
def apisix_route(settings):
    """Create a temporary route in APISIX for testing."""
    route_id = str(uuid.uuid4())
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes/{route_id}"
    headers = {"X-API-KEY": settings[APISIX_ADMIN_KEY]}
    
    # Configure route with openid-connect plugin
    # Note: discovery endpoint uses 'keycloak' hostname
    payload = {
        "uri": "/test-gateway-auth",
        "name": f"test-route-{route_id}",
        "upstream": {
            "type": "roundrobin",
            "nodes": {
                "service-a:8000": 1
            }
        },
        "plugins": {
            "proxy-rewrite": {
                "uri": "/public"
            },
            "openid-connect": {
                "client_id": settings[CLIENT_ID],
                "client_secret": settings[CLIENT_SECRET],
                "discovery": f"http://keycloak:8080/realms/{settings[REALM]}/.well-known/openid-configuration",
                "bearer_only": True,
                "realm": settings[REALM],
                "introspection_endpoint_auth_method": "client_secret_post"
            }
        }
    }
    
    print(f"Creating APISIX route: {route_id}")
    response = requests.put(admin_url, headers=headers, json=payload)
    assert response.status_code in [200, 201], f"Failed to create route: {response.text}"
    
    yield route_id
    
    # Cleanup
    print(f"Deleting APISIX route: {route_id}")
    requests.delete(admin_url, headers=headers)

def test_gateway_auth_no_token(settings, apisix_route):
    """Test accessing the gateway route without a token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-gateway-auth"
    response = requests.get(url)
    
    # Should be 401 Unauthorized because bearer_only=True
    assert response.status_code == 401

def test_gateway_auth_valid_token(settings, apisix_route, auth_headers):
    """Test accessing the gateway route with a valid token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-gateway-auth"
    response = requests.get(url, headers=auth_headers)
    
    assert response.status_code == 200
    data = response.json()
    # Service A returns "service": "service-a"
    assert data.get("service") == "service-a"
    assert data.get("endpoint") == "public"

def test_gateway_auth_invalid_token(settings, apisix_route):
    """Test accessing the gateway route with an invalid token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-gateway-auth"
    headers = {"Authorization": "Bearer invalid_token_123"}
    response = requests.get(url, headers=headers)
    
    assert response.status_code == 401
