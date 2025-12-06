import pytest
import requests
import uuid
import base64
import json
from tests.constants import (
    APISIX_ADMIN_URL, APISIX_ADMIN_KEY, APISIX_GATEWAY_URL,
    CLIENT_ID, CLIENT_SECRET, REALM
)

@pytest.fixture(scope="module")
def protected_route(settings):
    """Create a temporary protected route in APISIX."""
    route_id = str(uuid.uuid4())
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes/{route_id}"
    headers = {"X-API-KEY": settings[APISIX_ADMIN_KEY]}
    
    payload = {
        "uri": "/test-threat-protection",
        "name": f"test-threat-{route_id}",
        "upstream": {
            "type": "roundrobin",
            "nodes": {"service-a:8000": 1}
        },
        "plugins": {
            "proxy-rewrite": {"uri": "/public"},
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
    
    requests.put(admin_url, headers=headers, json=payload)
    yield route_id
    requests.delete(admin_url, headers=headers)

def test_access_without_token(settings, protected_route):
    """Test access denial when no token is provided."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-threat-protection"
    response = requests.get(url)
    assert response.status_code == 401

def test_access_with_malformed_token(settings, protected_route):
    """Test access denial with structurally invalid token."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-threat-protection"
    headers = {"Authorization": "Bearer invalid.token.structure"}
    response = requests.get(url, headers=headers)
    assert response.status_code == 401

def test_access_with_tampered_payload(settings, protected_route, auth_token):
    """Test access denial when token payload is modified (signature mismatch)."""
    parts = auth_token.split('.')
    payload = json.loads(base64.b64decode(parts[1] + "==").decode('utf-8'))
    # print(payload)
    # assert payload == {}
    
    # Attack: Elevate privileges or change identity
    payload['preferred_username'] = 'admin'
    payload['realm_access'] = {'roles': ['admin', 'root']}
    
    tampered_payload = base64.b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8').rstrip('=')
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    # print(tampered_token)
    # assert tampered_token == ""
    
    url = f"{settings[APISIX_GATEWAY_URL]}/test-threat-protection"
    headers = {"Authorization": f"Bearer {tampered_token}"}
    
    response = requests.get(url, headers=headers)
    assert response.status_code == 401

def test_access_with_none_algorithm(settings, protected_route, auth_token):
    """Test access denial with 'none' algorithm (signature bypass attempt)."""
    parts = auth_token.split('.')
    payload = parts[1]
    
    # Attack: Set algorithm to 'none' and remove signature
    header = {"alg": "none", "typ": "JWT"}
    malicious_header = base64.b64encode(json.dumps(header).encode('utf-8')).decode('utf-8').rstrip('=')
    
    # Construct token with no signature part
    none_algo_token = f"{malicious_header}.{payload}."
    
    url = f"{settings[APISIX_GATEWAY_URL]}/test-threat-protection"
    headers = {"Authorization": f"Bearer {none_algo_token}"}
    
    response = requests.get(url, headers=headers)
    assert response.status_code == 401

def test_replay_attack_behavior(settings, protected_route, auth_token):
    """Verify token reuse behavior (baseline for replay attacks)."""
    url = f"{settings[APISIX_GATEWAY_URL]}/test-threat-protection"
    headers = {"Authorization": f"Bearer {auth_token}"}
    
    # Attack: Replay the same valid token multiple times
    response1 = requests.get(url, headers=headers)
    response2 = requests.get(url, headers=headers)
    
    assert response1.status_code == 200
    assert response2.status_code == 200
