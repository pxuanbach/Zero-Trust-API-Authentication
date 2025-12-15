import pytest
import requests
import os
import json
from pathlib import Path
from tests.constants import (
    KEYCLOAK_URL, INTERNAL_KEYCLOAK_URL, REALM, CLIENT_ID, CLIENT_SECRET, 
    USERNAME, PASSWORD, EXTENSION_APP_URL, CRM_APP_URL,
    APISIX_ADMIN_URL, APISIX_ADMIN_KEY, APISIX_GATEWAY_URL,
    KC_ADMIN_USER, KC_ADMIN_PASSWORD
)

@pytest.fixture(scope="session")
def settings():
    """Global settings for the test suite."""
    return {
        KEYCLOAK_URL: os.getenv("KEYCLOAK_URL", "http://localhost:8080"),
        INTERNAL_KEYCLOAK_URL: os.getenv("KEYCLOAK_URL", "http://keycloak:8080"),
        REALM: "zero-trust",
        CLIENT_ID: "test-client",
        CLIENT_SECRET: "test-client-secret",
        USERNAME: "testuser",
        PASSWORD: "testpassword123",
        EXTENSION_APP_URL: os.getenv("EXTENSION_APP_URL", "http://localhost:8003"),
        CRM_APP_URL: os.getenv("CRM_APP_URL", "http://localhost:8004"),
        APISIX_ADMIN_URL: os.getenv("APISIX_ADMIN_URL", "http://localhost:9180"),
        APISIX_ADMIN_KEY: os.getenv("APISIX_ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1"),
        APISIX_GATEWAY_URL: os.getenv("APISIX_GATEWAY_URL", "http://localhost:9080"),
        KC_ADMIN_USER: os.getenv("KC_ADMIN_USER", "admin"),
        KC_ADMIN_PASSWORD: os.getenv("KC_ADMIN_PASSWORD", "admin123"),
    }

@pytest.fixture(scope="session")
def auth_token(settings, init_apisix_routes):
    """Authenticate with Keycloak via APISIX Gateway and return access token (session scoped)."""
    # Use Gateway URL for auth
    gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
    token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
    
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

@pytest.fixture(scope="session")
def init_apisix_routes(settings):
    """Initialize APISIX routes with mTLS and Keycloak configuration."""
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes"
    admin_key = settings[APISIX_ADMIN_KEY]
    
    project_root = Path(__file__).parent.parent
    cert_path = project_root / "src" / "certs" / "gateway" / "gateway.crt"
    key_path = project_root / "src" / "certs" / "gateway" / "gateway.key"

    if not cert_path.exists() or not key_path.exists():
        pytest.fail(f"Gateway certificates not found at {cert_path} or {key_path}")

    cert_content = cert_path.read_text()
    key_content = key_path.read_text()

    # Common plugins configuration
    common_plugins = {
        "cors": {
            "allow_origins": "*",
            "allow_methods": "*",
            "allow_headers": "*"
        },
        "request-id": {
            "include_in_response": True
        },
        "openid-connect": {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "discovery": f"{settings[INTERNAL_KEYCLOAK_URL]}/realms/{settings[REALM]}/.well-known/openid-configuration",
            "bearer_only": True,
            "realm": settings[REALM],
            "token_signing_alg_values_expected": "RS256"
        },
        "limit-req": {
            "rate": 10,
            "burst": 5,
            "key": "consumer_name",
            "rejected_code": 429
        }
    }

    # Common plugins configuration
    routes = [
        {
            "id": "test-1",
            "uri": "/api/test/extension-app/*",
            "name": "test-extension-app-route",
            "methods": ["GET", "POST", "PUT"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/extension-app/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "extension-app1:8000": 1
                },
                "type": "roundrobin",
                "scheme": "https",
                "tls": {
                    "client_cert": cert_content,
                    "client_key": key_content,
                    "verify": True
                }
            }
        },
        {
            "id": "test-1-admin",
            "uri": "/api/test/extension-app/*",
            "name": "test-extension-app-route-admin",
            "methods": ["DELETE"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/extension-app/(.*)", "/$1"]
                },
                "authz-keycloak": {
                    "token_endpoint": f"{settings[INTERNAL_KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token",
                    "client_id": "test-client",
                    "client_secret": "test-client-secret",
                    "policy_enforcement_mode": "ENFORCING",
                    "permissions": ["Extension App Delete Resource"]
                }
            },
            "upstream": {
                "nodes": {
                    "extension-app1:8000": 1
                },
                "type": "roundrobin",
                "scheme": "https",
                "tls": {
                    "client_cert": cert_content,
                    "client_key": key_content,
                    "verify": True
                }
            }
        },
        {
            "id": "test-2",
            "uri": "/api/test/crm/*",
            "name": "test-crm-app-route",
            "methods": ["GET", "POST", "PUT"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/crm/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8001": 1
                },
                "type": "roundrobin",
                "scheme": "https",
                "tls": {
                    "client_cert": cert_content,
                    "client_key": key_content,
                    "verify": True
                }
            }
        },
        {
            "id": "test-2-admin",
            "uri": "/api/test/crm/*",
            "name": "test-crm-app-route-admin",
            "methods": ["DELETE"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/crm/(.*)", "/$1"]
                },
                "authz-keycloak": {
                    "token_endpoint": f"{settings[INTERNAL_KEYCLOAK_URL]}/realms/{settings[REALM]}/protocol/openid-connect/token",
                    "client_id": "test-client",
                    "client_secret": "test-client-secret",
                    "policy_enforcement_mode": "ENFORCING",
                    "permissions": ["CRM App Delete Resource"]
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8001": 1
                },
                "type": "roundrobin",
                "scheme": "https",
                "tls": {
                    "client_cert": cert_content,
                    "client_key": key_content,
                    "verify": True
                }
            }
        },
        {
            "id": "test-auth",
            "uri": "/api/test/auth/*",
            "name": "test-auth-route",
            "methods": ["GET", "POST"],
            "plugins": {
                "cors": {
                    "allow_origins": "*",
                    "allow_methods": "*",
                    "allow_headers": "*"
                },
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/auth/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "keycloak:8080": 1
                },
                "type": "roundrobin"
            }
        }
    ]

    headers = {"X-API-KEY": admin_key}
    
    for route in routes:
        try:
            response = requests.put(
                f"{admin_url}/{route['id']}", 
                headers=headers, 
                json=route,
                timeout=5
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to create route {route['name']}: {e}")
            
    yield routes

    # Teardown: Delete test routes
    print("\nCleaning up APISIX test routes...")
    for route in routes:
        try:
            requests.delete(
                f"{admin_url}/{route['id']}",
                headers=headers,
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            print(f"Warning: Failed to delete route {route['name']}: {e}")

@pytest.fixture(scope="session")
def init_no_mtls_route(settings, init_apisix_routes):
    """Initialize APISIX routes WITHOUT mTLS (no client cert) for negative testing.
    
    These routes HAVE authentication (openid-connect) to verify user auth succeeds,
    but LACK client certificates, so Gateway cannot connect to backend services.
    Expected: Auth OK → Gateway connection to backend fails → 502/503 error.
    """
    admin_url = f"{settings[APISIX_ADMIN_URL]}/apisix/admin/routes"
    admin_key = settings[APISIX_ADMIN_KEY]
    
    # Common plugins WITH authentication but proxy will fail due to missing mTLS
    common_plugins_no_mtls = {
        "cors": {
            "allow_origins": "*",
            "allow_methods": "*",
            "allow_headers": "*"
        },
        "openid-connect": {
            "client_id": settings[CLIENT_ID],
            "client_secret": settings[CLIENT_SECRET],
            "discovery": f"{settings[INTERNAL_KEYCLOAK_URL]}/realms/{settings[REALM]}/.well-known/openid-configuration",
            "bearer_only": True,
            "realm": settings[REALM],
            "token_signing_alg_values_expected": "RS256"
        }
    }
    
    routes = [
        {
            "id": "test-no-mtls-ext",
            "uri": "/api/test/no-mtls/extension-app/*",
            "name": "test-no-mtls-extension-route",
            "methods": ["GET"],
            "plugins": {
                **common_plugins_no_mtls,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/no-mtls/extension-app/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "extension-app1:8000": 1
                },
                "type": "roundrobin",
                "scheme": "https"
                # No tls section = no client certificate
            }
        },
        {
            "id": "test-no-mtls-crm",
            "uri": "/api/test/no-mtls/crm/*",
            "name": "test-no-mtls-crm-route",
            "methods": ["GET"],
            "plugins": {
                **common_plugins_no_mtls,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/test/no-mtls/crm/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8001": 1
                },
                "type": "roundrobin",
                "scheme": "https"
                # No tls section = no client certificate
            }
        }
    ]
    
    headers = {"X-API-KEY": admin_key}
    
    for route in routes:
        try:
            response = requests.put(
                f"{admin_url}/{route['id']}", 
                headers=headers, 
                json=route,
                timeout=5
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to create no-mTLS route {route['name']}: {e}")
            
    yield routes

    # Teardown: Delete no-mTLS test routes
    print("\nCleaning up no-mTLS test routes...")
    for route in routes:
        try:
            requests.delete(
                f"{admin_url}/{route['id']}",
                headers=headers,
                timeout=5
            )
        except requests.exceptions.RequestException as e:
            print(f"Warning: Failed to delete no-mTLS route {route['name']}: {e}")

@pytest.fixture(scope="session")
def keycloak_admin_token(settings):
    """Get Keycloak Master Admin token for accessing Admin API."""
    url = f"{settings[KEYCLOAK_URL]}/realms/master/protocol/openid-connect/token"
    data = {
        "username": settings[KC_ADMIN_USER],
        "password": settings[KC_ADMIN_PASSWORD],
        "grant_type": "password",
        "client_id": "admin-cli"
    }
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
        return response.json()["access_token"]
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Failed to get Keycloak admin token: {e}")

@pytest.fixture
def keycloak_events(settings, keycloak_admin_token):
    """Query Keycloak events for the realm."""
    def _get_events(event_type=None, user=None, from_date=None, max_results=100):
        """
        Get events from Keycloak.
        
        Args:
            event_type: Filter by event type (LOGIN, LOGOUT, etc.)
            user: Filter by user ID
            from_date: Filter events from this date (ISO format)
            max_results: Maximum number of events to return
        """
        url = f"{settings[KEYCLOAK_URL]}/admin/realms/{settings[REALM]}/events"
        headers = {"Authorization": f"Bearer {keycloak_admin_token}"}
        
        params = {"max": max_results}
        if event_type:
            params["type"] = event_type
        if user:
            params["user"] = user
        if from_date:
            params["dateFrom"] = from_date
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to query Keycloak events: {e}")
    
    return _get_events

@pytest.fixture
def clear_keycloak_events(settings, keycloak_admin_token):
    """Clear all events from Keycloak (use for test isolation)."""
    def _clear():
        url = f"{settings[KEYCLOAK_URL]}/admin/realms/{settings[REALM]}/events"
        headers = {"Authorization": f"Bearer {keycloak_admin_token}"}
        
        try:
            response = requests.delete(url, headers=headers)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Warning: Failed to clear events: {e}")
            return False
    
    return _clear
