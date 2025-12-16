import os
import time
import json
import requests

APISIX_ADMIN_URL = "http://apisix:9180/apisix/admin/routes"
ADMIN_KEY = "edd1c9f034335f136f87ad84b625c8f1"

CERT_FILE = "/certs/gateway/gateway.crt"
KEY_FILE = "/certs/gateway/gateway.key"

def wait_for_apisix():
    print("Waiting for APISIX...")
    while True:
        try:
            # Check health or list routes to see if API is up
            response = requests.get(APISIX_ADMIN_URL, headers={"X-API-KEY": ADMIN_KEY}, timeout=2)
            if response.status_code == 200:
                print("APISIX is ready.")
                break
        except Exception as e:
            print(f"Waiting for APISIX... ({str(e)})")
        time.sleep(2)

def create_routes():
    try:
        with open(CERT_FILE, "r") as f:
            cert_content = f.read()
        with open(KEY_FILE, "r") as f:
            key_content = f.read()
    except FileNotFoundError as e:
        print(f"Error reading certs: {e}")
        return

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
            "client_id": "test-client",
            "client_secret": "test-client-secret",
            "discovery": "http://keycloak:8080/realms/zero-trust/.well-known/openid-configuration",
            "bearer_only": True,
            "realm": "zero-trust",
            "token_signing_alg_values_expected": "RS256"
        },
        "limit-req": {
            "rate": 10,
            "burst": 5,
            "key": "consumer_name",
            "rejected_code": 429
        }
    }

    routes = [
        {
            "id": "1",
            "uri": "/api/v1/extension-app/*",
            "name": "extension-app-route",
            "methods": ["GET", "POST", "PUT"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/extension-app/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "extension-app1:8443": 1
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
            "id": "2",
            "uri": "/api/v1/extension-app/*",
            "name": "extension-app-route-admin",
            "methods": ["DELETE"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/extension-app/(.*)", "/$1"]
                },
                "authz-keycloak": {
                    "token_endpoint": "http://keycloak:8080/realms/zero-trust/protocol/openid-connect/token",
                    "client_id": "test-client",
                    "client_secret": "test-client-secret",
                    "policy_enforcement_mode": "ENFORCING",
                    "permissions": ["Extension App Delete Resource"]
                }
            },
            "upstream": {
                "nodes": {
                    "extension-app1:8443": 1
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
            "id": "3",
            "uri": "/api/v1/crm/*",
            "name": "crm-app-route",
            "methods": ["GET", "POST", "PUT"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/crm/(.*)", "/$1"]
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8443": 1
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
            "id": "4",
            "uri": "/api/v1/crm/*",
            "name": "crm-app-route-admin",
            "methods": ["DELETE"],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/crm/(.*)", "/$1"]
                },
                "authz-keycloak": {
                    "token_endpoint": "http://keycloak:8080/realms/zero-trust/protocol/openid-connect/token",
                    "client_id": "test-client",
                    "client_secret": "test-client-secret",
                    "policy_enforcement_mode": "ENFORCING",
                    "permissions": ["CRM App Delete Resource"]
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8443": 1
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
            "id": "5",
            "uri": "/api/v1/auth/*",
            "name": "auth-route",
            "methods": ["GET", "POST"],
            "plugins": {
                "cors": {
                    "allow_origins": "*",
                    "allow_methods": "*",
                    "allow_headers": "*"
                },
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/auth/(.*)", "/$1"]
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

    for route in routes:
        print(f"Creating route {route['name']} (ID: {route['id']})...")
        try:
            response = requests.put(
                f"{APISIX_ADMIN_URL}/{route['id']}", 
                headers={"X-API-KEY": ADMIN_KEY}, 
                json=route
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
        except Exception as e:
            print(f"Failed to create route {route['name']}: {e}")

if __name__ == "__main__":
    wait_for_apisix()
    create_routes()
