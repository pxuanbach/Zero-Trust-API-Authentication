import os
import time
import requests

# Configuration
APISIX_ADMIN_URL = os.getenv("APISIX_ADMIN_URL", "http://127.0.0.1:9180/apisix/admin/routes")
ADMIN_KEY = os.getenv("ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1")

CERT_FILE = "/tmp/gateway.crt"
KEY_FILE = "/tmp/gateway.key"
CERT_FILE_CLIENT = "/tmp/gateway_client.crt"
KEY_FILE_CLIENT = "/tmp/gateway_client.key"

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
            
        # Read Client Certs for Backend mTLS
        with open(CERT_FILE_CLIENT, "r") as f:
            client_cert_content = f.read()
        with open(KEY_FILE_CLIENT, "r") as f:
            client_key_content = f.read()
            
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
            "uri": "/api/v1/crm/*",
            "name": "crm-app-route",
            "methods": ["GET", "POST", "PUT"],
            "vars": [
                ["ssl_client_verify", "==", "SUCCESS"]
            ],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/crm/(.*)", "/$1"],
                    "headers": {
                        "X-Client-Cert-Fingerprint": "$ssl_client_fingerprint"
                    }
                }
            },
            "upstream": {
                "nodes": {
                    "crm-app:8443": 1
                },
                "type": "roundrobin",
                "scheme": "https",
                "tls": {
                    "client_cert": client_cert_content,
                    "client_key": client_key_content
                }
            }
        },
        {
            "id": "2",
            "uri": "/api/v1/crm/*",
            "name": "crm-app-route-admin",
            "methods": ["DELETE"],
            "vars": [
                ["ssl_client_verify", "==", "SUCCESS"]
            ],
            "plugins": {
                **common_plugins,
                "proxy-rewrite": {
                    "regex_uri": ["^/api/v1/crm/(.*)", "/$1"],
                    "headers": {
                        "X-Client-Cert-Fingerprint": "$ssl_client_fingerprint"
                    }
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
                    "client_cert": client_cert_content,
                    "client_key": client_key_content
                }
            }
        },
        {
            "id": "3",
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
                    "regex_uri": ["^/api/v1/auth/(.*)", "/$1"],
                    "headers": {
                        "X-Client-Cert-Fingerprint": "$ssl_client_fingerprint"
                    }
                }
            },
            "upstream": {
                "nodes": {
                    "keycloak:8080": 1
                },
                "type": "roundrobin"
            }
        },
        # Route 4: Step CA Native Endpoints
        {
            "id": "4",
            "uris": ["/1.0/*", "/roots", "/root/*", "/provisioners", "/provisioners/*", "/health", "/otp/*", "/sign"],
            "name": "step-ca-native-route",
            "priority": 1,
            "methods": ["GET", "POST", "PUT", "HEAD", "OPTIONS"],
            "plugins": {
                "cors": {
                    "allow_origins": "*",
                    "allow_methods": "*",
                    "allow_headers": "*"
                },
                "limit-req": {
                    "rate": 20,
                    "burst": 10,
                    "key": "remote_addr",
                    "rejected_code": 429
                }
            },
            "upstream": {
                "nodes": {
                    "step-ca:9000": 1
                },
                "type": "roundrobin",
                "scheme": "https"
            }
        },
        {
            "id": "5",
            "uri": "/apisix/status",
            "name": "health-check-route",
            "methods": ["GET"],
            "plugins": {
                "fault-injection": {
                    "abort": {
                        "http_status": 200,
                        "body": "{\"status\":\"ok\"}"
                    }
                }
            },
            "upstream": {
                "nodes": {
                    "127.0.0.1:1980": 1
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
