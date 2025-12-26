import os
import time
import json
import requests

import subprocess

APISIX_ADMIN_URL = "http://apisix:9180/apisix/admin/routes"
APISIX_SSL_URL = "http://apisix:9180/apisix/admin/ssls"
ADMIN_KEY = "edd1c9f034335f136f87ad84b625c8f1"

# Internal locations (no host mount)
CERT_FILE = "/tmp/gateway.crt"
KEY_FILE = "/tmp/gateway.key"
CA_ROOT_FILE = "/usr/local/apisix/conf/ssl/step-ca/certs/root_ca.crt"

def get_identity():
    """Fetch identity from internal Step-CA via internal network"""
    print("--- Starting get_identity() task ---", flush=True)
    password = os.getenv("CA_PASSWORD", "secure-ca-password")
    print(f"Using password from env: {'***' if os.getenv('CA_PASSWORD') else 'default'}")
    
    # Debug: Check if 'step' is available
    step_path = subprocess.getoutput("which step")
    print(f"Step CLI path: {step_path}", flush=True)

    try:
        # 1. Generate token
        print("Generating token for SNI 'apisix'...", flush=True)
        pwd_file = "/tmp/pwd"
        with open(pwd_file, "w") as f:
            f.write(password)
        
        token_cmd = [
            "step", "ca", "token", "apisix",
            "--password-file", pwd_file,
            "--ca-url", "https://step-ca:9000",
            "--root", CA_ROOT_FILE
        ]
        result = subprocess.run(token_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Token generation failed: {result.stderr}", flush=True)
            return
        
        token = result.stdout.strip().split('\n')[-1]
        print("Token generated successfully.", flush=True)

        # 2. Get Certificate
        print(f"Requesting certificate to {CERT_FILE}...", flush=True)
        cert_cmd = [
            "step", "ca", "certificate", "apisix", CERT_FILE, KEY_FILE,
            "--token", token,
            "--ca-url", "https://step-ca:9000",
            "--root", CA_ROOT_FILE,
            "--force"
        ]
        cert_result = subprocess.run(cert_cmd, capture_output=True, text=True)
        if cert_result.returncode != 0:
            print(f"Certificate request failed: {cert_result.stderr}", flush=True)
            return

        print(f"Successfully obtained identity: {CERT_FILE}", flush=True)
    except Exception as e:
        print(f"Unexpected error in get_identity: {e}", flush=True)

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

def create_ssl():
    """Create SSL resources in APISIX"""
    try:
        with open(CERT_FILE, "r") as f:
            cert_content = f.read()
        with open(KEY_FILE, "r") as f:
            key_content = f.read()
        with open(CA_ROOT_FILE, "r") as f:
            ca_content = f.read()
    except Exception as e:
        print(f"Skipping SSL creation: {e}")
        return

    # 1. SSL for Bootstrapping (TLS only, No mTLS)
    ssl_bootstrap = {
        "id": "1",
        "snis": ["apisix", "localhost"],
        "cert": cert_content,
        "key": key_content,
    }

    # 2. SSL for Business API (TLS + mTLS)
    ssl_business = {
        "id": "2",
        "snis": ["apisix"],
        "cert": cert_content,
        "key": key_content,
        "client": {
            "ca": ca_content,
            "depth": 10
        }
    }

    print("Configuring APISIX SSL resources (Registration & Business)...", flush=True)
    requests.put(f"{APISIX_SSL_URL}/1", headers={"X-API-KEY": ADMIN_KEY}, json=ssl_bootstrap)
    requests.put(f"{APISIX_SSL_URL}/2", headers={"X-API-KEY": ADMIN_KEY}, json=ssl_business)
    print("SSL Configuration complete.", flush=True)

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
            "id": "2",
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
                    "regex_uri": ["^/api/v1/auth/(.*)", "/$1"]
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
        # The Step CLI does not respect path prefixes (e.g. /api/v1/ca), so we must expose 
        # the standard CA endpoints at the root level.
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
    get_identity()
    wait_for_apisix()
    create_ssl()
    create_routes()
