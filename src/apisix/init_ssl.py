import os
import time
import requests
import subprocess
import json

# Configuration
APISIX_SSL_URL = os.getenv("APISIX_SSL_URL", "http://127.0.0.1:9180/apisix/admin/ssls")
APISIX_ADMIN_URL = os.getenv("APISIX_ADMIN_URL", "http://127.0.0.1:9180/apisix/admin/routes")
ADMIN_KEY = os.getenv("ADMIN_KEY", "edd1c9f034335f136f87ad84b625c8f1")
STEP_CA_URL = os.getenv("STEP_CA_URL", "https://step-ca:9000")

CERT_FILE = "/tmp/gateway.crt"
KEY_FILE = "/tmp/gateway.key"
CA_ROOT_FILE = "./certs/certs/root_ca.crt"

def ensure_root_ca():
    """Ensure Root CA exists by downloading from Step-CA if missing"""

    print(f"Checking Root CA at {CA_ROOT_FILE}...", flush=True)
    if os.path.exists(CA_ROOT_FILE):
        print("Root CA found.", flush=True)
        return

    print("Root CA not found. Attempting to download from Step-CA...", flush=True)
    ca_dir = os.path.dirname(CA_ROOT_FILE)
    if not os.path.exists(ca_dir):
        print(f"Creating directory {ca_dir}...", flush=True)
        os.makedirs(ca_dir, exist_ok=True)

    try:
        # Download from Step-CA insecurely (bootstrapping trust)
        url = f"{STEP_CA_URL}/roots.pem"
        print(f"Downloading {url}...", flush=True)
        response = requests.get(url, verify=False, timeout=10)
        
        if response.status_code == 200:
            cert_data = response.content
            with open(CA_ROOT_FILE, "wb") as f:
                f.write(cert_data)
            print(f"Successfully downloaded Root CA to {CA_ROOT_FILE}", flush=True)
        else:
            print(f"Failed to download Root CA. Status: {response.status_code}, Body: {response.text}", flush=True)
            exit(1)
    except Exception as e:
        print(f"Error downloading Root CA: {e}", flush=True)
        exit(1)

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
        
        APISIX_PUBLIC_IP = os.getenv("APISIX_PUBLIC_IP")
        token_cmd = [
            "step", "ca", "token", "apisix",
            "--password-file", pwd_file,
            "--ca-url", STEP_CA_URL,
            "--root", CA_ROOT_FILE,
            "--san", "apisix",
            "--san", "localhost",
            "--san", "127.0.0.1"
        ]

        if APISIX_PUBLIC_IP:
             print(f"Adding Public IP to SANs: {APISIX_PUBLIC_IP}", flush=True)
             token_cmd.extend(["--san", APISIX_PUBLIC_IP])

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
            "--ca-url", STEP_CA_URL,
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

    APISIX_PUBLIC_IP = os.getenv("APISIX_PUBLIC_IP")
    snis_list = ["apisix", "localhost", "127.0.0.1"]
    if APISIX_PUBLIC_IP:
        snis_list.append(APISIX_PUBLIC_IP)

    # SSL Config with mTLS enabled, but skipped for bootstrapping endpoints
    ssl_config = {
        "id": "1",
        "snis": snis_list,
        "cert": cert_content,
        "key": key_content,
        "client": {
            "ca": ca_content,
            "depth": 10,
            "skip_mtls_uri": [
                "^/roots",
                "^/roots/.*",
                "^/health",
                "^/1.0/.*",
                "^/provisioners",
                "^/provisioners/.*",
                "^/otp/.*",
                "^/sign",
                "^/apisix/status",
                "^/api/v1/auth/.*",
                "^/$"
            ]
        }
    }

    print("Configuring APISIX SSL resource (Enforcing mTLS with exemptions)...", flush=True)
    
    # Put ID 1
    resp = requests.put(f"{APISIX_SSL_URL}/1", headers={"X-API-KEY": ADMIN_KEY}, json=ssl_config)
    print(f"SSL Config Response: {resp.status_code} - {resp.text}", flush=True)
    
    # Cleanup old ID 2 if it exists (from previous dual-config setup)
    requests.delete(f"{APISIX_SSL_URL}/2", headers={"X-API-KEY": ADMIN_KEY})
    
    print("SSL Configuration complete.", flush=True)

if __name__ == "__main__":
    ensure_root_ca()
    get_identity()
    wait_for_apisix()
    create_ssl()
