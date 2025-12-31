import os
import sys
import subprocess
import requests
import getpass
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APISIX_URL = os.getenv("APISIX_URL", "https://apisix:9443")
CA_ROUTE = APISIX_URL
SERVICE_NAME = os.getenv("SERVICE_NAME", "extension-app1")

APP_DIR = "/app"
CERT_DIR = f"{APP_DIR}/certs/{SERVICE_NAME}"
CA_CERT_DIR = f"{APP_DIR}/certs/ca"
CA_CERT_PATH = f"{CA_CERT_DIR}/ca.crt"
SERVER_CERT_PATH = f"{CERT_DIR}/{SERVICE_NAME}.crt"
SERVER_KEY_PATH = f"{CERT_DIR}/{SERVICE_NAME}.key"

def ensure_dirs():
    os.makedirs(CERT_DIR, exist_ok=True)
    os.makedirs(CA_CERT_DIR, exist_ok=True)

def fetch_root_ca():
    """Fetch the Root CA certificate from the CA via APISIX."""
    print(f"[*] Fetching Root CA from {CA_ROUTE}/roots ...")
    try:
        response = requests.get(f"{CA_ROUTE}/roots", verify=False, timeout=10)
        
        if response.status_code == 201:
            data = response.json()
            crts = data.get("crts", [])
            if not crts:
                print("[-] No certificates found in /roots response")
                sys.exit(1)
            
            root_pem = crts[0]
            
            with open(CA_CERT_PATH, "w") as f:
                f.write(root_pem)
            print(f"[+] Root CA saved to {CA_CERT_PATH}")
        else:
            print(f"[-] Failed to fetch Root CA. Status: {response.status_code}")
            print("Response:", response.text)
            sys.exit(1)
            
    except Exception as e:
        print(f"[-] Error fetching Root CA: {e}")
        sys.exit(1)
            

def generate_identity_cert():
    """Generate identity certificate using step CLI."""
    print(f"[*] Requesting Identity Certificate for '{SERVICE_NAME}'...")
    
    # Prompt for CA password if not in env
    password = os.getenv("CA_PASSWORD")
    if not password:
        try:
            password = getpass.getpass("Enter CA Provisioner Password: ")
        except EOFError:
            print("[-] No password provided and no TTY.")
            sys.exit(1)
            
    if not password:
        print("[-] Password is required.")
        sys.exit(1)

    pwd_file = "/tmp/pwd.tmp"
    with open(pwd_file, "w") as f:
        f.write(password)

    cmd = [
        "step", "ca", "certificate",
        SERVICE_NAME,
        SERVER_CERT_PATH,
        SERVER_KEY_PATH,
        "--ca-url", CA_ROUTE,
        "--root", CA_CERT_PATH,
        "--provisioner-password-file", pwd_file,
        "--force"
    ]

    print(f"[*] Executing: {' '.join(cmd)}")
    
    try:
        # Capture output
        result = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True
        )
        print("[+] Certificate generated successfully.")
        print(f"    - Certificate: {SERVER_CERT_PATH}")
        print(f"    - Key: {SERVER_KEY_PATH}")
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to generate certificate.")
        print(f"Error Output:\n{e.stderr}")
        print(f"Standard Output:\n{e.stdout}")
        sys.exit(1)
        
    finally:
        if os.path.exists(pwd_file):
            os.remove(pwd_file)

def main():
    print("--- Extension App 1 Certificate Bootstrap Script ---")
    ensure_dirs()
    
    # Check if APISIX is reachable
    print(f"[*] Checking connectivity to APISIX ({APISIX_URL})...")
    # Loop/Wait logic could go here, but script is 'manual' so just try once or user retries
    
    fetch_root_ca()
    generate_identity_cert()
    print("[+] Bootstrap complete. Application can now start mTLS.")

if __name__ == "__main__":
    main()
