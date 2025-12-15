import requests
import json
import os

KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://keycloak:8080")
REALM = "zero-trust"

# Keycloak Master Admin Credentials
KC_MASTER_ADMIN_USER = "admin"
KC_MASTER_ADMIN_PASS = "admin123"

CLIENT_ID = "test-client"

def get_admin_token():
    """Get Access Token for Keycloak Master Admin (admin-cli)"""
    url = f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token"
    data = {
        "username": KC_MASTER_ADMIN_USER,
        "password": KC_MASTER_ADMIN_PASS,
        "grant_type": "password",
        "client_id": "admin-cli"
    }
    resp = requests.post(url, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

def setup_authorization():
    token = get_admin_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Get Client UUID
    clients_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
    resp = requests.get(clients_url, headers=headers)
    resp.raise_for_status()
    clients = resp.json()
    if not clients:
        print(f"Client {CLIENT_ID} not found")
        return
    client_uuid = clients[0]["id"]
    print(f"Found Client UUID: {client_uuid}")

    authz_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/{client_uuid}/authz/resource-server"

    # Create Resource for Extension App DELETE
    resource_name = "Extension App Delete Resource"
    resource_data = {
        "name": resource_name,
        "uris": ["/api/v1/extension-app/*"],
        "scopes": [{"name": "delete"}]
    }
    
    # Check if exists
    resp = requests.get(f"{authz_url}/resource?name={resource_name}", headers=headers)
    if resp.json():
        print(f"Resource '{resource_name}' already exists")
        resource_id = resp.json()[0]["_id"]
    else:
        resp = requests.post(f"{authz_url}/resource", headers=headers, json=resource_data)
        if resp.status_code == 201:
            print(f"Created Resource: {resource_name}")
            resource_id = resp.json()["_id"]
        else:
            print(f"Failed to create resource: {resp.text}")
            return

    # Get Admin Policy ID (Assuming it exists from realm-config.json)
    policy_name = "Admin Only Policy"
    resp = requests.get(f"{authz_url}/policy?name={policy_name}", headers=headers)
    if not resp.json():
        print(f"Policy '{policy_name}' not found")
        return
    policy_id = resp.json()[0]["id"]
    print(f"Found Policy ID: {policy_id}")

    # Create Permission associating Resource + Policy
    perm_name = "Extension App Delete Permission"
    perm_data = {
        "name": perm_name,
        "type": "resource",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "resources": [resource_id],
        "policies": [policy_id]
    }

    resp = requests.get(f"{authz_url}/policy?name={perm_name}", headers=headers)
    if resp.json():
        print(f"Permission '{perm_name}' already exists")
    else:
        resp = requests.post(f"{authz_url}/policy/resource", headers=headers, json=perm_data)
        if resp.status_code == 201:
            print(f"Created Permission: {perm_name}")
        else:
            print(f"Failed to create permission: {resp.text}")

    # Create Resource for CRM App DELETE
    crm_resource_name = "CRM App Delete Resource"
    crm_resource_data = {
        "name": crm_resource_name,
        "uris": ["/api/v1/crm/*"],
        "scopes": [{"name": "delete"}]
    }
    
    # Check if exists
    resp = requests.get(f"{authz_url}/resource?name={crm_resource_name}", headers=headers)
    if resp.json():
        print(f"Resource '{crm_resource_name}' already exists")
        crm_resource_id = resp.json()[0]["_id"]
    else:
        resp = requests.post(f"{authz_url}/resource", headers=headers, json=crm_resource_data)
        if resp.status_code == 201:
            print(f"Created Resource: {crm_resource_name}")
            crm_resource_id = resp.json()["_id"]
        else:
            print(f"Failed to create resource: {resp.text}")
            return

    # Create Permission for CRM App
    crm_perm_name = "CRM App Delete Permission"
    crm_perm_data = {
        "name": crm_perm_name,
        "type": "resource",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "resources": [crm_resource_id],
        "policies": [policy_id]
    }

    resp = requests.get(f"{authz_url}/policy?name={crm_perm_name}", headers=headers)
    if resp.json():
        print(f"Permission '{crm_perm_name}' already exists")
    else:
        resp = requests.post(f"{authz_url}/policy/resource", headers=headers, json=crm_perm_data)
        if resp.status_code == 201:
            print(f"Created Permission: {crm_perm_name}")
        else:
            print(f"Failed to create permission: {resp.text}")

if __name__ == "__main__":
    try:
        setup_authorization()
    except Exception as e:
        print(f"Error setting up Keycloak AuthZ: {e}")
