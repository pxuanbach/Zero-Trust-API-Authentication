import pytest
import requests
from tests.constants import (
    USERNAME, PASSWORD, APISIX_GATEWAY_URL, REALM, CLIENT_ID, CLIENT_SECRET
)

def get_admin_token(settings):
    """Helper to get Admin Token"""
    gateway_auth_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/auth"
    token_url = f"{gateway_auth_url}/realms/{settings[REALM]}/protocol/openid-connect/token"
    
    payload = {
        "client_id": settings[CLIENT_ID],
        "client_secret": settings[CLIENT_SECRET],
        "username": "admin",
        "password": "adminpassword123",
        "grant_type": "password"
    }
    
    response = requests.post(token_url, data=payload)
    response.raise_for_status()
    return response.json()["access_token"]

@pytest.mark.usefixtures("init_apisix_routes")
class TestAuthorization:

    def test_authz_1_normal_user_delete_forbidden(self, settings, auth_headers):
        """
        ID: AUTHZ-1
        Scenario: Normal User attempts DELETE operation
        Expect: 403 Forbidden (Access Denied)
        """
        # Try DELETE on Extension App
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/resource/1"
        resp_ext = requests.delete(ext_url, headers=auth_headers)
        
        assert resp_ext.status_code == 403, f"Expected 403, got {resp_ext.status_code}"
        assert resp_ext.json().get("error") == "access_denied"
        assert resp_ext.json().get("error_description") == "not_authorized"

        # Try DELETE on CRM App
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/data/1"
        resp_crm = requests.delete(crm_url, headers=auth_headers)
        
        assert resp_crm.status_code == 403, f"Expected 403, got {resp_crm.status_code}"
        assert resp_crm.json().get("error") == "access_denied"
        assert resp_crm.json().get("error_description") == "not_authorized"

    def test_authz_2_admin_user_delete_allowed(self, settings):
        """
        ID: AUTHZ-2
        Scenario: Admin User attempts DELETE operation
        Expect: 200 OK (Allowed by Gateway)
        """
        admin_token = get_admin_token(settings)
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Try DELETE on Extension App
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/resource/1"
        resp_ext = requests.delete(ext_url, headers=admin_headers)
        
        assert resp_ext.status_code == 200, f"Admin DELETE failed: {resp_ext.text}"
        assert resp_ext.json()["status"] == "deleted"

        # Try DELETE on CRM App
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/data/1"
        resp_crm = requests.delete(crm_url, headers=admin_headers)
        
        assert resp_crm.status_code == 200, f"Admin DELETE failed: {resp_crm.text}"
        assert resp_crm.json()["status"] == "deleted"

    def test_authz_3_normal_user_get_allowed(self, settings, auth_headers):
        """
        ID: AUTHZ-3
        Scenario: Normal User attempts GET operation
        Expect: 200 OK (Allowed) - Regression Test
        """
        # Try GET on Extension App
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        resp_ext = requests.get(ext_url, headers=auth_headers)
        assert resp_ext.status_code == 200

        # Try GET on CRM App
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/"
        resp_crm = requests.get(crm_url, headers=auth_headers)
        assert resp_crm.status_code == 200
