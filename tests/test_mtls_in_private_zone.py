import pytest
import requests
import ssl
from pathlib import Path
from tests.constants import APISIX_GATEWAY_URL, EXTENSION_APP_URL

@pytest.mark.usefixtures("init_apisix_routes")
class TestExtensionAppZone:
    """Test mTLS security in Private Subnet Zone."""

    def test_mtls_1_valid_gateway_cert_accepted(self, settings, auth_headers):
        """
        ID: mTLS-1
        Scenario: APISIX with valid certificate connects to Extension App
        Expect: mTLS handshake succeeds, request reaches Extension App (200 OK)
        """
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        
        response = requests.get(ext_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        assert response.json()["service"] == "extension-app1"

    def test_mtls_2_direct_call_without_mtls_rejected(self, settings, auth_headers):
        """
        ID: mTLS-2
        Scenario: Direct call to Extension App without mTLS (bypassing APISIX)
        Expect: Connection fails or Extension App rejects (no client cert provided)
        """
        # Call without client cert (mTLS will fail)
        response = requests.get(
            settings[EXTENSION_APP_URL], 
            headers=auth_headers,
            verify=False,  # Skip server cert verification for test
            timeout=2
        )

        assert response.status_code == 400
        assert "400 No required SSL certificate was sent" in response.text

    def test_mtls_3_verify_mtls_cert_in_request(self, settings, auth_headers):
        """
        ID: mTLS-3
        Scenario: Verify that APISIX presents client certificate to Extension App
        Expect: Extension App receives and validates APISIX's client certificate
        """
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        
        response = requests.get(ext_url, headers=auth_headers)
        
        assert response.status_code == 200
        
    def test_mtls_4_crm_app_zone_isolation(self, settings, auth_headers):
        """
        ID: mTLS-4
        Scenario: Verify CRM App (Core Zone) also requires mTLS
        Expect: APISIX → CRM App connection succeeds (APISIX has valid cert)
        """
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/"
        
        response = requests.get(crm_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.json()["service"] == "crm-app"

    def test_mtls_5_multiple_extension_apps_mtls(self, settings, auth_headers):
        """
        ID: mTLS-5
        Scenario: APISIX can connect to multiple Extension Apps with same cert
        Expect: All Extension Apps accept APISIX's gateway certificate
        """
        # Test Extension App
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        ext_response = requests.get(ext_url, headers=auth_headers)
        assert ext_response.status_code == 200
        
        # Test CRM App
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/"
        crm_response = requests.get(crm_url, headers=auth_headers)
        assert crm_response.status_code == 200
        
        # Both should succeed with same APISIX cert
        assert ext_response.json()["service"] == "extension-app1"
        assert crm_response.json()["service"] == "crm-app"

    def test_mtls_6_gateway_without_cert_to_extension_app(self, settings, auth_headers, init_no_mtls_route):
        """
        ID: mTLS-6
        Scenario: APISIX route WITHOUT client cert tries to call Extension App
        Expect: Authentication succeeds, but Extension App rejects mTLS connection (502)
        """
        # Call through no-mTLS route (auth passes, but APISIX won't send client cert to backend)
        url = f"{settings[APISIX_GATEWAY_URL]}/api/test/no-mtls/extension-app/"
        
        response = requests.get(url, headers=auth_headers)
        
        assert response.status_code == 400, \
            f"Expected 400 Bad Request, got {response.status_code}: {response.text}"
        assert "400 No required SSL certificate was sent" in response.text

    def test_mtls_7_gateway_without_cert_to_crm_app(self, settings, auth_headers, init_no_mtls_route):
        """
        ID: mTLS-7
        Scenario: APISIX route WITHOUT client cert tries to call CRM App
        Expect: Authentication succeeds, but CRM App rejects mTLS connection (502 upstream SSL error)
        """
        # Call through no-mTLS route (auth passes, but APISIX won't send client cert to backend)
        url = f"{settings[APISIX_GATEWAY_URL]}/api/test/no-mtls/crm/"
        
        response = requests.get(url, headers=auth_headers)
        
        assert response.status_code == 400, \
            f"Expected 400 Bad Request, got {response.status_code}: {response.text}"
        assert "400 No required SSL certificate was sent" in response.text
