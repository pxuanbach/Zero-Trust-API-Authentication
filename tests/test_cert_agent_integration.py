"""
Integration tests for Certificate Agent API
"""
import pytest
from datetime import datetime, timedelta
from fastapi import status as http_status

from src.shared.models import CertificateStatus, CertificateInfo, CertificateResponse


class TestCertificateIssuance:
    """Tests for POST /certificates/issue"""
    
    def test_issue_certificate_success(self, client, sample_cert_request):
        """Test successful certificate issuance"""
        response = client.post("/certificates/issue", json=sample_cert_request)
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert "serial_number" in data
        assert "fingerprint_sha256" in data
        assert "certificate_pem" in data
        assert "private_key_pem" in data
        assert data["certificate_pem"].startswith("-----BEGIN CERTIFICATE-----")
        assert data["private_key_pem"].startswith("-----BEGIN")
    
    def test_issue_certificate_with_san(self, client):
        """Test certificate issuance with multiple SANs"""
        request = {
            "common_name": "multi.example.com",
            "organization": "Test Org",
            "country": "US",
            "san_list": ["multi.example.com", "www.multi.example.com", "api.multi.example.com"],
            "key_size": 2048,
            "validity_days": 365
        }
        
        response = client.post("/certificates/issue", json=request)
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert "serial_number" in data


class TestGetCertificate:
    """Tests for GET /certificates/{identifier}"""
    
    def test_get_certificate_success(self, client, sample_cert_request):
        """Test successful retrieval after issuance"""
        # First issue a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        assert issue_response.status_code == http_status.HTTP_200_OK
        serial_number = issue_response.json()["serial_number"]
        
        # Then retrieve it
        response = client.get(f"/certificates/{serial_number}")
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["serial_number"] == serial_number
        assert data["status"] == "valid"
        assert "CN=test.example.com" in data["subject"]
    
    def test_get_certificate_not_found(self, client):
        """Test certificate not found"""
        response = client.get("/certificates/nonexistent-serial-999999")
        
        assert response.status_code == http_status.HTTP_404_NOT_FOUND
        assert "Certificate not found" in response.json()["detail"]


class TestRevokeCertificate:
    """Tests for POST /certificates/{identifier}/revoke"""
    
    def test_revoke_certificate_success(self, client, sample_cert_request):
        """Test successful revocation"""
        # First issue a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        serial_number = issue_response.json()["serial_number"]
        
        # Then revoke it
        response = client.post(f"/certificates/{serial_number}/revoke")
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["success"] is True
        assert "revoked successfully" in data["message"]
        
        # Verify it's revoked
        get_response = client.get(f"/certificates/{serial_number}")
        assert get_response.json()["status"] == "revoked"
    
    def test_revoke_certificate_with_custom_reason(self, client, sample_cert_request):
        """Test revocation with custom reason"""
        # Issue certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        serial_number = issue_response.json()["serial_number"]
        
        # Revoke with custom reason
        response = client.post(f"/certificates/{serial_number}/revoke?reason=key_compromise")
        
        assert response.status_code == http_status.HTTP_200_OK
        assert response.json()["success"] is True


class TestListCertificates:
    """Tests for GET /certificates"""
    
    def test_list_all_certificates(self, client, sample_cert_request):
        """Test list all certificates"""
        # Issue some certificates first
        client.post("/certificates/issue", json=sample_cert_request)
        client.post("/certificates/issue", json={**sample_cert_request, "common_name": "test2.example.com"})
        
        response = client.get("/certificates")
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 2
    
    def test_list_certificates_with_status_filter(self, client, sample_cert_request):
        """Test list with status filter"""
        # Issue and revoke a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        serial = issue_response.json()["serial_number"]
        client.post(f"/certificates/{serial}/revoke")
        
        # List only valid certificates
        response = client.get("/certificates?status_filter=valid")
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert all(cert["status"] == "valid" for cert in data)


class TestValidateCertificateChain:
    """Tests for POST /certificates/validate-chain"""
    
    def test_validate_certificate_chain_valid(self, client, sample_cert_request):
        """Test valid certificate chain"""
        # Issue a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        cert_pem = issue_response.json()["certificate_pem"]
        
        # Validate its chain
        response = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": cert_pem}
        )
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is True
    
    def test_validate_certificate_chain_invalid(self, client):
        """Test invalid certificate chain"""
        invalid_pem = "-----BEGIN CERTIFICATE-----\nINVALID_CERT_DATA\n-----END CERTIFICATE-----"
        
        response = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": invalid_pem}
        )
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["valid"] is False


class TestCheckRevocationStatus:
    """Tests for POST /certificates/check-revocation"""
    
    def test_check_revocation_status_valid(self, client, sample_cert_request):
        """Test revocation status check - valid"""
        # Issue a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        cert_pem = issue_response.json()["certificate_pem"]
        
        # Check its revocation status
        response = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": cert_pem}
        )
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "valid"
    
    def test_check_revocation_status_revoked(self, client, sample_cert_request):
        """Test revocation status check - revoked"""
        # Issue and revoke a certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        cert_data = issue_response.json()
        serial_number = cert_data["serial_number"]
        cert_pem = cert_data["certificate_pem"]
        
        # Revoke it
        client.post(f"/certificates/{serial_number}/revoke")
        
        # Check revocation status
        response = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": cert_pem}
        )
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "revoked"


class TestRotateCertificate:
    """Tests for POST /certificates/rotate"""
    
    def test_rotate_certificate_success(self, client, sample_cert_request):
        """Test successful rotation"""
        # Issue initial certificate
        initial_response = client.post("/certificates/issue", json=sample_cert_request)
        old_serial = initial_response.json()["serial_number"]
        
        # Rotate certificate
        response = client.post(
            f"/certificates/rotate?old_identifier={old_serial}",
            json=sample_cert_request
        )
        
        assert response.status_code == http_status.HTTP_200_OK
        data = response.json()
        assert "serial_number" in data
        assert data["serial_number"] != old_serial  # New cert has different serial
        assert "certificate_pem" in data
        
        # Verify old cert is revoked
        old_cert_response = client.get(f"/certificates/{old_serial}")
        assert old_cert_response.json()["status"] == "revoked"


class TestIntegrationScenarios:
    """
    Integration tests simulating real-world certificate lifecycle scenarios
    These tests chain multiple API calls together to test end-to-end flows
    """
    
    def test_complete_certificate_lifecycle(self, client, sample_cert_request):
        """
        Real-world scenario: Complete certificate lifecycle
        1. Issue a new certificate
        2. Retrieve and verify it
        3. Validate its chain
        4. Check revocation status
        5. List all certificates
        6. Revoke the certificate
        7. Verify revocation status changed
        """
        # Step 1: Issue new certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        assert issue_response.status_code == http_status.HTTP_200_OK
        cert_data = issue_response.json()
        serial_number = cert_data["serial_number"]
        cert_pem = cert_data["certificate_pem"]
        
        # Step 2: Retrieve certificate info
        get_response = client.get(f"/certificates/{serial_number}")
        assert get_response.status_code == http_status.HTTP_200_OK
        cert_info = get_response.json()
        assert cert_info["serial_number"] == serial_number
        assert cert_info["status"] == "valid"
        
        # Step 3: Validate certificate chain
        validate_response = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": cert_pem}
        )
        assert validate_response.status_code == http_status.HTTP_200_OK
        assert validate_response.json()["valid"] is True
        
        # Step 4: Check initial revocation status (should be valid)
        revocation_check_1 = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": cert_pem}
        )
        assert revocation_check_1.status_code == http_status.HTTP_200_OK
        assert revocation_check_1.json()["status"] == "valid"
        
        # Step 5: List all certificates (should include our cert)
        list_response = client.get("/certificates")
        assert list_response.status_code == http_status.HTTP_200_OK
        certs_list = list_response.json()
        assert len(certs_list) >= 1
        assert any(cert["serial_number"] == serial_number for cert in certs_list)
        
        # Step 6: Revoke the certificate
        revoke_response = client.post(
            f"/certificates/{serial_number}/revoke?reason=testing_lifecycle"
        )
        assert revoke_response.status_code == http_status.HTTP_200_OK
        assert revoke_response.json()["success"] is True
        
        # Step 7: Check revocation status again (should be revoked)
        revocation_check_2 = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": cert_pem}
        )
        assert revocation_check_2.status_code == http_status.HTTP_200_OK
        assert revocation_check_2.json()["status"] == "revoked"
    
    def test_certificate_rotation_workflow(self, client, sample_cert_request):
        """
        Real-world scenario: Certificate rotation before expiry
        1. Issue initial certificate
        2. Verify it's valid and in use
        3. Before expiry, rotate to new certificate
        4. Verify old cert is revoked
        5. Verify new cert is valid
        6. List certificates to see both
        """
        # Step 1: Issue initial certificate
        initial_response = client.post("/certificates/issue", json=sample_cert_request)
        assert initial_response.status_code == http_status.HTTP_200_OK
        old_cert = initial_response.json()
        old_serial = old_cert["serial_number"]
        old_pem = old_cert["certificate_pem"]
        
        # Step 2: Verify old certificate is valid
        validate_old = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": old_pem}
        )
        assert validate_old.status_code == http_status.HTTP_200_OK
        assert validate_old.json()["valid"] is True
        
        # Step 3: Rotate certificate (issue new, revoke old)
        rotate_response = client.post(
            f"/certificates/rotate?old_identifier={old_serial}",
            json=sample_cert_request
        )
        assert rotate_response.status_code == http_status.HTTP_200_OK
        new_cert = rotate_response.json()
        new_serial = new_cert["serial_number"]
        assert new_serial != old_serial
        
        # Step 4: Verify old certificate was revoked (superseded)
        old_cert_check = client.get(f"/certificates/{old_serial}")
        assert old_cert_check.json()["status"] == "revoked"
        
        # Step 5: Verify new certificate is valid
        get_new_response = client.get(f"/certificates/{new_serial}")
        assert get_new_response.status_code == http_status.HTTP_200_OK
        assert get_new_response.json()["status"] == "valid"
    
    def test_multiple_certificates_management(self, client, sample_cert_request):
        """
        Real-world scenario: Managing multiple certificates
        1. Issue certificates for different services
        2. List all active certificates
        3. Revoke compromised certificate
        4. Verify state changes
        """
        # Step 1: Issue multiple certificates
        cert1_request = {**sample_cert_request, "common_name": "web.example.com"}
        response1 = client.post("/certificates/issue", json=cert1_request)
        assert response1.status_code == http_status.HTTP_200_OK
        serial1 = response1.json()["serial_number"]
        
        cert2_request = {**sample_cert_request, "common_name": "api.example.com"}
        response2 = client.post("/certificates/issue", json=cert2_request)
        assert response2.status_code == http_status.HTTP_200_OK
        serial2 = response2.json()["serial_number"]
        
        cert3_request = {**sample_cert_request, "common_name": "db.example.com"}
        response3 = client.post("/certificates/issue", json=cert3_request)
        assert response3.status_code == http_status.HTTP_200_OK
        serial3 = response3.json()["serial_number"]
        
        # Step 2: List all certificates
        list_all = client.get("/certificates")
        assert list_all.status_code == http_status.HTTP_200_OK
        all_certs = list_all.json()
        assert len(all_certs) >= 3
        
        # Verify all our certs are in the list
        our_serials = {serial1, serial2, serial3}
        listed_serials = {cert["serial_number"] for cert in all_certs}
        assert our_serials.issubset(listed_serials)
        
        # Step 3: Revoke compromised certificate (api-server)
        revoke_response = client.post(
            f"/certificates/{serial2}/revoke?reason=key_compromise"
        )
        assert revoke_response.status_code == http_status.HTTP_200_OK
        
        # Step 4: Verify revoked cert status
        revoked_cert_response = client.get(f"/certificates/{serial2}")
        assert revoked_cert_response.json()["status"] == "revoked"
        
        # Verify others are still valid
        cert1_response = client.get(f"/certificates/{serial1}")
        assert cert1_response.json()["status"] == "valid"
        
        cert3_response = client.get(f"/certificates/{serial3}")
        assert cert3_response.json()["status"] == "valid"
    
    def test_certificate_validation_and_revocation_check_workflow(self, client, sample_cert_request):
        """
        Real-world scenario: Client verifying certificate before trusting
        1. Receive certificate from peer
        2. Validate certificate chain
        3. Check revocation status via OCSP/CRL
        4. Make trust decision based on results
        """
        # Scenario A: Valid certificate
        issue_response = client.post("/certificates/issue", json=sample_cert_request)
        valid_cert_pem = issue_response.json()["certificate_pem"]
        
        # Step 1: Validate chain
        validate_response = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": valid_cert_pem}
        )
        assert validate_response.status_code == http_status.HTTP_200_OK
        chain_valid = validate_response.json()["valid"]
        
        # Step 2: Check revocation status
        revocation_response = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": valid_cert_pem}
        )
        assert revocation_response.status_code == http_status.HTTP_200_OK
        revocation_status = revocation_response.json()["status"]
        
        # Decision: Trust certificate
        can_trust = chain_valid and revocation_status == "valid"
        assert can_trust is True
        
        # Scenario B: Revoked certificate
        issue_response2 = client.post("/certificates/issue", json=sample_cert_request)
        revoked_cert_data = issue_response2.json()
        revoked_cert_pem = revoked_cert_data["certificate_pem"]
        serial = revoked_cert_data["serial_number"]
        
        # Revoke the certificate
        client.post(f"/certificates/{serial}/revoke")
        
        # Chain is still valid (certificate itself is cryptographically valid)
        validate_revoked = client.post(
            "/certificates/validate-chain",
            json={"certificate_pem": revoked_cert_pem}
        )
        assert validate_revoked.json()["valid"] is True
        
        # But revocation check shows it's revoked
        check_revoked = client.post(
            "/certificates/check-revocation",
            json={"certificate_pem": revoked_cert_pem}
        )
        assert check_revoked.json()["status"] == "revoked"
        
        # Decision: Reject certificate
        chain_valid_revoked = validate_revoked.json()["valid"]
        status_revoked = check_revoked.json()["status"]
        can_trust_revoked = chain_valid_revoked and status_revoked == "valid"
        assert can_trust_revoked is False
