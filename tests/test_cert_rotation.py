import pytest
import requests
import subprocess
import time
import shutil
from pathlib import Path
from datetime import datetime
from tests.constants import APISIX_GATEWAY_URL


def run_terraform_apply(tf_dir: str, target: str = None, var: dict = None) -> subprocess.CompletedProcess:
    """
    Run terraform apply in the specified directory.
    
    Args:
        tf_dir: Path to terraform directory
        target: Optional resource target (e.g., 'tls_locally_signed_cert.service["crm-app"]')
        var: Optional dict of variables (e.g., {'cert_validity_hours': 0.003})
    """
    cmd = ["terraform", "apply", "-auto-approve"]
    
    if target:
        cmd.extend(["-target", target])
    
    if var:
        for key, value in var.items():
            cmd.extend(["-var", f"{key}={value}"])
    
    result = subprocess.run(
        cmd,
        cwd=tf_dir,
        capture_output=True,
        text=True,
        timeout=120
    )
    return result


def backup_certs(cert_dir: str, backup_dir: str) -> str:
    """Backup current certificates to a backup directory."""
    backup_path = Path(backup_dir)
    backup_path.mkdir(parents=True, exist_ok=True)
    
    cert_path = Path(cert_dir)
    if cert_path.exists():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_target = backup_path / f"certs_backup_{timestamp}"
        shutil.copytree(cert_path, backup_target)
        return str(backup_target)
    return None


def restore_certs(backup_dir: str, cert_dir: str):
    """Restore certificates from backup directory."""
    backup_path = Path(backup_dir)
    cert_path = Path(cert_dir)
    
    if backup_path.exists():
        if cert_path.exists():
            shutil.rmtree(cert_path)
        shutil.copytree(backup_path, cert_path)


# ===== TEST FIXTURES =====

@pytest.fixture(scope="module")
def tf_dir():
    """Path to Terraform TLS provider directory."""
    return str(Path(__file__).parent.parent / "src" / "tls_provider")


@pytest.fixture(scope="module")
def cert_dir():
    """Path to certificates directory."""
    return str(Path(__file__).parent.parent / "src" / "certs")


@pytest.fixture(scope="module")
def backup_dir(tmp_path_factory):
    """Temporary directory for certificate backups."""
    return str(tmp_path_factory.mktemp("cert_backups"))


@pytest.fixture(scope="function")
def cert_backup(cert_dir, backup_dir):
    """Backup certificates before test, restore after test."""
    backup_path = backup_certs(cert_dir, backup_dir)
    yield backup_path
    if backup_path:
        restore_certs(backup_path, cert_dir)


@pytest.fixture(scope="module")
def rotated_certs(tf_dir, cert_dir, backup_dir):
    """Rotate certificates once for all tests in the module."""
    backup_path = backup_certs(cert_dir, backup_dir)
    
    # Run terraform apply to rotate all certs
    result = run_terraform_apply(tf_dir)
    if result.returncode != 0:
        pytest.fail(f"Terraform apply failed: {result.stderr}")
    
    time.sleep(5)
    
    yield
    
    # Restore original certs after all tests
    if backup_path:
        restore_certs(backup_path, cert_dir)
        time.sleep(5)  # Wait for services to reload original certs


@pytest.mark.usefixtures("init_apisix_routes", "rotated_certs")
class TestCertificateRotation:
    """Test cases for certificate rotation scenarios."""
    
    def test_rotation_apisix_to_extension_app_after_rotation(self, settings, auth_headers):
        """
        ID: CERT-ROT-1
        Scenario: Verify APISIX → Extension App mTLS call after cert rotation
        Expect: APISIX can connect to Extension App via mTLS (200 OK)
        """
        ext_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/"
        response = requests.get(ext_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        assert response.json()["service"] == "extension-app1"
    
    def test_rotation_apisix_to_crm_app_after_rotation(self, settings, auth_headers):
        """
        ID: CERT-ROT-2
        Scenario: Verify APISIX → CRM App mTLS call after cert rotation
        Expect: APISIX can connect to CRM App via mTLS (200 OK)
        """
        crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/crm/"
        response = requests.get(crm_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        assert response.json()["service"] == "crm-app"
    
    def test_rotation_extension_app_to_crm_app_after_rotation(self, settings, auth_headers):
        """
        ID: CERT-ROT-3
        Scenario: Verify Extension App → CRM App mTLS call after cert rotation
        Expect: Extension App can call CRM App via mTLS (200 OK)
        """
        call_crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/call-crm"
        response = requests.get(call_crm_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        
        assert "crm_response" in data
        assert data["crm_response"]["context_received"]["source"] == "extension-app1"
        assert data["crm_response"]["service"] == "crm-app"
    
    def test_rotation_single_service_old_cert_still_valid(self, settings, auth_headers, tf_dir, cert_backup):
        """
        ID: CERT-ROT-4
        Scenario: Rotate only crm-app cert, extension-app1 keeps old cert (still valid)
        Expect:
            - Only crm-app cert is regenerated
            - Extension-app1 cert unchanged
            - Extension App → CRM App mTLS still works (same CA, both certs valid)
        """
        result = run_terraform_apply(
            tf_dir,
            target='tls_locally_signed_cert.service["crm-app"]'
        )
        assert result.returncode == 0, f"Terraform apply failed: {result.stderr}"
        
        time.sleep(5)
        
        # Verify extension-app1 (with old cert) can still call crm-app (with new cert)
        call_crm_url = f"{settings[APISIX_GATEWAY_URL]}/api/test/extension-app/call-crm"
        response = requests.get(call_crm_url, headers=auth_headers)
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
        data = response.json()
        assert "crm_response" in data
        assert data["crm_response"]["context_received"]["source"] == "extension-app1"
        assert data["crm_response"]["service"] == "crm-app"
