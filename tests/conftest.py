"""
Pytest configuration and shared fixtures
"""
import os
import shutil
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from src.cert_agent.main import CertificateAgent


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment and clean up after all tests"""
    # Set test certificate storage path BEFORE importing config
    os.environ["CERT_AGENT_CERT_STORAGE_PATH"] = "certs_test/"
    
    # Reload config to pick up test environment variables
    from src.cert_agent.config import reload_settings
    reload_settings()
    
    # Create test certs directory if it doesn't exist
    test_certs_dir = Path("certs_test")
    test_certs_dir.mkdir(exist_ok=True)
    
    yield
    
    # Clean up test certificates after all tests
    if test_certs_dir.exists():
        shutil.rmtree(test_certs_dir)


@pytest.fixture(autouse=True)
def clear_test_certs():
    """Clear test certificates before each test"""
    test_certs_dir = Path("certs_test")
    if test_certs_dir.exists():
        # Remove all files in the directory
        for item in test_certs_dir.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
    else:
        test_certs_dir.mkdir(exist_ok=True)
    
    yield


@pytest.fixture
def certificate_agent():
    """Create CertificateAgent instance with real internal CA adapter"""
    # Ensure config is reloaded with test environment variables
    from src.cert_agent.config import reload_settings, get_settings
    settings = reload_settings()
    
    agent = CertificateAgent(adapter_type="internal")
    
    # Initialize the provider manually with test config (bypass lifespan)
    from src.cert_agent.adapters.base_adapter import CertificateAdapterFactory
    adapter_config = {
        "ca_cert_path": settings.CA_CERT_PATH,
        "ca_key_path": settings.CA_KEY_PATH,
        "cert_storage_path": settings.CERT_STORAGE_PATH,
    }
    agent.cert_provider = CertificateAdapterFactory.create_adapter("internal", adapter_config)
    
    yield agent


@pytest.fixture
def client(certificate_agent):
    """TestClient for making HTTP requests"""
    return TestClient(certificate_agent.app)


@pytest.fixture
def sample_cert_request():
    """Sample certificate request"""
    return {
        "common_name": "test.example.com",
        "organization": "Test Org",
        "country": "US",
        "san_list": ["test.example.com", "www.test.example.com"],
        "key_size": 2048,
        "validity_days": 365
    }


@pytest.fixture
def sample_certificate_pem():
    """Sample certificate PEM"""
    return "-----BEGIN CERTIFICATE-----\nMOCK_CERT_DATA\n-----END CERTIFICATE-----"
