"""
Base adapter class and factory for certificate providers
"""
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from ...shared.interfaces import ICertificateProvider
from ...shared.models import CertificateRequest, CertificateResponse, CertificateInfo, CertificateStatus


class BaseCertificateAdapter(ICertificateProvider):
    """Base class for certificate adapters"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
    
    @abstractmethod
    async def issue_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue a new certificate"""
        pass
    
    @abstractmethod
    async def get_certificate(self, identifier: str) -> Optional[CertificateInfo]:
        """Get certificate information by identifier"""
        pass
    
    @abstractmethod
    async def revoke_certificate(self, identifier: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate"""
        pass
    
    @abstractmethod
    async def list_certificates(self, status_filter: Optional[CertificateStatus] = None) -> List[CertificateInfo]:
        """List certificates with optional status filter"""
        pass
    
    @abstractmethod
    async def validate_certificate_chain(self, certificate_pem: str) -> bool:
        """Validate certificate chain"""
        pass
    
    @abstractmethod
    async def check_revocation_status(self, certificate_pem: str) -> CertificateStatus:
        """Check certificate revocation status"""
        pass


class CertificateAdapterFactory:
    """Factory for creating certificate adapters"""
    
    @staticmethod
    def create_adapter(adapter_type: str, config: Optional[Dict[str, Any]] = None) -> ICertificateProvider:
        """Create certificate adapter based on type"""
        
        if adapter_type.lower() == "aws":
            from .aws_adapter import AwsCertificateAdapter
            return AwsCertificateAdapter(config)
        
        elif adapter_type.lower() == "internal":
            from .internal_ca_adapter import InternalCAAdapter
            return InternalCAAdapter(config)
        
        elif adapter_type.lower() == "letsencrypt":
            from .letsencrypt_adapter import LetsEncryptAdapter
            return LetsEncryptAdapter(config)
        
        else:
            raise ValueError(f"Unsupported certificate adapter type: {adapter_type}")
    
    @staticmethod
    def get_supported_adapters() -> List[str]:
        """Get list of supported adapter types"""
        return ["aws", "internal", "letsencrypt"]