"""
Interface definitions for certificate management
"""
from abc import ABC, abstractmethod
from typing import List, Optional
from .models import CertificateRequest, CertificateResponse, CertificateInfo, CertificateStatus


class ICertificateProvider(ABC):
    """Interface for certificate providers (AWS ACM, Let's Encrypt, Internal CA, etc.)"""
    
    @abstractmethod
    async def issue_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue a new certificate"""
        pass
    
    @abstractmethod
    async def get_certificate(self, identifier: str) -> Optional[CertificateInfo]:
        """Get certificate information by identifier (serial number, ARN, etc.)"""
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
        """Check certificate revocation status (CRL/OCSP)"""
        pass


class ICacheProvider(ABC):
    """Interface for cache providers (Redis, Memcached, etc.)"""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: str, expire_seconds: Optional[int] = None) -> bool:
        """Set value in cache with optional expiration"""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        pass