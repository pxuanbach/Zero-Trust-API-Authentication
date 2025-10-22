"""
mTLS authentication middleware
"""
import ssl
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer
from ..utils.crypto_utils import extract_certificate_info
from ..cache.redis_client import ICacheProvider
from ...shared.models import CertificateInfo, CertificateStatus


class MTLSMiddleware:
    """Middleware for mTLS authentication"""
    
    def __init__(self, cache_provider: Optional[ICacheProvider] = None, cache_ttl: int = 300):
        self.cache_provider = cache_provider
        self.cache_ttl = cache_ttl
    
    async def authenticate(self, request: Request) -> Dict[str, Any]:
        """
        Extract and validate client certificate from mTLS connection
        """
        # Extract client certificate from TLS connection
        client_cert_pem = self._extract_client_certificate(request)
        
        if not client_cert_pem:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Client certificate required"
            )
        
        # Check cache first
        cert_fingerprint = None
        if self.cache_provider:
            from ..utils.crypto_utils import get_certificate_fingerprint
            cert_fingerprint = get_certificate_fingerprint(client_cert_pem)
            cache_key = f"cert_validation:{cert_fingerprint}"
            
            cached_result = await self.cache_provider.get_json(cache_key)
            if cached_result:
                return cached_result
        
        # Validate certificate
        cert_info = await self._validate_certificate(client_cert_pem)
        
        # Cache the result
        if self.cache_provider and cert_fingerprint:
            cache_key = f"cert_validation:{cert_fingerprint}"
            await self.cache_provider.set_json(cache_key, cert_info, self.cache_ttl)
        
        return cert_info
    
    def _extract_client_certificate(self, request: Request) -> Optional[str]:
        """
        Extract client certificate from HTTPS request
        Note: This is a simplified implementation. In production, you would
        extract the certificate from the TLS connection context.
        """
        # In FastAPI with uvicorn, client certificate extraction depends on the ASGI server
        # This is a placeholder implementation
        
        # Check if certificate is passed via header (for testing)
        cert_header = request.headers.get("X-Client-Certificate")
        if cert_header:
            return cert_header
        
        # In production, extract from TLS context
        # This requires proper ASGI server configuration with client cert verification
        scope = request.scope
        if "tls" in scope and scope["tls"] and "client_cert" in scope["tls"]:
            return scope["tls"]["client_cert"]
        
        return None
    
    async def _validate_certificate(self, cert_pem: str) -> Dict[str, Any]:
        """
        Validate client certificate
        """
        try:
            # Extract certificate information
            cert_info = extract_certificate_info(cert_pem)
            
            # Check certificate validity period
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            
            if now < cert_info["not_before"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Certificate not yet valid"
                )
            
            if now > cert_info["not_after"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Certificate has expired"
                )
            
            # TODO: Add additional validations:
            # - Certificate chain validation
            # - CRL/OCSP checking
            # - Trusted CA verification
            
            return {
                "success": True,
                "certificate_info": cert_info,
                "client_id": cert_info["subject"],
                "fingerprint": cert_info["fingerprint_sha256"]
            }
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Certificate validation failed: {str(e)}"
            )


class CertificateValidator:
    """Certificate validation utilities"""
    
    @staticmethod
    async def validate_certificate_chain(cert_pem: str, ca_cert_pem: str) -> bool:
        """
        Validate certificate chain against CA certificate
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            
            # Load certificates
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
            
            # Verify certificate signature against CA
            ca_public_key = ca_cert.public_key()
            
            # Verify signature (simplified)
            try:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm
                )
                return True
            except Exception:
                return False
                
        except Exception as e:
            print(f"Certificate chain validation error: {str(e)}")
            return False
    
    @staticmethod
    async def check_certificate_revocation(cert_pem: str) -> CertificateStatus:
        """
        Check certificate revocation status via CRL/OCSP
        """
        # TODO: Implement CRL/OCSP checking
        # This is a placeholder implementation
        try:
            # In production, implement proper CRL/OCSP validation
            # For now, assume certificate is valid
            return CertificateStatus.VALID
            
        except Exception as e:
            print(f"Certificate revocation check error: {str(e)}")
            return CertificateStatus.VALID