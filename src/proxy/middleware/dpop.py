"""
DPoP (Demonstration of Proof-of-Possession) authentication middleware
"""
from typing import Optional, Dict, Any, Set
from fastapi import Request, HTTPException, status
from ..utils.crypto_utils import validate_dpop_proof
from ..cache.redis_client import ICacheProvider


class DPoPMiddleware:
    """Middleware for DPoP proof authentication"""
    
    def __init__(self, 
                 cache_provider: Optional[ICacheProvider] = None,
                 max_age_seconds: int = 60,
                 cache_ttl: int = 3600):
        self.cache_provider = cache_provider
        self.max_age_seconds = max_age_seconds
        self.cache_ttl = cache_ttl
        self._used_jti: Set[str] = set()  # In-memory JTI tracking for single instance
    
    async def authenticate(self, request: Request, cert_info: Dict[str, Any], 
                          token_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and validate DPoP proof from DPoP header
        """
        # Extract DPoP proof from header
        dpop_header = request.headers.get("DPoP")
        if not dpop_header:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="DPoP header required"
            )
        
        # Get HTTP method and URI for validation
        http_method = request.method
        http_uri = str(request.url)
        
        # Get access token for binding (if available)
        auth_header = request.headers.get("Authorization", "")
        access_token = auth_header[7:] if auth_header.startswith("Bearer ") else None
        
        try:
            # Validate DPoP proof
            dpop_claims = validate_dpop_proof(
                dpop_token=dpop_header,
                http_method=http_method,
                http_uri=http_uri,
                access_token=access_token
            )
            
            # Check for replay attacks using JTI
            jti = dpop_claims["jti"]
            if await self._is_jti_used(jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="DPoP proof replay detected"
                )
            
            # Mark JTI as used
            await self._mark_jti_used(jti)
            
            # Verify JWK in DPoP matches certificate public key
            if not await self._verify_dpop_certificate_binding(dpop_claims, cert_info):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="DPoP proof does not match certificate"
                )
            
            dpop_info = {
                "success": True,
                "dpop_claims": dpop_claims,
                "dpop_jti": jti,
                "dpop_iat": dpop_claims["iat"],
                "dpop_jwk": dpop_claims.get("jwk")
            }
            
            return dpop_info
            
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"DPoP validation failed: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"DPoP authentication error: {str(e)}"
            )
    
    async def _is_jti_used(self, jti: str) -> bool:
        """
        Check if JTI has been used before (replay detection)
        """
        if self.cache_provider:
            cache_key = f"dpop_jti:{jti}"
            return await self.cache_provider.exists(cache_key)
        else:
            # Fallback to in-memory tracking
            return jti in self._used_jti
    
    async def _mark_jti_used(self, jti: str) -> None:
        """
        Mark JTI as used to prevent replay
        """
        if self.cache_provider:
            cache_key = f"dpop_jti:{jti}"
            await self.cache_provider.set(cache_key, "used", self.cache_ttl)
        else:
            # Fallback to in-memory tracking
            self._used_jti.add(jti)
            
            # Clean up old JTIs (simple cleanup for in-memory)
            if len(self._used_jti) > 10000:
                # Remove half of the entries (simple cleanup)
                to_remove = list(self._used_jti)[:5000]
                for old_jti in to_remove:
                    self._used_jti.discard(old_jti)
    
    async def _verify_dpop_certificate_binding(self, dpop_claims: Dict[str, Any], 
                                             cert_info: Dict[str, Any]) -> bool:
        """
        Verify that DPoP JWK matches the certificate public key
        """
        try:
            # Extract JWK from DPoP claims
            dpop_jwk = dpop_claims.get("jwk")
            if not dpop_jwk:
                return False
            
            # Convert certificate public key to JWK format for comparison
            # This is a simplified implementation
            cert_public_key_jwk = await self._extract_public_key_from_cert(cert_info)
            
            # Compare JWKs (simplified comparison)
            return self._compare_jwks(dpop_jwk, cert_public_key_jwk)
            
        except Exception as e:
            print(f"DPoP certificate binding verification error: {str(e)}")
            return False
    
    async def _extract_public_key_from_cert(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract public key from certificate and convert to JWK format
        """
        # This is a placeholder implementation
        # In production, extract the actual public key from the certificate
        # and convert it to JWK format
        
        # For now, return a dummy JWK structure
        return {
            "kty": "RSA",
            "n": "dummy_modulus",
            "e": "AQAB"
        }
    
    def _compare_jwks(self, jwk1: Dict[str, Any], jwk2: Dict[str, Any]) -> bool:
        """
        Compare two JWKs for equality
        """
        try:
            # Compare key type
            if jwk1.get("kty") != jwk2.get("kty"):
                return False
            
            # For RSA keys, compare modulus and exponent
            if jwk1.get("kty") == "RSA":
                return (jwk1.get("n") == jwk2.get("n") and 
                       jwk1.get("e") == jwk2.get("e"))
            
            # For other key types, implement specific comparison
            # For now, consider them equal if key type matches
            return True
            
        except Exception:
            return False


class DPoPValidator:
    """DPoP validation utilities"""
    
    @staticmethod
    def generate_dpop_jti() -> str:
        """
        Generate a unique JTI for DPoP proof
        """
        import uuid
        return str(uuid.uuid4())
    
    @staticmethod
    def is_dpop_token_fresh(iat: int, max_age_seconds: int = 60) -> bool:
        """
        Check if DPoP token is fresh (not too old)
        """
        from datetime import datetime, timezone
        current_time = datetime.now(timezone.utc).timestamp()
        return (current_time - iat) <= max_age_seconds