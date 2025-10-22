"""
JWT token authentication middleware
"""
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, status
from ..utils.crypto_utils import validate_jwt_token, verify_certificate_binding
from ..cache.redis_client import ICacheProvider


class TokenMiddleware:
    """Middleware for JWT token authentication"""
    
    def __init__(self, 
                 jwt_public_key: str,
                 jwt_algorithm: str = "RS256",
                 jwt_audience: str = None,
                 jwt_issuer: str = None,
                 cache_provider: Optional[ICacheProvider] = None,
                 cache_ttl: int = 300):
        self.jwt_public_key = jwt_public_key
        self.jwt_algorithm = jwt_algorithm
        self.jwt_audience = jwt_audience
        self.jwt_issuer = jwt_issuer
        self.cache_provider = cache_provider
        self.cache_ttl = cache_ttl
    
    async def authenticate(self, request: Request, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and validate JWT token from Authorization header
        """
        # Extract JWT token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required"
            )
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Check cache first
        if self.cache_provider:
            cache_key = f"token_validation:{hash(token)}"
            cached_result = await self.cache_provider.get_json(cache_key)
            if cached_result:
                # Still need to verify certificate binding
                if await self._verify_token_certificate_binding(cached_result, cert_info):
                    return cached_result
        
        # Validate JWT token
        try:
            payload = validate_jwt_token(
                token=token,
                public_key=self.jwt_public_key,
                algorithm=self.jwt_algorithm,
                audience=self.jwt_audience,
                issuer=self.jwt_issuer
            )
            
            token_info = {
                "success": True,
                "token_claims": payload,
                "token_subject": payload.get("sub"),
                "token_audience": payload.get("aud"),
                "token_issuer": payload.get("iss"),
                "token_expiry": payload.get("exp")
            }
            
            # Verify certificate binding with token
            if not await self._verify_token_certificate_binding(token_info, cert_info):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Certificate-token binding verification failed"
                )
            
            # Cache the result
            if self.cache_provider:
                cache_key = f"token_validation:{hash(token)}"
                await self.cache_provider.set_json(cache_key, token_info, self.cache_ttl)
            
            return token_info
            
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token validation failed: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token authentication error: {str(e)}"
            )
    
    async def _verify_token_certificate_binding(self, token_info: Dict[str, Any], cert_info: Dict[str, Any]) -> bool:
        """
        Verify that the JWT token is bound to the client certificate
        """
        try:
            token_claims = token_info.get("token_claims", {})
            cnf_claim = token_claims.get("cnf")
            
            if not cnf_claim:
                # If no cnf claim, skip binding verification
                return True
            
            # Get certificate PEM from cert_info (this is simplified)
            # In production, you'd have the actual certificate PEM
            cert_fingerprint = cert_info.get("fingerprint")
            cert_thumbprint = cert_info.get("certificate_info", {}).get("thumbprint_base64url")
            
            if cnf_claim.get("x5t#S256") and cert_thumbprint:
                return cnf_claim["x5t#S256"] == cert_thumbprint
            
            return True
            
        except Exception as e:
            print(f"Certificate-token binding verification error: {str(e)}")
            return False


class TokenValidator:
    """Token validation utilities"""
    
    @staticmethod
    async def get_jwt_public_key_from_url(jwks_url: str) -> str:
        """
        Fetch JWT public key from JWKS endpoint
        """
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                response = await client.get(jwks_url)
                response.raise_for_status()
                jwks = response.json()
                
                # Extract first key (simplified)
                if "keys" in jwks and len(jwks["keys"]) > 0:
                    key = jwks["keys"][0]
                    # Convert JWK to PEM format
                    # This is simplified - use proper JWK library in production
                    return TokenValidator._jwk_to_pem(key)
                
                raise ValueError("No keys found in JWKS")
                
        except Exception as e:
            raise ValueError(f"Failed to fetch JWT public key: {str(e)}")
    
    @staticmethod
    def _jwk_to_pem(jwk: Dict[str, Any]) -> str:
        """
        Convert JWK to PEM format (simplified implementation)
        """
        # This is a placeholder - use proper JWK library in production
        # For now, assume the key is already in PEM format or handle specific cases
        if "x5c" in jwk and len(jwk["x5c"]) > 0:
            # X.509 certificate chain
            cert_der = jwk["x5c"][0]
            import base64
            cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_der}\n-----END CERTIFICATE-----"
            return cert_pem
        
        # For other JWK formats, implement proper conversion
        raise ValueError("JWK to PEM conversion not implemented for this key type")