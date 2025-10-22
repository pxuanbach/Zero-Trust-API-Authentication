"""
Main proxy application with mTLS + Token-Based Signature authentication
"""
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional, AsyncGenerator
from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import httpx
import uvicorn

from .config.settings import settings
from .middleware.mtls import MTLSMiddleware
from .middleware.token import TokenMiddleware, TokenValidator
from .middleware.dpop import DPoPMiddleware
from .cache.redis_client import RedisCache, MemoryCache, ICacheProvider
from ..shared.models import AuthenticationResult


# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ZeroTrustProxy:
    """Zero Trust API Authentication Proxy"""
    
    def __init__(self):
        # Initialize cache provider
        self.cache_provider: Optional[ICacheProvider] = None
        
        # Initialize middleware components
        self.mtls_middleware: Optional[MTLSMiddleware] = None
        self.token_middleware: Optional[TokenMiddleware] = None
        self.dpop_middleware: Optional[DPoPMiddleware] = None
        
        # HTTP client for backend communication
        self.http_client: Optional[httpx.AsyncClient] = None
        
        # Create FastAPI app with lifespan
        self.app = FastAPI(
            title="Zero Trust API Authentication Proxy",
            description="Proxy with mTLS + Token-Based Signature authentication",
            version="1.0.0",
            lifespan=self.lifespan
        )
        
        self._setup_middleware()
        self._setup_routes()
    
    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncGenerator[None, None]:
        """Lifespan event handler for startup and shutdown"""
        # Startup
        await self.startup()
        yield
        # Shutdown
        await self.shutdown()
    
    async def startup(self):
        """Application startup handler"""
        logger.info("Starting Zero Trust Proxy...")
        
        # Initialize cache provider
        if settings.cache_enabled:
            try:
                self.cache_provider = RedisCache(settings.redis_url)
                await self.cache_provider.connect()
                logger.info("Connected to Redis cache")
            except Exception as e:
                logger.warning(f"Failed to connect to Redis, using memory cache: {str(e)}")
                self.cache_provider = MemoryCache()
        else:
            self.cache_provider = MemoryCache()
        
        # Initialize middleware
        self.mtls_middleware = MTLSMiddleware(
            cache_provider=self.cache_provider,
            cache_ttl=settings.cache_ttl_seconds
        )
        
        # Get JWT public key
        jwt_public_key = await self._get_jwt_public_key()
        
        self.token_middleware = TokenMiddleware(
            jwt_public_key=jwt_public_key,
            jwt_algorithm=settings.jwt_algorithm,
            jwt_audience=settings.jwt_audience,
            jwt_issuer=settings.jwt_issuer,
            cache_provider=self.cache_provider,
            cache_ttl=settings.cache_ttl_seconds
        )
        
        if settings.dpop_enabled:
            self.dpop_middleware = DPoPMiddleware(
                cache_provider=self.cache_provider,
                max_age_seconds=settings.dpop_max_age_seconds,
                cache_ttl=settings.cache_ttl_seconds
            )
        
        # Initialize HTTP client for backend communication
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.backend_timeout),
            verify=True
        )
        
        logger.info("Zero Trust Proxy started successfully")
    
    async def shutdown(self):
        """Application shutdown handler"""
        logger.info("Shutting down Zero Trust Proxy...")
        
        if self.cache_provider:
            if hasattr(self.cache_provider, 'disconnect'):
                await self.cache_provider.disconnect()
        
        if self.http_client:
            await self.http_client.aclose()
        
        logger.info("Zero Trust Proxy shut down successfully")
    
    def _setup_middleware(self):
        """Setup FastAPI middleware"""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    
    def _setup_routes(self):
        """Setup application routes"""
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {"status": "healthy", "service": "zero-trust-proxy"}
        
        @self.app.get("/auth/status")
        async def auth_status(auth_result: AuthenticationResult = Depends(self.authenticate_request)):
            """Get authentication status"""
            return {
                "authenticated": auth_result.success,
                "client_id": auth_result.client_id,
                "security_context": auth_result.security_context
            }
        
        # Catch-all route for proxying requests
        @self.app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        async def proxy_request(
            request: Request, 
            path: str,
            auth_result: AuthenticationResult = Depends(self.authenticate_request)
        ):
            """Proxy authenticated requests to backend"""
            return await self._forward_to_backend(request, path, auth_result)
    
    async def authenticate_request(self, request: Request) -> AuthenticationResult:
        """
        Complete authentication flow: mTLS + JWT + DPoP
        """
        try:
            # Step 1: mTLS authentication
            logger.debug("Starting mTLS authentication")
            cert_result = await self.mtls_middleware.authenticate(request)
            
            # Step 2: JWT token authentication
            logger.debug("Starting JWT token authentication")
            token_result = await self.token_middleware.authenticate(request, cert_result)
            
            # Step 3: DPoP proof authentication (if enabled)
            dpop_result = None
            if settings.dpop_enabled and self.dpop_middleware:
                logger.debug("Starting DPoP proof authentication")
                dpop_result = await self.dpop_middleware.authenticate(request, cert_result, token_result)
            
            # Combine authentication results
            auth_result = AuthenticationResult(
                success=True,
                client_id=cert_result.get("client_id"),
                certificate_info=cert_result.get("certificate_info"),
                token_claims=token_result.get("token_claims"),
                dpop_claims=dpop_result.get("dpop_claims") if dpop_result else None,
                security_context={
                    "cert_fingerprint": cert_result.get("fingerprint"),
                    "token_subject": token_result.get("token_subject"),
                    "token_audience": token_result.get("token_audience"),
                    "authenticated_at": int(asyncio.get_event_loop().time()),
                    "dpop_enabled": settings.dpop_enabled,
                    "dpop_jti": dpop_result.get("dpop_jti") if dpop_result else None
                }
            )
            
            # Log successful authentication
            logger.info(f"Authentication successful for client: {auth_result.client_id}")
            
            return auth_result
            
        except HTTPException:
            # Re-raise HTTP exceptions (authentication failures)
            raise
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication system error"
            )
    
    async def _forward_to_backend(self, request: Request, path: str, 
                                auth_result: AuthenticationResult) -> JSONResponse:
        """
        Forward authenticated request to backend service
        """
        try:
            # Construct backend URL
            backend_url = f"{settings.backend_base_url.rstrip('/')}/{path.lstrip('/')}"
            
            # Prepare headers for backend request
            headers = dict(request.headers)
            
            # Add security context headers
            headers["X-Client-Id"] = auth_result.client_id or ""
            headers["X-Cert-Fingerprint"] = auth_result.security_context.get("cert_fingerprint", "")
            headers["X-Token-Subject"] = auth_result.security_context.get("token_subject", "")
            headers["X-Authenticated-At"] = str(auth_result.security_context.get("authenticated_at", ""))
            
            if auth_result.dpop_claims:
                headers["X-DPoP-JTI"] = auth_result.security_context.get("dpop_jti", "")
            
            # Get request body
            body = await request.body()
            
            # Forward request to backend
            response = await self.http_client.request(
                method=request.method,
                url=backend_url,
                headers=headers,
                content=body,
                params=dict(request.query_params)
            )
            
            # Return backend response
            return JSONResponse(
                content=response.json() if response.headers.get("content-type", "").startswith("application/json") else {"data": response.text},
                status_code=response.status_code,
                headers=dict(response.headers)
            )
            
        except httpx.RequestError as e:
            logger.error(f"Backend request error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Backend service unavailable"
            )
        except Exception as e:
            logger.error(f"Request forwarding error: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Request forwarding error"
            )
    
    async def _get_jwt_public_key(self) -> str:
        """
        Get JWT public key from configuration or URL
        """
        if settings.jwt_public_key_url:
            try:
                return await TokenValidator.get_jwt_public_key_from_url(settings.jwt_public_key_url)
            except Exception as e:
                logger.error(f"Failed to fetch JWT public key from URL: {str(e)}")
                raise
        else:
            # For testing, use a dummy public key
            # In production, load from file or configuration
            return """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf02VDA+XyGHI1Vc6VqX+0/D6bKZ6U9w8aEGYs2B
1P+CsKdQW7MJ9I6z3w1B8/P+CYUoH6PBQF5LyTq0ZH3KWqD7XoWz9o7TQNL+1d2w
1q6YKE+Z7rS5qVzI8yJ8qZW4RxQiYRy2I8FQI5dJWMQi4/kJzN4UlB/9f2D8b7A
-----END PUBLIC KEY-----"""


# Create proxy instance
proxy = ZeroTrustProxy()
app = proxy.app


def run_proxy():
    """Run the proxy server"""
    uvicorn.run(
        "src.proxy.main:app",
        host=settings.host,
        port=settings.port,
        ssl_keyfile=settings.tls_key_file,
        ssl_certfile=settings.tls_cert_file,
        ssl_ca_certs=settings.ca_cert_file if settings.require_client_cert else None,
        ssl_cert_reqs=2 if settings.require_client_cert else 0,  # ssl.CERT_REQUIRED
        reload=False,
        log_level=settings.log_level.lower()
    )


if __name__ == "__main__":
    run_proxy()