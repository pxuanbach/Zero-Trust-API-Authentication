"""
Main Certificate Agent application
"""
import logging
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any, AsyncGenerator
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from .adapters.aws_adapter import AwsCertificateAdapter
from .adapters.internal_ca_adapter import InternalCAAdapter
from .adapters.base_adapter import CertificateAdapterFactory
from ..shared.models import CertificateRequest, CertificateResponse, CertificateInfo, CertificateStatus
from ..shared.interfaces import ICertificateProvider


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CertificateAgent:
    """Certificate Agent for managing certificates"""
    
    def __init__(self, adapter_type: str = "aws"):
        self.cert_provider: Optional[ICertificateProvider] = None
        self.adapter_type = adapter_type
        
        self.app = FastAPI(
            title="Certificate Agent",
            description="Certificate management service with multiple providers",
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
        logger.info(f"Starting Certificate Agent with {self.adapter_type} adapter...")
        
        # Initialize certificate provider
        self.cert_provider = CertificateAdapterFactory.create_adapter(self.adapter_type)
        
        logger.info("Certificate Agent started successfully")
    
    async def shutdown(self):
        """Application shutdown handler"""
        logger.info("Shutting down Certificate Agent...")
        # Cleanup if needed
        logger.info("Certificate Agent shut down successfully")
    
    def _setup_middleware(self):
        """Setup FastAPI middleware"""
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
            return {
                "status": "healthy", 
                "service": "certificate-agent",
                "adapter": self.adapter_type
            }
        
        @self.app.post("/certificates/issue", response_model=CertificateResponse)
        async def issue_certificate(request: CertificateRequest):
            """Issue a new certificate"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                logger.info(f"Issuing certificate for CN: {request.common_name}")
                response = await self.cert_provider.issue_certificate(request)
                logger.info(f"Certificate issued successfully: {response.serial_number}")
                return response
                
            except Exception as e:
                logger.error(f"Certificate issuance failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Certificate issuance failed: {str(e)}"
                )
        
        @self.app.get("/certificates/{identifier}", response_model=CertificateInfo)
        async def get_certificate(identifier: str):
            """Get certificate information by identifier"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                cert_info = await self.cert_provider.get_certificate(identifier)
                if not cert_info:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Certificate not found"
                    )
                
                return cert_info
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Get certificate failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Get certificate failed: {str(e)}"
                )
        
        @self.app.post("/certificates/{identifier}/revoke")
        async def revoke_certificate(identifier: str, reason: str = "unspecified"):
            """Revoke a certificate"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                logger.info(f"Revoking certificate: {identifier}, reason: {reason}")
                success = await self.cert_provider.revoke_certificate(identifier, reason)
                
                if not success:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Certificate revocation failed"
                    )
                
                logger.info(f"Certificate revoked successfully: {identifier}")
                return {"success": True, "message": "Certificate revoked successfully"}
                
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Certificate revocation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Certificate revocation failed: {str(e)}"
                )
        
        @self.app.get("/certificates", response_model=List[CertificateInfo])
        async def list_certificates(status_filter: Optional[CertificateStatus] = None):
            """List certificates with optional status filter"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                certificates = await self.cert_provider.list_certificates(status_filter)
                return certificates
                
            except Exception as e:
                logger.error(f"List certificates failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"List certificates failed: {str(e)}"
                )
        
        @self.app.post("/certificates/validate-chain")
        async def validate_certificate_chain(certificate_pem: str):
            """Validate certificate chain"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                is_valid = await self.cert_provider.validate_certificate_chain(certificate_pem)
                return {"valid": is_valid}
                
            except Exception as e:
                logger.error(f"Certificate chain validation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Certificate chain validation failed: {str(e)}"
                )
        
        @self.app.post("/certificates/check-revocation")
        async def check_revocation_status(certificate_pem: str):
            """Check certificate revocation status"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                status_result = await self.cert_provider.check_revocation_status(certificate_pem)
                return {"status": status_result.value}
                
            except Exception as e:
                logger.error(f"Certificate revocation check failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Certificate revocation check failed: {str(e)}"
                )
        
        @self.app.post("/certificates/rotate")
        async def rotate_certificate(old_identifier: str, request: CertificateRequest):
            """Rotate certificate (revoke old, issue new)"""
            try:
                if not self.cert_provider:
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Certificate provider not initialized"
                    )
                
                logger.info(f"Rotating certificate: {old_identifier}")
                
                # Issue new certificate first
                new_cert = await self.cert_provider.issue_certificate(request)
                
                # Revoke old certificate
                try:
                    await self.cert_provider.revoke_certificate(old_identifier, "superseded")
                except Exception as e:
                    logger.warning(f"Failed to revoke old certificate {old_identifier}: {str(e)}")
                
                logger.info(f"Certificate rotated successfully: {old_identifier} -> {new_cert.serial_number}")
                return new_cert
                
            except Exception as e:
                logger.error(f"Certificate rotation failed: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Certificate rotation failed: {str(e)}"
                )


# Create certificate agent instance
cert_agent = CertificateAgent()
app = cert_agent.app


def run_cert_agent(adapter_type: str = "aws", host: str = "0.0.0.0", port: int = 8080):
    """Run the certificate agent server"""
    global cert_agent
    cert_agent = CertificateAgent(adapter_type=adapter_type)
    
    uvicorn.run(
        "src.cert_agent.main:app",
        host=host,
        port=port,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    import os
    adapter_type = os.getenv("CERT_ADAPTER", "aws")
    run_cert_agent(adapter_type=adapter_type)