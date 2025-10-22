"""
Configuration settings for the proxy
"""
import os
from typing import List, Optional
from pydantic import BaseSettings, Field


class ProxySettings(BaseSettings):
    """Proxy configuration settings"""
    
    # Server settings
    host: str = Field(default="0.0.0.0", env="PROXY_HOST")
    port: int = Field(default=8443, env="PROXY_PORT")
    
    # TLS settings
    tls_cert_file: str = Field(default="certs/server.crt", env="TLS_CERT_FILE")
    tls_key_file: str = Field(default="certs/server.key", env="TLS_KEY_FILE")
    ca_cert_file: str = Field(default="certs/ca.crt", env="CA_CERT_FILE")
    require_client_cert: bool = Field(default=True, env="REQUIRE_CLIENT_CERT")
    
    # JWT settings
    jwt_algorithm: str = Field(default="RS256", env="JWT_ALGORITHM")
    jwt_issuer: str = Field(default="zero-trust-auth", env="JWT_ISSUER")
    jwt_audience: str = Field(default="api-gateway", env="JWT_AUDIENCE")
    jwt_public_key_url: str = Field(default="", env="JWT_PUBLIC_KEY_URL")
    
    # DPoP settings
    dpop_enabled: bool = Field(default=True, env="DPOP_ENABLED")
    dpop_max_age_seconds: int = Field(default=60, env="DPOP_MAX_AGE_SECONDS")
    
    # Cache settings
    cache_enabled: bool = Field(default=True, env="CACHE_ENABLED")
    redis_url: str = Field(default="redis://localhost:6379", env="REDIS_URL")
    cache_ttl_seconds: int = Field(default=300, env="CACHE_TTL_SECONDS")
    
    # Cert Agent settings
    cert_agent_url: str = Field(default="http://localhost:8080", env="CERT_AGENT_URL")
    cert_agent_timeout: int = Field(default=30, env="CERT_AGENT_TIMEOUT")
    
    # Backend settings
    backend_base_url: str = Field(default="http://localhost:3000", env="BACKEND_BASE_URL")
    backend_timeout: int = Field(default=30, env="BACKEND_TIMEOUT")
    
    # Security settings
    enable_ocsp_validation: bool = Field(default=True, env="ENABLE_OCSP_VALIDATION")
    enable_crl_validation: bool = Field(default=True, env="ENABLE_CRL_VALIDATION")
    trusted_ca_list: List[str] = Field(default=[], env="TRUSTED_CA_LIST")
    
    # Logging settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    enable_audit_log: bool = Field(default=True, env="ENABLE_AUDIT_LOG")
    audit_log_file: str = Field(default="logs/audit.log", env="AUDIT_LOG_FILE")
    
    # Monitoring settings
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    enable_tracing: bool = Field(default=True, env="ENABLE_TRACING")
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Global settings instance
settings = ProxySettings()