"""
Configuration management for Certificate Agent
"""
import os
from pathlib import Path
from typing import Optional, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class CertAgentSettings(BaseSettings):
    """Certificate Agent configuration settings"""
    
    # Application settings
    CERT_ADAPTER: str = Field(
        default="internal",
        description="Certificate adapter type: 'internal', 'aws', or 'letsencrypt'"
    )
    
    HOST: str = Field(
        default="0.0.0.0",
        description="Host to bind the server to"
    )
    
    PORT: int = Field(
        default=8080,
        description="Port to bind the server to"
    )
    
    LOG_LEVEL: str = Field(
        default="INFO",
        description="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL"
    )
    
    # Internal CA settings
    CA_CERT_PATH: str = Field(
        default="ca/ca.crt",
        description="Path to CA certificate file"
    )
    
    CA_KEY_PATH: str = Field(
        default="ca/ca.key",
        description="Path to CA private key file"
    )
    
    CERT_STORAGE_PATH: str = Field(
        default="certs/",
        description="Directory to store issued certificates"
    )
    
    # Cryptography algorithm settings
    CERTIFICATE_ALGORITHM: Literal["ECDSA_P256", "RSA_2048", "ED25519"] = Field(
        default="ECDSA_P256",
        description="Certificate generation algorithm: ECDSA_P256, RSA_2048, or ED25519"
    )
    
    TOKEN_ALGORITHM: Literal["ES256", "RS256", "EdDSA"] = Field(
        default="ES256",
        description="Token signing algorithm: ES256, RS256, or EdDSA"
    )
    
    HASH_ALGORITHM: Literal["SHA256", "SHA512", "SHA3_256", "SHA3_512"] = Field(
        default="SHA256",
        description="Hash algorithm for certificate signing: SHA256, SHA512, SHA3_256, or SHA3_512"
    )
    
    RSA_KEY_SIZE: int = Field(
        default=2048,
        description="RSA key size in bits (2048 or 4096), only used for RSA_2048"
    )
    
    CERTIFICATE_VALIDITY_DAYS: int = Field(
        default=90,
        description="Certificate validity period in days"
    )
    
    # AWS ACM settings (if using AWS adapter)
    AWS_REGION: Optional[str] = Field(
        default=None,
        description="AWS region for ACM"
    )
    
    AWS_ACCESS_KEY_ID: Optional[str] = Field(
        default=None,
        description="AWS access key ID"
    )
    
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(
        default=None,
        description="AWS secret access key"
    )
    
    # CORS settings
    CORS_ORIGINS: str = Field(
        default="*",
        description="Comma-separated list of allowed CORS origins"
    )
    
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Allow credentials in CORS requests"
    )
    
    model_config = SettingsConfigDict(
        env_prefix="CERT_AGENT_",
        env_file=os.path.join(Path(__file__).parent, ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Get CORS origins as a list"""
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]


# Global settings instance
_settings: Optional[CertAgentSettings] = None


def get_settings() -> CertAgentSettings:
    """Get or create settings instance (singleton pattern)"""
    global _settings
    if _settings is None:
        _settings = CertAgentSettings()
    return _settings


def reload_settings() -> CertAgentSettings:
    """Reload settings from environment"""
    global _settings
    _settings = CertAgentSettings()
    return _settings
