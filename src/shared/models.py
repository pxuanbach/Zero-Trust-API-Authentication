"""
Shared models for certificate management and authentication
"""
from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field
from enum import Enum


class CertificateStatus(str, Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    PENDING = "pending"


class CertificateInfo(BaseModel):
    """Certificate information model"""
    serial_number: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    fingerprint_sha256: str
    public_key: str
    status: CertificateStatus
    san_list: Optional[List[str]] = None


class TokenClaims(BaseModel):
    """JWT Token claims"""
    iss: str  # issuer
    aud: str  # audience
    exp: int  # expiration time
    iat: int  # issued at
    nbf: int  # not before
    sub: str  # subject
    cnf: Optional[Dict[str, str]] = None  # confirmation claim with x5t#S256


class DPoPClaims(BaseModel):
    """DPoP JWT claims"""
    htm: str  # HTTP method
    htu: str  # HTTP URI
    iat: int  # issued at
    jti: str  # JWT ID (nonce)
    jwk: Dict[str, Any]  # JSON Web Key


class AuthenticationResult(BaseModel):
    """Result of authentication process"""
    success: bool
    client_id: Optional[str] = None
    certificate_info: Optional[CertificateInfo] = None
    token_claims: Optional[TokenClaims] = None
    dpop_claims: Optional[DPoPClaims] = None
    error_message: Optional[str] = None
    security_context: Optional[Dict[str, Any]] = None


class CertificateRequest(BaseModel):
    """Certificate request model"""
    common_name: str
    organization: Optional[str] = None
    country: Optional[str] = None
    san_list: Optional[List[str]] = None
    key_size: int = Field(default=2048, ge=2048)
    validity_days: int = Field(default=365, ge=1, le=3650)


class CertificateResponse(BaseModel):
    """Certificate response model"""
    certificate_pem: str
    private_key_pem: str
    ca_chain_pem: Optional[str] = None
    serial_number: str
    fingerprint_sha256: str
    not_before: datetime
    not_after: datetime