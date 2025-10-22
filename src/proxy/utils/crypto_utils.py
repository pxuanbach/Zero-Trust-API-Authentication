"""
Cryptographic utilities for the proxy
"""
import hashlib
import base64
import json
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import jwt
from datetime import datetime, timezone


def get_certificate_fingerprint(cert_pem: str) -> str:
    """
    Calculate SHA-256 fingerprint of certificate
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        return fingerprint.upper()
    except Exception as e:
        raise ValueError(f"Error calculating certificate fingerprint: {str(e)}")


def get_certificate_thumbprint_base64url(cert_pem: str) -> str:
    """
    Calculate base64url-encoded SHA-256 thumbprint for cnf claim
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        thumbprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).digest()
        return base64.urlsafe_b64encode(thumbprint).decode().rstrip('=')
    except Exception as e:
        raise ValueError(f"Error calculating certificate thumbprint: {str(e)}")


def extract_certificate_info(cert_pem: str) -> Dict[str, Any]:
    """
    Extract detailed information from X.509 certificate
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        
        # Extract Subject Alternative Names
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        return {
            "serial_number": str(cert.serial_number),
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before,
            "not_after": cert.not_valid_after,
            "fingerprint_sha256": get_certificate_fingerprint(cert_pem),
            "thumbprint_base64url": get_certificate_thumbprint_base64url(cert_pem),
            "san_list": san_list,
            "version": cert.version.name,
            "signature_algorithm": cert.signature_algorithm_oid._name
        }
    except Exception as e:
        raise ValueError(f"Error extracting certificate info: {str(e)}")


def validate_jwt_token(token: str, public_key: str, algorithm: str = "RS256", 
                      audience: str = None, issuer: str = None) -> Dict[str, Any]:
    """
    Validate and decode JWT token
    """
    try:
        # Decode and verify JWT
        payload = jwt.decode(
            token,
            public_key,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer,
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidAudienceError:
        raise ValueError("Invalid token audience")
    except jwt.InvalidIssuerError:
        raise ValueError("Invalid token issuer")
    except jwt.InvalidSignatureError:
        raise ValueError("Invalid token signature")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


def validate_dpop_proof(dpop_token: str, http_method: str, http_uri: str, 
                       access_token: Optional[str] = None) -> Dict[str, Any]:
    """
    Validate DPoP proof JWT
    """
    try:
        # Decode header to get JWK
        header = jwt.get_unverified_header(dpop_token)
        
        if "jwk" not in header:
            raise ValueError("DPoP token missing jwk in header")
        
        jwk = header["jwk"]
        
        # Convert JWK to public key (simplified for RSA)
        if jwk.get("kty") != "RSA":
            raise ValueError("Only RSA keys supported for DPoP")
        
        # Construct public key from JWK (this is simplified)
        # In production, use proper JWK library
        public_key = construct_rsa_public_key_from_jwk(jwk)
        
        # Verify DPoP token
        payload = jwt.decode(
            dpop_token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False}
        )
        
        # Validate required claims
        required_claims = ["htm", "htu", "iat", "jti"]
        for claim in required_claims:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")
        
        # Validate HTTP method and URI
        if payload["htm"] != http_method:
            raise ValueError("DPoP htm claim does not match request method")
        
        if payload["htu"] != http_uri:
            raise ValueError("DPoP htu claim does not match request URI")
        
        # Check token age (should be recent)
        token_age = datetime.now(timezone.utc).timestamp() - payload["iat"]
        if token_age > 300:  # 5 minutes
            raise ValueError("DPoP token too old")
        
        return payload
        
    except Exception as e:
        raise ValueError(f"DPoP validation failed: {str(e)}")


def construct_rsa_public_key_from_jwk(jwk: Dict[str, Any]) -> str:
    """
    Construct RSA public key from JWK (simplified implementation)
    In production, use proper JWK library like python-jwk
    """
    # This is a simplified implementation
    # In production, use libraries like python-jwk or cryptography's JWK support
    try:
        n = base64.urlsafe_b64decode(jwk["n"] + "==")
        e = base64.urlsafe_b64decode(jwk["e"] + "==")
        
        # Convert to integers
        n_int = int.from_bytes(n, byteorder='big')
        e_int = int.from_bytes(e, byteorder='big')
        
        # Create RSA public key
        public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key()
        
        # Convert to PEM format
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return pem.decode()
        
    except Exception as e:
        raise ValueError(f"Error constructing public key from JWK: {str(e)}")


def verify_certificate_binding(cert_pem: str, cnf_claim: Dict[str, str]) -> bool:
    """
    Verify certificate binding with JWT cnf claim
    """
    try:
        if "x5t#S256" not in cnf_claim:
            return False
        
        expected_thumbprint = cnf_claim["x5t#S256"]
        actual_thumbprint = get_certificate_thumbprint_base64url(cert_pem)
        
        return expected_thumbprint == actual_thumbprint
        
    except Exception:
        return False