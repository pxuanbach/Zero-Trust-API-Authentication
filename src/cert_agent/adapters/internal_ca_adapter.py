"""
Internal CA adapter for self-signed certificates
"""
import os
import tempfile
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .base_adapter import BaseCertificateAdapter
from ...shared.models import CertificateRequest, CertificateResponse, CertificateInfo, CertificateStatus


class InternalCAAdapter(BaseCertificateAdapter):
    """Internal CA adapter for self-signed certificates"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # CA configuration
        self.ca_cert_path = self.config.get("ca_cert_path", "ca/ca.crt")
        self.ca_key_path = self.config.get("ca_key_path", "ca/ca.key")
        self.cert_storage_path = self.config.get("cert_storage_path", "certs/")
        
        # In-memory certificate storage (for demo purposes)
        self.certificates: Dict[str, Dict[str, Any]] = {}
        
        # Ensure storage directory exists
        os.makedirs(self.cert_storage_path, exist_ok=True)
        
        # Initialize CA if it doesn't exist
        self._ensure_ca_exists()
    
    def _ensure_ca_exists(self):
        """Ensure CA certificate and key exist, create if necessary"""
        if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
            self._create_ca()
    
    def _create_ca(self):
        """Create a new CA certificate and private key"""
        # Generate CA private key
        ca_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Zero Trust Internal CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Zero Trust Root CA"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            ca_private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(ca_private_key, hashes.SHA256())
        
        # Save CA certificate and key
        os.makedirs(os.path.dirname(self.ca_cert_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.ca_key_path), exist_ok=True)
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(self.ca_key_path, "wb") as f:
            f.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    def _load_ca(self):
        """Load CA certificate and private key"""
        with open(self.ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        
        with open(self.ca_key_path, "rb") as f:
            ca_private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        return ca_cert, ca_private_key
    
    async def issue_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue a new certificate using internal CA"""
        try:
            # Load CA
            ca_cert, ca_private_key = self._load_ca()
            
            # Generate client private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=request.key_size
            )
            
            # Create certificate subject
            subject_components = [
                x509.NameAttribute(NameOID.COMMON_NAME, request.common_name)
            ]
            
            if request.organization:
                subject_components.append(
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, request.organization)
                )
            
            if request.country:
                subject_components.append(
                    x509.NameAttribute(NameOID.COUNTRY_NAME, request.country)
                )
            
            subject = x509.Name(subject_components)
            
            # Create certificate
            builder = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                ca_cert.subject
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.now(timezone.utc)
            ).not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=request.validity_days)
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
                critical=False,
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True,
            )
            
            # Add Subject Alternative Names
            if request.san_list:
                san_list = [x509.DNSName(san) for san in request.san_list]
                builder = builder.add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False
                )
            
            # Sign certificate
            cert = builder.sign(ca_private_key, hashes.SHA256())
            
            # Convert to PEM format
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            ca_chain_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
            
            # Calculate fingerprint
            import hashlib
            fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            
            # Store certificate information
            serial_number = str(cert.serial_number)
            self.certificates[serial_number] = {
                "certificate_pem": cert_pem,
                "private_key_pem": key_pem,
                "ca_chain_pem": ca_chain_pem,
                "serial_number": serial_number,
                "fingerprint_sha256": fingerprint.upper(),
                "not_before": cert.not_valid_before.replace(tzinfo=timezone.utc),
                "not_after": cert.not_valid_after.replace(tzinfo=timezone.utc),
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "status": CertificateStatus.VALID,
                "san_list": request.san_list or []
            }
            
            # Save certificate to file
            cert_file_path = os.path.join(self.cert_storage_path, f"{serial_number}.crt")
            key_file_path = os.path.join(self.cert_storage_path, f"{serial_number}.key")
            
            with open(cert_file_path, "w") as f:
                f.write(cert_pem)
            
            with open(key_file_path, "w") as f:
                f.write(key_pem)
            
            return CertificateResponse(
                certificate_pem=cert_pem,
                private_key_pem=key_pem,
                ca_chain_pem=ca_chain_pem,
                serial_number=serial_number,
                fingerprint_sha256=fingerprint.upper(),
                not_before=cert.not_valid_before.replace(tzinfo=timezone.utc),
                not_after=cert.not_valid_after.replace(tzinfo=timezone.utc)
            )
            
        except Exception as e:
            raise Exception(f"Internal CA certificate issuance failed: {str(e)}")
    
    async def get_certificate(self, identifier: str) -> Optional[CertificateInfo]:
        """Get certificate information by serial number"""
        cert_data = self.certificates.get(identifier)
        if not cert_data:
            return None
        
        return CertificateInfo(
            serial_number=cert_data["serial_number"],
            subject=cert_data["subject"],
            issuer=cert_data["issuer"],
            not_before=cert_data["not_before"],
            not_after=cert_data["not_after"],
            fingerprint_sha256=cert_data["fingerprint_sha256"],
            public_key="",  # Could extract from certificate if needed
            status=cert_data["status"],
            san_list=cert_data["san_list"]
        )
    
    async def revoke_certificate(self, identifier: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate"""
        if identifier not in self.certificates:
            return False
        
        # Mark certificate as revoked
        self.certificates[identifier]["status"] = CertificateStatus.REVOKED
        self.certificates[identifier]["revocation_reason"] = reason
        self.certificates[identifier]["revoked_at"] = datetime.now(timezone.utc)
        
        return True
    
    async def list_certificates(self, status_filter: Optional[CertificateStatus] = None) -> List[CertificateInfo]:
        """List certificates with optional status filter"""
        certificates = []
        
        for cert_data in self.certificates.values():
            if status_filter is None or cert_data["status"] == status_filter:
                cert_info = CertificateInfo(
                    serial_number=cert_data["serial_number"],
                    subject=cert_data["subject"],
                    issuer=cert_data["issuer"],
                    not_before=cert_data["not_before"],
                    not_after=cert_data["not_after"],
                    fingerprint_sha256=cert_data["fingerprint_sha256"],
                    public_key="",
                    status=cert_data["status"],
                    san_list=cert_data["san_list"]
                )
                certificates.append(cert_info)
        
        return certificates
    
    async def validate_certificate_chain(self, certificate_pem: str) -> bool:
        """Validate certificate chain against internal CA"""
        try:
            # Load CA certificate
            ca_cert, _ = self._load_ca()
            
            # Load certificate to validate
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            
            # Check if certificate was issued by our CA
            ca_public_key = ca_cert.public_key()
            
            try:
                # Verify certificate signature against CA
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    cert.signature_hash_algorithm
                )
                return True
            except Exception:
                return False
                
        except Exception:
            return False
    
    async def check_revocation_status(self, certificate_pem: str) -> CertificateStatus:
        """Check certificate revocation status"""
        try:
            # Extract serial number from certificate
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            serial_number = str(cert.serial_number)
            
            # Check if certificate exists and get its status
            cert_data = self.certificates.get(serial_number)
            if cert_data:
                return cert_data["status"]
            
            # Certificate not found in our records
            return CertificateStatus.VALID
            
        except Exception:
            return CertificateStatus.VALID