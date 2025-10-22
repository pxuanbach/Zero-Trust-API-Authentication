"""
AWS Certificate Manager adapter
"""
import boto3
import base64
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from botocore.exceptions import ClientError

from .base_adapter import BaseCertificateAdapter
from ...shared.models import CertificateRequest, CertificateResponse, CertificateInfo, CertificateStatus


class AwsCertificateAdapter(BaseCertificateAdapter):
    """AWS Certificate Manager adapter"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # AWS configuration
        self.region = self.config.get("aws_region", "us-east-1")
        self.profile = self.config.get("aws_profile")
        
        # Initialize AWS clients
        session = boto3.Session(profile_name=self.profile)
        self.acm_client = session.client("acm", region_name=self.region)
        self.private_ca_client = session.client("acm-pca", region_name=self.region)
        
        # Private CA ARN (if using AWS Private CA)
        self.private_ca_arn = self.config.get("private_ca_arn")
        
    async def issue_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue a new certificate using AWS ACM or Private CA"""
        try:
            if self.private_ca_arn:
                # Use AWS Private CA
                return await self._issue_private_ca_certificate(request)
            else:
                # Use AWS ACM (public certificates)
                return await self._issue_acm_certificate(request)
                
        except Exception as e:
            raise Exception(f"AWS certificate issuance failed: {str(e)}")
    
    async def _issue_acm_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue certificate using AWS ACM (public certificates)"""
        try:
            # Prepare domain validation method
            domain_validation_options = []
            
            # Add primary domain
            domain_validation_options.append({
                'DomainName': request.common_name,
                'ValidationDomain': request.common_name
            })
            
            # Add SANs
            if request.san_list:
                for san in request.san_list:
                    domain_validation_options.append({
                        'DomainName': san,
                        'ValidationDomain': san
                    })
            
            # Request certificate
            response = self.acm_client.request_certificate(
                DomainName=request.common_name,
                SubjectAlternativeNames=request.san_list or [],
                ValidationMethod='DNS',  # or 'EMAIL'
                DomainValidationOptions=domain_validation_options
            )
            
            certificate_arn = response['CertificateArn']
            
            # Wait for certificate to be issued (this is simplified)
            # In production, implement proper polling or webhook handling
            
            # For now, return a placeholder response
            # Note: ACM doesn't provide access to private keys for public certificates
            return CertificateResponse(
                certificate_pem="",  # ACM doesn't expose the certificate PEM for public certs
                private_key_pem="",  # ACM doesn't expose private keys
                ca_chain_pem="",
                serial_number=certificate_arn.split('/')[-1],
                fingerprint_sha256="",
                not_before=datetime.now(timezone.utc),
                not_after=datetime.now(timezone.utc)
            )
            
        except ClientError as e:
            raise Exception(f"ACM certificate request failed: {str(e)}")
    
    async def _issue_private_ca_certificate(self, request: CertificateRequest) -> CertificateResponse:
        """Issue certificate using AWS Private CA"""
        try:
            # Generate CSR (Certificate Signing Request)
            csr = await self._generate_csr(request)
            
            # Issue certificate
            response = self.private_ca_client.issue_certificate(
                CertificateAuthorityArn=self.private_ca_arn,
                Csr=csr,
                SigningAlgorithm='SHA256WITHRSA',
                Validity={
                    'Value': request.validity_days,
                    'Type': 'DAYS'
                }
            )
            
            certificate_arn = response['CertificateArn']
            
            # Get the issued certificate
            cert_response = self.private_ca_client.get_certificate(
                CertificateAuthorityArn=self.private_ca_arn,
                CertificateArn=certificate_arn
            )
            
            certificate_pem = cert_response['Certificate']
            ca_chain_pem = cert_response.get('CertificateChain', '')
            
            # Extract certificate information
            cert_info = await self._parse_certificate_pem(certificate_pem)
            
            return CertificateResponse(
                certificate_pem=certificate_pem,
                private_key_pem="",  # Private key was generated separately
                ca_chain_pem=ca_chain_pem,
                serial_number=cert_info['serial_number'],
                fingerprint_sha256=cert_info['fingerprint_sha256'],
                not_before=cert_info['not_before'],
                not_after=cert_info['not_after']
            )
            
        except ClientError as e:
            raise Exception(f"Private CA certificate issuance failed: {str(e)}")
    
    async def get_certificate(self, identifier: str) -> Optional[CertificateInfo]:
        """Get certificate information by ARN"""
        try:
            # Try ACM first
            try:
                response = self.acm_client.describe_certificate(CertificateArn=identifier)
                cert = response['Certificate']
                
                return CertificateInfo(
                    serial_number=cert.get('Serial', ''),
                    subject=cert.get('Subject', ''),
                    issuer=cert.get('Issuer', ''),
                    not_before=cert.get('NotBefore', datetime.now(timezone.utc)),
                    not_after=cert.get('NotAfter', datetime.now(timezone.utc)),
                    fingerprint_sha256="",  # ACM doesn't provide this
                    public_key="",
                    status=self._map_acm_status(cert.get('Status', 'UNKNOWN')),
                    san_list=cert.get('SubjectAlternativeNames', [])
                )
                
            except ClientError:
                # Try Private CA
                if self.private_ca_arn:
                    cert_response = self.private_ca_client.get_certificate(
                        CertificateAuthorityArn=self.private_ca_arn,
                        CertificateArn=identifier
                    )
                    
                    certificate_pem = cert_response['Certificate']
                    cert_info = await self._parse_certificate_pem(certificate_pem)
                    
                    return CertificateInfo(
                        serial_number=cert_info['serial_number'],
                        subject=cert_info['subject'],
                        issuer=cert_info['issuer'],
                        not_before=cert_info['not_before'],
                        not_after=cert_info['not_after'],
                        fingerprint_sha256=cert_info['fingerprint_sha256'],
                        public_key=cert_info.get('public_key', ''),
                        status=CertificateStatus.VALID,
                        san_list=cert_info.get('san_list', [])
                    )
            
            return None
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            raise Exception(f"Get certificate failed: {str(e)}")
    
    async def revoke_certificate(self, identifier: str, reason: str = "unspecified") -> bool:
        """Revoke a certificate"""
        try:
            # ACM doesn't support certificate revocation for public certificates
            # For Private CA certificates
            if self.private_ca_arn:
                self.private_ca_client.revoke_certificate(
                    CertificateAuthorityArn=self.private_ca_arn,
                    CertificateSerial=identifier,  # Use serial number for Private CA
                    RevocationReason=self._map_revocation_reason(reason)
                )
                return True
            else:
                # For ACM public certificates, just delete them
                self.acm_client.delete_certificate(CertificateArn=identifier)
                return True
                
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return False
            raise Exception(f"Certificate revocation failed: {str(e)}")
    
    async def list_certificates(self, status_filter: Optional[CertificateStatus] = None) -> List[CertificateInfo]:
        """List certificates"""
        certificates = []
        
        try:
            # List ACM certificates
            acm_status_filter = None
            if status_filter:
                acm_status_filter = [self._map_status_to_acm(status_filter)]
            
            paginator = self.acm_client.get_paginator('list_certificates')
            for page in paginator.paginate(CertificateStatuses=acm_status_filter or ['ISSUED', 'PENDING_VALIDATION']):
                for cert_summary in page['CertificateSummaryList']:
                    cert_info = await self.get_certificate(cert_summary['CertificateArn'])
                    if cert_info:
                        certificates.append(cert_info)
            
            # TODO: Add Private CA certificate listing
            
        except ClientError as e:
            raise Exception(f"List certificates failed: {str(e)}")
        
        return certificates
    
    async def validate_certificate_chain(self, certificate_pem: str) -> bool:
        """Validate certificate chain"""
        # AWS ACM automatically validates certificate chains
        # For now, implement basic validation
        try:
            from cryptography import x509
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            
            # Basic validation - check if certificate is well-formed
            return cert is not None
            
        except Exception:
            return False
    
    async def check_revocation_status(self, certificate_pem: str) -> CertificateStatus:
        """Check certificate revocation status"""
        # AWS ACM doesn't provide direct CRL/OCSP checking
        # This would need to be implemented using the certificate's CRL/OCSP endpoints
        return CertificateStatus.VALID
    
    def _map_acm_status(self, acm_status: str) -> CertificateStatus:
        """Map ACM status to CertificateStatus"""
        status_mapping = {
            'ISSUED': CertificateStatus.VALID,
            'PENDING_VALIDATION': CertificateStatus.PENDING,
            'FAILED': CertificateStatus.REVOKED,
            'INACTIVE': CertificateStatus.REVOKED,
            'EXPIRED': CertificateStatus.EXPIRED,
            'VALIDATION_TIMED_OUT': CertificateStatus.REVOKED
        }
        return status_mapping.get(acm_status, CertificateStatus.VALID)
    
    def _map_status_to_acm(self, status: CertificateStatus) -> str:
        """Map CertificateStatus to ACM status"""
        status_mapping = {
            CertificateStatus.VALID: 'ISSUED',
            CertificateStatus.PENDING: 'PENDING_VALIDATION',
            CertificateStatus.REVOKED: 'FAILED',
            CertificateStatus.EXPIRED: 'EXPIRED'
        }
        return status_mapping.get(status, 'ISSUED')
    
    def _map_revocation_reason(self, reason: str) -> str:
        """Map revocation reason to AWS format"""
        reason_mapping = {
            'unspecified': 'UNSPECIFIED',
            'key_compromise': 'KEY_COMPROMISE',
            'ca_compromise': 'CERTIFICATE_AUTHORITY_COMPROMISE',
            'affiliation_changed': 'AFFILIATION_CHANGED',
            'superseded': 'SUPERSEDED',
            'cessation_of_operation': 'CESSATION_OF_OPERATION',
            'privilege_withdrawn': 'PRIVILEGE_WITHDRAWN',
            'aa_compromise': 'A_A_COMPROMISE'
        }
        return reason_mapping.get(reason.lower(), 'UNSPECIFIED')
    
    async def _generate_csr(self, request: CertificateRequest) -> str:
        """Generate Certificate Signing Request"""
        # This is a simplified implementation
        # In production, use proper CSR generation with cryptography library
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=request.key_size
        )
        
        # Create CSR
        builder = x509.CertificateSigningRequestBuilder()
        
        # Add subject
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
        
        builder = builder.subject_name(x509.Name(subject_components))
        
        # Add SANs
        if request.san_list:
            san_list = [x509.DNSName(san) for san in request.san_list]
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
        
        # Sign CSR
        csr = builder.sign(private_key, hashes.SHA256())
        
        # Return CSR in PEM format
        return csr.public_bytes(serialization.Encoding.PEM).decode()
    
    async def _parse_certificate_pem(self, certificate_pem: str) -> Dict[str, Any]:
        """Parse certificate PEM and extract information"""
        from cryptography import x509
        import hashlib
        
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        
        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        
        # Extract SANs
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        return {
            'serial_number': str(cert.serial_number),
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'not_before': cert.not_valid_before.replace(tzinfo=timezone.utc),
            'not_after': cert.not_valid_after.replace(tzinfo=timezone.utc),
            'fingerprint_sha256': fingerprint.upper(),
            'san_list': san_list
        }