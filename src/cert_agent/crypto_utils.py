"""
Cryptographic utilities for algorithm selection and key generation
"""
from typing import Literal, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class CryptoAlgorithm:
    """Manage cryptographic algorithm selection"""
    
    # Certificate Algorithms
    CERT_ALGORITHMS = {
        "ECDSA_P256": "ec",
        "RSA_2048": "rsa",
        "ED25519": "ed25519",
    }
    
    # Token Algorithms (mapping to JWT algorithms)
    TOKEN_ALGORITHMS = {
        "ES256": "ecdsa",      # ECDSA with SHA-256
        "RS256": "rsa",        # RSA with SHA-256
        "EdDSA": "ed25519",    # EdDSA
    }
    
    @staticmethod
    def get_certificate_algorithm_type(algorithm: str) -> str:
        """Get certificate algorithm type"""
        if algorithm not in CryptoAlgorithm.CERT_ALGORITHMS:
            raise ValueError(f"Unsupported certificate algorithm: {algorithm}")
        return CryptoAlgorithm.CERT_ALGORITHMS[algorithm]
    
    @staticmethod
    def get_token_algorithm_type(algorithm: str) -> str:
        """Get token algorithm type"""
        if algorithm not in CryptoAlgorithm.TOKEN_ALGORITHMS:
            raise ValueError(f"Unsupported token algorithm: {algorithm}")
        return CryptoAlgorithm.TOKEN_ALGORITHMS[algorithm]
    
    @staticmethod
    def generate_private_key(
        cert_algorithm: Literal["ECDSA_P256", "RSA_2048", "ED25519"],
        rsa_key_size: int = 2048
    ):
        """
        Generate private key based on algorithm
        
        Args:
            cert_algorithm: Certificate algorithm to use
            rsa_key_size: Key size for RSA (2048 or 4096)
            
        Returns:
            Private key object
        """
        if cert_algorithm == "ECDSA_P256":
            # ECDSA with P-256 curve
            return ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        elif cert_algorithm == "RSA_2048":
            # RSA with configurable key size
            if rsa_key_size not in [2048, 4096]:
                raise ValueError(f"RSA key size must be 2048 or 4096, got {rsa_key_size}")
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=rsa_key_size,
                backend=default_backend()
            )
        
        elif cert_algorithm == "ED25519":
            # Edwards Curve Digital Signature Algorithm
            return ed25519.Ed25519PrivateKey.generate()
        
        else:
            raise ValueError(f"Unsupported certificate algorithm: {cert_algorithm}")
    
    @staticmethod
    def get_hash_algorithm_by_name(
        hash_name: Literal["SHA256", "SHA512", "SHA3_256", "SHA3_512"]
    ):
        """
        Get hash algorithm instance by name
        
        Args:
            hash_name: Hash algorithm name (SHA256, SHA512, SHA3_256, SHA3_512)
            
        Returns:
            Hash algorithm instance
        """
        hash_map = {
            # SHA-2 family
            "SHA256": hashes.SHA256(),
            "SHA512": hashes.SHA512(),
            # SHA-3 family
            "SHA3_256": hashes.SHA3_256(),
            "SHA3_512": hashes.SHA3_512(),
        }
        
        if hash_name not in hash_map:
            raise ValueError(f"Unsupported hash algorithm: {hash_name}")
        
        return hash_map[hash_name]
    
    @staticmethod
    def get_hash_algorithm(
        cert_algorithm: Literal["ECDSA_P256", "RSA_2048", "ED25519"],
        hash_name: Optional[str] = None
    ):
        """
        Get hash algorithm for signing based on certificate algorithm
        
        Args:
            cert_algorithm: Certificate algorithm
            hash_name: Optional hash algorithm name (if None, uses default SHA256)
            
        Returns:
            Hash algorithm instance or None for Ed25519
        """
        if cert_algorithm == "ED25519":
            # Ed25519 doesn't use a separate hash algorithm
            return None
        
        # For ECDSA and RSA, use specified hash or default to SHA256
        if hash_name:
            return CryptoAlgorithm.get_hash_algorithm_by_name(hash_name)
        else:
            return hashes.SHA256()
    
    @staticmethod
    def get_token_signing_algorithm(
        token_algorithm: Literal["ES256", "RS256", "EdDSA"]
    ) -> str:
        """
        Get JWT signing algorithm name for PyJWT library
        
        Args:
            token_algorithm: Token algorithm
            
        Returns:
            JWT algorithm name
        """
        if token_algorithm == "ES256":
            return "ES256"
        elif token_algorithm == "RS256":
            return "RS256"
        elif token_algorithm == "EdDSA":
            return "EdDSA"
        else:
            raise ValueError(f"Unsupported token algorithm: {token_algorithm}")
    
    @staticmethod
    def validate_algorithm_compatibility(
        cert_algorithm: str,
        token_algorithm: str
    ) -> bool:
        """
        Validate that certificate and token algorithms are compatible
        
        Args:
            cert_algorithm: Certificate algorithm
            token_algorithm: Token algorithm
            
        Returns:
            True if compatible, False otherwise
            
        Note:
            - ECDSA_P256 works best with ES256
            - RSA_2048 works with RS256
            - ED25519 works with EdDSA
        """
        compatibility_map = {
            "ECDSA_P256": ["ES256"],
            "RSA_2048": ["RS256"],
            "ED25519": ["EdDSA"],
        }
        
        if cert_algorithm not in compatibility_map:
            return False
        
        return token_algorithm in compatibility_map[cert_algorithm]
