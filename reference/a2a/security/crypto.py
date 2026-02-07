"""
Cryptographic primitives for A2A Protocol.

Implements:
- Ed25519 key generation, signing, verification
- JWS (JSON Web Signature) creation and verification
- SHA-256 hashing
- Secure nonce generation
- Base58 encoding (for DIDs)
- Base64url encoding

All implementations use standard, audited libraries.
No custom crypto.
"""

import hashlib
import base64
import json
import time
import secrets
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class CryptoError(Exception):
    """Cryptographic operation failed."""
    pass


def b64url_encode(data: bytes) -> str:
    """
    Base64url encode (RFC 4648 Section 5).
    
    Args:
        data: Raw bytes to encode
    
    Returns:
        Base64url string (no padding)
    """
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def b64url_decode(data: str) -> bytes:
    """
    Base64url decode (RFC 4648 Section 5).
    
    Args:
        data: Base64url string (with or without padding)
    
    Returns:
        Raw bytes
    
    Raises:
        CryptoError: If decoding fails
    """
    try:
        # Add padding as needed
        padding = '=' * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)
    except Exception as e:
        raise CryptoError(f"Base64url decode failed: {e}")


def base58_encode(data: bytes) -> str:
    """
    Base58 encode (Bitcoin-style, used for DIDs).
    
    Args:
        data: Raw bytes
    
    Returns:
        Base58 string
    """
    # Base58 alphabet (Bitcoin standard)
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    # Convert bytes to integer
    num = int.from_bytes(data, 'big')
    
    # Encode integer as base58
    encoded = []
    if num == 0:
        encoded = []
    else:
        while num > 0:
            num, remainder = divmod(num, 58)
            encoded.append(ALPHABET[remainder])
    
    # Add leading zeros (each zero byte becomes '1')
    leading_zeros = 0
    for byte in data:
        if byte == 0:
            leading_zeros += 1
        else:
            break
    
    result = ALPHABET[0] * leading_zeros + ''.join(reversed(encoded))
    
    # Handle all-zero case
    if not result:
        result = ALPHABET[0]
    
    return result


def base58_decode(encoded: str) -> bytes:
    """
    Base58 decode (Bitcoin-style).
    
    Args:
        encoded: Base58 string
    
    Returns:
        Raw bytes
    
    Raises:
        CryptoError: If decoding fails
    """
    try:
        ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        
        # Convert to integer
        num = 0
        for char in encoded:
            num = num * 58 + ALPHABET.index(char)
        
        # Convert integer to bytes (handle zero case)
        if num == 0:
            combined = b''
        else:
            combined = num.to_bytes((num.bit_length() + 7) // 8, 'big')
        
        # Add leading zero bytes
        leading_zeros = 0
        for char in encoded:
            if char == ALPHABET[0]:
                leading_zeros += 1
            else:
                break
        
        return b'\x00' * leading_zeros + combined
    except Exception as e:
        raise CryptoError(f"Base58 decode failed: {e}")


def sha256(data: bytes) -> str:
    """
    SHA-256 hash.
    
    Args:
        data: Input bytes
    
    Returns:
        Hex-encoded hash (64 chars)
    """
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    """
    SHA-256 hash (returns bytes).
    
    Args:
        data: Input bytes
    
    Returns:
        Raw hash bytes (32 bytes)
    """
    return hashlib.sha256(data).digest()


def generate_nonce(length: int = 32) -> str:
    """
    Generate cryptographically secure random nonce.
    
    Args:
        length: Nonce length in bytes
    
    Returns:
        Base64url-encoded nonce
    """
    random_bytes = secrets.token_bytes(length)
    return b64url_encode(random_bytes)


class KeyPair:
    """
    Ed25519 keypair for agent identity and signing.
    """
    
    def __init__(self, private_key: ed25519.Ed25519PrivateKey):
        """
        Initialize with private key.
        
        Args:
            private_key: ed25519.Ed25519PrivateKey instance
        """
        self.private_key = private_key
        self.public_key = private_key.public_key()
    
    @staticmethod
    def generate() -> "KeyPair":
        """
        Generate new Ed25519 keypair.
        
        Returns:
            KeyPair: New keypair
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        return KeyPair(private_key)
    
    @staticmethod
    def from_private_key_bytes(private_key_bytes: bytes) -> "KeyPair":
        """
        Load keypair from 32-byte Ed25519 private key.
        
        Args:
            private_key_bytes: 32-byte Ed25519 private key
        
        Returns:
            KeyPair: Loaded keypair
        
        Raises:
            CryptoError: If key is invalid
        """
        try:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            return KeyPair(private_key)
        except Exception as e:
            raise CryptoError(f"Invalid private key bytes: {e}")
    
    @staticmethod
    def from_private_key_base64(key_b64: str) -> "KeyPair":
        """
        Load keypair from base64url-encoded private key.
        
        Args:
            key_b64: Base64url-encoded private key
        
        Returns:
            KeyPair: Loaded keypair
        
        Raises:
            CryptoError: If key is invalid
        """
        try:
            private_key_bytes = b64url_decode(key_b64)
            return KeyPair.from_private_key_bytes(private_key_bytes)
        except Exception as e:
            raise CryptoError(f"Failed to load private key from base64: {e}")
    
    def private_key_bytes(self) -> bytes:
        """Get private key as raw bytes."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def private_key_base64(self) -> str:
        """Get private key as base64url string."""
        return b64url_encode(self.private_key_bytes())
    
    def public_key_bytes(self) -> bytes:
        """Get public key as raw bytes (32 bytes)."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def public_key_base64(self) -> str:
        """Get public key as base64url string."""
        return b64url_encode(self.public_key_bytes())
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign a message with the private key.
        
        Args:
            message: Message to sign
        
        Returns:
            64-byte EdDSA signature
        """
        return self.private_key.sign(message)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature with the public key.
        
        Args:
            message: Original message
            signature: Signature to verify
        
        Returns:
            True if signature is valid
        
        Raises:
            CryptoError: If verification fails
        """
        try:
            self.public_key.verify(signature, message)
            return True
        except Exception:
            return False
    
    def get_did_key(self) -> str:
        """
        Derive did:key from public key.
        
        Format: did:key:z<base58(multicodec_bytes)>
        where multicodec_bytes = [0x12, 0x20] + public_key
        (0x1220 = multicodec for Ed25519 public key)
        
        Returns:
            did:key string
        """
        # Multicodec prefix for Ed25519 public key
        multicodec_bytes = bytes([0x12, 0x20]) + self.public_key_bytes()
        
        # Base58 encode
        b58 = base58_encode(multicodec_bytes)
        
        return f"did:key:z{b58}"


class JWS:
    """
    JSON Web Signature (RFC 7515) implementation.
    
    Creates and verifies signatures over JSON payloads.
    """
    
    @staticmethod
    def create(
        payload: Dict[str, Any],
        keypair: KeyPair,
        kid: Optional[str] = None,
    ) -> str:
        """
        Create JWS (JSON Web Signature).
        
        Args:
            payload: JSON-serializable payload dict
            keypair: KeyPair to sign with
            kid: Key ID (optional, for key rotation)
        
        Returns:
            JWS string (header.payload.signature)
        """
        # Header
        header = {
            "alg": "EdDSA",
            "typ": "JWT",
        }
        if kid:
            header["kid"] = kid
        
        # Encode header and payload
        header_json = json.dumps(header, separators=(',', ':'), sort_keys=True)
        header_b64 = b64url_encode(header_json.encode('utf-8'))
        
        payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
        payload_b64 = b64url_encode(payload_json.encode('utf-8'))
        
        # Signing input
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        
        # Sign
        signature = keypair.sign(signing_input)
        signature_b64 = b64url_encode(signature)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    @staticmethod
    def verify(jws: str, public_key_bytes: bytes) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Verify JWS and extract payload.
        
        Args:
            jws: JWS string (header.payload.signature)
            public_key_bytes: Ed25519 public key (32 bytes)
        
        Returns:
            (is_valid, payload_dict)
            is_valid: True if signature is valid
            payload_dict: Parsed payload if valid, None if invalid
        """
        try:
            # Split JWS
            parts = jws.split('.')
            if len(parts) != 3:
                return False, None
            
            header_b64, payload_b64, signature_b64 = parts
            
            # Reconstruct signing input
            signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
            
            # Decode signature
            signature = b64url_decode(signature_b64)
            
            # Verify with public key
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            try:
                public_key.verify(signature, signing_input)
            except Exception:
                return False, None
            
            # Decode payload
            payload_json = b64url_decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            return True, payload
        
        except Exception:
            return False, None
    
    @staticmethod
    def decode_payload(jws: str) -> Optional[Dict[str, Any]]:
        """
        Decode payload from JWS (without verification).
        
        Args:
            jws: JWS string
        
        Returns:
            Payload dict if valid JWS format, None otherwise
        """
        try:
            parts = jws.split('.')
            if len(parts) != 3:
                return None
            
            payload_json = b64url_decode(parts[1]).decode('utf-8')
            return json.loads(payload_json)
        except Exception:
            return None
