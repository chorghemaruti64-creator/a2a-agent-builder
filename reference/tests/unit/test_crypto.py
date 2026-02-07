"""
Unit tests for cryptographic primitives.

Tests:
- Ed25519 key generation and signing
- JWS creation and verification
- Base58/Base64url encoding
- Nonce generation
- Hash functions
"""

import pytest
import json
from a2a.security.crypto import (
    KeyPair,
    JWS,
    sha256,
    sha256_bytes,
    generate_nonce,
    b64url_encode,
    b64url_decode,
    base58_encode,
    base58_decode,
    CryptoError,
)


class TestKeyPair:
    """Test Ed25519 keypair operations."""
    
    def test_generate_keypair(self):
        """Generate new keypair."""
        kp = KeyPair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None
        assert len(kp.public_key_bytes()) == 32
        assert len(kp.private_key_bytes()) == 32
    
    def test_keypair_deterministic(self):
        """Keypair from same private key is deterministic."""
        kp1 = KeyPair.generate()
        private_bytes = kp1.private_key_bytes()
        
        kp2 = KeyPair.from_private_key_bytes(private_bytes)
        assert kp1.public_key_bytes() == kp2.public_key_bytes()
    
    def test_keypair_sign_verify(self):
        """Sign and verify message."""
        kp = KeyPair.generate()
        message = b"test message"
        
        signature = kp.sign(message)
        assert len(signature) == 64  # Ed25519 signature is 64 bytes
        
        assert kp.verify(message, signature)
    
    def test_keypair_verify_fails_on_tampered_message(self):
        """Signature verification fails on tampered message."""
        kp = KeyPair.generate()
        message = b"test message"
        
        signature = kp.sign(message)
        tampered = b"tampered message"
        
        assert not kp.verify(tampered, signature)
    
    def test_keypair_verify_fails_on_tampered_signature(self):
        """Signature verification fails on tampered signature."""
        kp = KeyPair.generate()
        message = b"test message"
        
        signature = kp.sign(message)
        tampered_sig = bytes([(signature[0] + 1) % 256]) + signature[1:]
        
        assert not kp.verify(message, tampered_sig)
    
    def test_keypair_base64_serialization(self):
        """Serialize and deserialize keypair to/from base64."""
        kp1 = KeyPair.generate()
        
        # Serialize
        private_b64 = kp1.private_key_base64()
        assert isinstance(private_b64, str)
        
        # Deserialize
        kp2 = KeyPair.from_private_key_base64(private_b64)
        assert kp1.public_key_bytes() == kp2.public_key_bytes()
    
    def test_keypair_invalid_private_key(self):
        """Loading invalid private key raises error."""
        with pytest.raises(CryptoError):
            KeyPair.from_private_key_bytes(b"too short")
    
    def test_keypair_get_did_key(self):
        """Generate did:key from public key."""
        kp = KeyPair.generate()
        did = kp.get_did_key()
        
        assert did.startswith("did:key:z")
        assert len(did) > 10


class TestJWS:
    """Test JSON Web Signature operations."""
    
    def test_jws_create_and_verify(self):
        """Create JWS and verify signature."""
        kp = KeyPair.generate()
        payload = {"test": "data", "number": 123}
        
        jws = JWS.create(payload, kp)
        assert jws.count('.') == 2  # Three parts
        
        # Verify
        valid, decoded_payload = JWS.verify(jws, kp.public_key_bytes())
        assert valid
        assert decoded_payload == payload
    
    def test_jws_verify_fails_with_wrong_key(self):
        """JWS verification fails with different key."""
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        
        payload = {"test": "data"}
        jws = JWS.create(payload, kp1)
        
        # Verify with wrong key
        valid, _ = JWS.verify(jws, kp2.public_key_bytes())
        assert not valid
    
    def test_jws_verify_fails_on_tampered_jws(self):
        """JWS verification fails if JWS is tampered."""
        kp = KeyPair.generate()
        payload = {"test": "data"}
        
        jws = JWS.create(payload, kp)
        
        # Tamper with payload
        parts = jws.split('.')
        tampered = f"{parts[0]}.AAAA.{parts[2]}"
        
        valid, _ = JWS.verify(tampered, kp.public_key_bytes())
        assert not valid
    
    def test_jws_with_kid(self):
        """JWS with key ID."""
        kp = KeyPair.generate()
        payload = {"data": "value"}
        
        jws = JWS.create(payload, kp, kid="sig-2024-01")
        
        valid, decoded = JWS.verify(jws, kp.public_key_bytes())
        assert valid
        assert decoded == payload
    
    def test_jws_decode_payload_without_verification(self):
        """Decode payload from JWS without verification."""
        kp = KeyPair.generate()
        payload = {"test": "data"}
        
        jws = JWS.create(payload, kp)
        decoded = JWS.decode_payload(jws)
        
        assert decoded == payload
    
    def test_jws_decode_payload_from_invalid_jws(self):
        """Decoding payload from invalid JWS returns None."""
        assert JWS.decode_payload("invalid") is None
        assert JWS.decode_payload("a.b") is None
        assert JWS.decode_payload("a.b.c.d") is None
    
    def test_jws_payload_canonicalization(self):
        """JWS uses canonical JSON (sorted keys)."""
        kp = KeyPair.generate()
        
        # Create payload with different key order
        payload1 = {"z": 1, "a": 2}
        payload2 = {"a": 2, "z": 1}
        
        jws1 = JWS.create(payload1, kp)
        jws2 = JWS.create(payload2, kp)
        
        # Should produce identical JWS (same canonical form)
        assert jws1 == jws2


class TestEncoding:
    """Test base58 and base64url encoding."""
    
    def test_base64url_encode_decode(self):
        """Base64url round-trip."""
        original = b"test data with special chars: !@#$%"
        
        encoded = b64url_encode(original)
        decoded = b64url_decode(encoded)
        
        assert decoded == original
    
    def test_base64url_no_padding(self):
        """Base64url doesn't include padding."""
        encoded = b64url_encode(b"test")
        assert '=' not in encoded
    
    def test_base64url_decode_with_padding(self):
        """Base64url decode works with or without padding."""
        original = b"test"
        encoded = b64url_encode(original)
        
        # Decode without padding
        assert b64url_decode(encoded) == original
        
        # Decode with padding
        padded = encoded + "=" * (4 - len(encoded) % 4)
        assert b64url_decode(padded) == original
    
    def test_base58_encode_decode(self):
        """Base58 round-trip."""
        original = b"test data"
        
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        
        assert decoded == original
    
    def test_base58_leading_zeros(self):
        """Base58 preserves leading zeros."""
        original = b"\x00\x00test"
        
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        
        assert decoded == original
    
    def test_base58_all_zeros(self):
        """Base58 handles all-zero bytes."""
        original = b"\x00\x00\x00"
        
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        
        assert decoded == original


class TestHashFunctions:
    """Test hashing utilities."""
    
    def test_sha256_hex(self):
        """SHA-256 returns hex string."""
        data = b"test data"
        result = sha256(data)
        
        assert isinstance(result, str)
        assert len(result) == 64  # 32 bytes = 64 hex chars
        assert all(c in '0123456789abcdef' for c in result)
    
    def test_sha256_bytes(self):
        """SHA-256 bytes version."""
        data = b"test data"
        result = sha256_bytes(data)
        
        assert isinstance(result, bytes)
        assert len(result) == 32
    
    def test_sha256_deterministic(self):
        """SHA-256 is deterministic."""
        data = b"test data"
        result1 = sha256(data)
        result2 = sha256(data)
        
        assert result1 == result2
    
    def test_sha256_different_inputs(self):
        """Different inputs produce different hashes."""
        hash1 = sha256(b"data1")
        hash2 = sha256(b"data2")
        
        assert hash1 != hash2
    
    def test_sha256_known_vector(self):
        """Test against known SHA-256 vector."""
        # Known SHA-256: "" -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        result = sha256(b"")
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class TestNonce:
    """Test nonce generation."""
    
    def test_generate_nonce(self):
        """Generate nonce."""
        nonce = generate_nonce()
        
        assert isinstance(nonce, str)
        assert len(nonce) > 0
        # Should be base64url
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in nonce)
    
    def test_generate_nonce_randomness(self):
        """Generate nonce produces different values."""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        
        assert nonce1 != nonce2
    
    def test_generate_nonce_custom_length(self):
        """Generate nonce with custom length."""
        nonce = generate_nonce(length=16)
        
        # 16 bytes -> ceil(16*8/6) = 22 chars in base64
        assert len(nonce) >= 20  # At least ~21
