"""
A2A Handshake Protocol Message Types (Phase 3).

Implements the 6 handshake messages per A2A Protocol Spec Section 5:
- HELLO: Client initiates
- CHALLENGE: Server responds
- PROOF: Client proves ownership
- POLICY: Server sends policy
- ACCEPT_POLICY: Client accepts
- SESSION: Server establishes session

All messages include:
- Timestamp validation (±5 min tolerance)
- Nonce validation (32+ bytes base64url)
- Field completeness checks
- State-specific constraints
"""

import time
from typing import Dict, Any, Optional, List
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict

from a2a.security.crypto import b64url_decode
from a2a.core.errors import A2AError


class HandshakeError(A2AError):
    """Handshake protocol error."""

    def __init__(self, message: str, code: str = "HANDSHAKE_FAILED", request_id: Optional[str] = None):
        super().__init__(
            code=code,
            message=message,
            recoverable=True,
            request_id=request_id,
            http_status=500,
        )


class MessageType(str, Enum):
    """Handshake message types."""
    HELLO = "HELLO"
    CHALLENGE = "CHALLENGE"
    PROOF = "PROOF"
    POLICY = "POLICY"
    ACCEPT_POLICY = "ACCEPT_POLICY"
    SESSION = "SESSION"


class HandshakeMessage(BaseModel):
    """Base class for handshake messages."""
    
    model_config = ConfigDict(frozen=True)
    
    message_type: MessageType
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    
    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: int) -> int:
        """Ensure timestamp is within ±5 min tolerance."""
        now = int(time.time())
        delta = abs(now - v)
        if delta > 300:  # 5 minutes
            raise ValueError(f"Timestamp too old or in future: delta={delta}s")
        return v


class HelloMessage(HandshakeMessage):
    """
    Client HELLO message.
    
    Initiates handshake with:
    - nonce_a: Random nonce (32+ bytes base64url)
    - agent_did: Client DID (format: did:key:z...)
    - manifest_hash: SHA-256 of client manifest (hex string)
    """
    
    message_type: MessageType = MessageType.HELLO
    nonce_a: str = Field(..., min_length=32)  # base64url encoded
    agent_did: str = Field(..., min_length=8)
    manifest_hash: str = Field(..., min_length=64)  # SHA-256 hex
    
    @field_validator("nonce_a")
    @classmethod
    def validate_nonce_a(cls, v: str) -> str:
        """Validate nonce_a is valid base64url."""
        try:
            decoded = b64url_decode(v)
            if len(decoded) < 32:
                raise ValueError("Nonce too short")
        except Exception as e:
            raise ValueError(f"Invalid nonce_a: {e}")
        return v
    
    @field_validator("agent_did")
    @classmethod
    def validate_agent_did(cls, v: str) -> str:
        """Validate DID format."""
        if not v.startswith("did:key:"):
            raise ValueError("DID must start with 'did:key:'")
        return v
    
    @field_validator("manifest_hash")
    @classmethod
    def validate_manifest_hash(cls, v: str) -> str:
        """Validate manifest_hash is hex string of correct length."""
        if len(v) != 64:
            raise ValueError(f"Manifest hash must be 64 hex chars, got {len(v)}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Manifest hash must be valid hex")
        return v


class ChallengeMessage(HandshakeMessage):
    """
    Server CHALLENGE message.
    
    Responds to HELLO with:
    - nonce_b: Server nonce (32+ bytes base64url)
    - policy_hash: SHA-256 of policy (hex string)
    - public_keys: List of public key JWKs for verification
    """
    
    message_type: MessageType = MessageType.CHALLENGE
    nonce_b: str = Field(..., min_length=32)
    policy_hash: str = Field(..., min_length=64)
    public_keys: List[Dict[str, Any]] = Field(..., min_length=1)
    
    @field_validator("nonce_b")
    @classmethod
    def validate_nonce_b(cls, v: str) -> str:
        """Validate nonce_b is valid base64url."""
        try:
            decoded = b64url_decode(v)
            if len(decoded) < 32:
                raise ValueError("Nonce too short")
        except Exception as e:
            raise ValueError(f"Invalid nonce_b: {e}")
        return v
    
    @field_validator("policy_hash")
    @classmethod
    def validate_policy_hash(cls, v: str) -> str:
        """Validate policy_hash."""
        if len(v) != 64:
            raise ValueError(f"Policy hash must be 64 hex chars, got {len(v)}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Policy hash must be valid hex")
        return v
    
    @field_validator("public_keys")
    @classmethod
    def validate_public_keys(cls, v: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate public_keys list."""
        if not v:
            raise ValueError("Must provide at least one public key")
        for key in v:
            if "key" not in key:
                raise ValueError("Each public key must have 'key' field")
            if "alg" not in key or key["alg"] != "EdDSA":
                raise ValueError("Public key must have alg=EdDSA")
        return v


class ProofMessage(HandshakeMessage):
    """
    Client PROOF message.
    
    Proves ownership by signing both nonces:
    - nonce_a: Echo of original nonce_a
    - nonce_b: Echo of server's nonce_b
    - proof: JWS signature over nonce_a and nonce_b
    """
    
    message_type: MessageType = MessageType.PROOF
    nonce_a: str = Field(..., min_length=32)
    nonce_b: str = Field(..., min_length=32)
    proof: str = Field(..., min_length=10)  # JWS format: header.payload.sig
    
    @field_validator("nonce_a")
    @classmethod
    def validate_nonce_a(cls, v: str) -> str:
        """Validate nonce_a."""
        try:
            decoded = b64url_decode(v)
            if len(decoded) < 32:
                raise ValueError("Nonce too short")
        except Exception as e:
            raise ValueError(f"Invalid nonce_a: {e}")
        return v
    
    @field_validator("nonce_b")
    @classmethod
    def validate_nonce_b(cls, v: str) -> str:
        """Validate nonce_b."""
        try:
            decoded = b64url_decode(v)
            if len(decoded) < 32:
                raise ValueError("Nonce too short")
        except Exception as e:
            raise ValueError(f"Invalid nonce_b: {e}")
        return v
    
    @field_validator("proof")
    @classmethod
    def validate_proof(cls, v: str) -> str:
        """Validate proof is JWS format."""
        if v.count('.') != 2:
            raise ValueError("Proof must be JWS format (header.payload.signature)")
        return v


class PolicyMessage(HandshakeMessage):
    """
    Server POLICY message.
    
    Sends policy object:
    - policy: Dict with rate_limit, session_timeout, etc.
    - signature: JWS signature over policy
    """
    
    message_type: MessageType = MessageType.POLICY
    policy: Dict[str, Any] = Field(...)
    signature: str = Field(..., min_length=10)  # JWS signature
    
    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        """Validate signature is JWS format."""
        if v.count('.') != 2:
            raise ValueError("Signature must be JWS format (header.payload.signature)")
        return v


class AcceptPolicyMessage(HandshakeMessage):
    """
    Client ACCEPT_POLICY message.
    
    Client accepts policy:
    - policy_hash: Echo of policy hash
    - commitment: JWS signature committing to policy
    """
    
    message_type: MessageType = MessageType.ACCEPT_POLICY
    policy_hash: str = Field(..., min_length=64)
    commitment: str = Field(..., min_length=10)  # JWS signature
    
    @field_validator("policy_hash")
    @classmethod
    def validate_policy_hash(cls, v: str) -> str:
        """Validate policy_hash."""
        if len(v) != 64:
            raise ValueError(f"Policy hash must be 64 hex chars, got {len(v)}")
        try:
            int(v, 16)
        except ValueError:
            raise ValueError("Policy hash must be valid hex")
        return v
    
    @field_validator("commitment")
    @classmethod
    def validate_commitment(cls, v: str) -> str:
        """Validate commitment."""
        if v.count('.') != 2:
            raise ValueError("Commitment must be JWS format (header.payload.signature)")
        return v


class SessionMessage(HandshakeMessage):
    """
    Server SESSION message.
    
    Establishes session:
    - session_id: Unique session identifier
    - expires_at: Unix timestamp when session expires
    - signature: JWS signature over session data
    """
    
    message_type: MessageType = MessageType.SESSION
    session_id: str = Field(..., min_length=16)
    expires_at: int = Field(...)
    signature: str = Field(..., min_length=10)  # JWS signature
    
    @field_validator("expires_at")
    @classmethod
    def validate_expires_at(cls, v: int) -> int:
        """Ensure expires_at is in the future."""
        now = int(time.time())
        if v <= now:
            raise ValueError(f"Session must expire in the future")
        return v
    
    @field_validator("signature")
    @classmethod
    def validate_signature(cls, v: str) -> str:
        """Validate signature."""
        if v.count('.') != 2:
            raise ValueError("Signature must be JWS format (header.payload.signature)")
        return v


def parse_message(data: Dict[str, Any]) -> HandshakeMessage:
    """
    Parse raw message dict to typed message.
    
    Args:
        data: Raw message dictionary
    
    Returns:
        Typed message instance
    
    Raises:
        HandshakeError: If message type unknown or validation fails
    """
    msg_type = data.get("message_type")
    
    try:
        if msg_type == MessageType.HELLO.value or msg_type == MessageType.HELLO:
            return HelloMessage(**data)
        elif msg_type == MessageType.CHALLENGE.value or msg_type == MessageType.CHALLENGE:
            return ChallengeMessage(**data)
        elif msg_type == MessageType.PROOF.value or msg_type == MessageType.PROOF:
            return ProofMessage(**data)
        elif msg_type == MessageType.POLICY.value or msg_type == MessageType.POLICY:
            return PolicyMessage(**data)
        elif msg_type == MessageType.ACCEPT_POLICY.value or msg_type == MessageType.ACCEPT_POLICY:
            return AcceptPolicyMessage(**data)
        elif msg_type == MessageType.SESSION.value or msg_type == MessageType.SESSION:
            return SessionMessage(**data)
        else:
            raise HandshakeError(f"Unknown message type: {msg_type}", code="INVALID_MESSAGE_TYPE")
    except HandshakeError:
        raise
    except Exception as e:
        raise HandshakeError(f"Message validation failed: {e}", code="INVALID_MESSAGE")
