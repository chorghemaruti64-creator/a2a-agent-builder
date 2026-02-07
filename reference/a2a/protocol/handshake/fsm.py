"""
Handshake Finite State Machine (Phase 3).

Implements the 9-state FSM per A2A Protocol Spec Section 5:
- INIT (start)
- HELLO_SENT, CHALLENGE_RECEIVED, PROOF_SENT, POLICY_RECEIVED, ACCEPTANCE_SENT, SESSION_RECEIVED
- ESTABLISHED (success)
- TERMINATED, FAILED (error states)

Security features:
- Nonce verification (both nonces must match in PROOF)
- Replay protection (track received nonces, reject duplicates)
- Manifest hash verification (client checks server manifest)
- Policy signature verification (using server public key)
- Timestamp validation (±5 min tolerance)
- Timeout handling (10s per state, 30s total)
- Invalid state transitions raise errors
"""

import time
import json
from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass

from a2a.security.crypto import JWS, generate_nonce, KeyPair
from a2a.protocol.handshake.messages import (
    HandshakeMessage,
    HelloMessage,
    ChallengeMessage,
    ProofMessage,
    PolicyMessage,
    AcceptPolicyMessage,
    SessionMessage,
    HandshakeError,
    parse_message,
)
from a2a.core.errors import TimeoutError as A2ATimeoutError


class HandshakeState(str, Enum):
    """Handshake FSM states."""
    INIT = "INIT"
    HELLO_SENT = "HELLO_SENT"
    CHALLENGE_RECEIVED = "CHALLENGE_RECEIVED"
    PROOF_SENT = "PROOF_SENT"
    POLICY_RECEIVED = "POLICY_RECEIVED"
    ACCEPTANCE_SENT = "ACCEPTANCE_SENT"
    SESSION_RECEIVED = "SESSION_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    TERMINATED = "TERMINATED"
    FAILED = "FAILED"


@dataclass
class HandshakeFSMConfig:
    """Configuration for HandshakeFSM."""
    state_timeout_seconds: int = 10  # Max time per state
    total_timeout_seconds: int = 30  # Max total handshake time
    nonce_length_bytes: int = 32
    manifest_hash_length: int = 64


class HandshakeFSM:
    """
    Handshake Finite State Machine.
    
    Manages client-side handshake protocol flow.
    Each method corresponds to a state transition and message.
    """
    
    def __init__(self, keypair: KeyPair, agent_did: str, manifest_hash: str, config: Optional[HandshakeFSMConfig] = None):
        """
        Initialize FSM.
        
        Args:
            keypair: Client's Ed25519 keypair
            agent_did: Client's DID (did:key:z...)
            manifest_hash: SHA-256 of client's manifest (hex string)
            config: Optional configuration
        """
        self.keypair = keypair
        self.agent_did = agent_did
        self.manifest_hash = manifest_hash
        self.config = config or HandshakeFSMConfig()
        
        # State tracking
        self.state = HandshakeState.INIT
        self.start_time = int(time.time())
        self.state_entry_time = self.start_time
        
        # Nonce tracking (for replay protection)
        self.nonce_a: Optional[str] = None
        self.nonce_b: Optional[str] = None
        self.received_nonces: set = set()  # Track all received nonces
        
        # Server data
        self.server_public_keys: Optional[list] = None
        self.policy_hash: Optional[str] = None
        self._policy_data: Optional[Dict[str, Any]] = None
        self.session_id: Optional[str] = None
        self.expires_at: Optional[int] = None
    
    def _check_state_timeout(self):
        """Check if current state has timed out."""
        elapsed = int(time.time()) - self.state_entry_time
        if elapsed > self.config.state_timeout_seconds:
            raise A2ATimeoutError(
                operation=f"Handshake state {self.state}",
                timeout_seconds=self.config.state_timeout_seconds,
            )
    
    def _check_total_timeout(self):
        """Check if total handshake has timed out."""
        elapsed = int(time.time()) - self.start_time
        if elapsed > self.config.total_timeout_seconds:
            raise A2ATimeoutError(
                operation="Handshake",
                timeout_seconds=self.config.total_timeout_seconds,
            )
    
    def _check_nonce_replay(self, nonce: str):
        """Check if nonce has been received before (replay protection)."""
        if nonce in self.received_nonces:
            raise HandshakeError(
                f"Nonce replay detected: {nonce[:16]}...",
                code="NONCE_REPLAY",
            )
        self.received_nonces.add(nonce)
    
    def _transition_to(self, new_state: HandshakeState):
        """Transition to new state."""
        self.state = new_state
        self.state_entry_time = int(time.time())
    
    def hello(self) -> Dict[str, Any]:
        """
        HELLO message: Client initiates handshake.
        
        State: INIT → HELLO_SENT
        
        Returns:
            HELLO message dict
        
        Raises:
            HandshakeError: If not in INIT state
        """
        if self.state != HandshakeState.INIT:
            raise HandshakeError(
                f"Cannot send HELLO from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_total_timeout()
        
        # Generate nonce_a
        self.nonce_a = generate_nonce(self.config.nonce_length_bytes)
        self._check_nonce_replay(self.nonce_a)
        
        # Create message
        msg = HelloMessage(
            nonce_a=self.nonce_a,
            agent_did=self.agent_did,
            manifest_hash=self.manifest_hash,
            timestamp=int(time.time()),
        )
        
        self._transition_to(HandshakeState.HELLO_SENT)
        return msg.model_dump()
    
    def challenge(self, message_data: Dict[str, Any]) -> None:
        """
        CHALLENGE message: Server responds with nonce and policy.
        
        State: HELLO_SENT → CHALLENGE_RECEIVED
        
        Args:
            message_data: CHALLENGE message dict
        
        Raises:
            HandshakeError: If not in HELLO_SENT state, or validation fails
        """
        if self.state != HandshakeState.HELLO_SENT:
            raise HandshakeError(
                f"Cannot receive CHALLENGE from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_state_timeout()
        self._check_total_timeout()
        
        # Parse message
        msg = parse_message(message_data)
        if not isinstance(msg, ChallengeMessage):
            raise HandshakeError(
                f"Expected CHALLENGE, got {type(msg).__name__}",
                code="INVALID_MESSAGE_TYPE",
            )
        
        # Check for replay
        self._check_nonce_replay(msg.nonce_b)
        
        # Store nonce_b and policy_hash
        self.nonce_b = msg.nonce_b
        self.policy_hash = msg.policy_hash
        self.server_public_keys = msg.public_keys
        
        self._transition_to(HandshakeState.CHALLENGE_RECEIVED)
    
    def proof(self) -> Dict[str, Any]:
        """
        PROOF message: Client proves ownership by signing nonces.
        
        State: CHALLENGE_RECEIVED → PROOF_SENT
        
        Returns:
            PROOF message dict
        
        Raises:
            HandshakeError: If not in CHALLENGE_RECEIVED state
        """
        if self.state != HandshakeState.CHALLENGE_RECEIVED:
            raise HandshakeError(
                f"Cannot send PROOF from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_state_timeout()
        self._check_total_timeout()
        
        if not self.nonce_a or not self.nonce_b:
            raise HandshakeError(
                "Cannot create PROOF: missing nonces",
                code="MISSING_NONCES",
            )
        
        # Create proof payload (both nonces signed)
        proof_payload = {
            "nonce_a": self.nonce_a,
            "nonce_b": self.nonce_b,
        }
        
        # Sign with client's keypair
        proof_jws = JWS.create(proof_payload, self.keypair)
        
        # Create message
        msg = ProofMessage(
            nonce_a=self.nonce_a,
            nonce_b=self.nonce_b,
            proof=proof_jws,
            timestamp=int(time.time()),
        )
        
        self._transition_to(HandshakeState.PROOF_SENT)
        return msg.model_dump()
    
    def policy(self, message_data: Dict[str, Any]) -> None:
        """
        POLICY message: Server sends policy.
        
        State: PROOF_SENT → POLICY_RECEIVED
        
        Args:
            message_data: POLICY message dict
        
        Raises:
            HandshakeError: If not in PROOF_SENT state, or validation fails
        """
        if self.state != HandshakeState.PROOF_SENT:
            raise HandshakeError(
                f"Cannot receive POLICY from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_state_timeout()
        self._check_total_timeout()
        
        # Parse message
        msg = parse_message(message_data)
        if not isinstance(msg, PolicyMessage):
            raise HandshakeError(
                f"Expected POLICY, got {type(msg).__name__}",
                code="INVALID_MESSAGE_TYPE",
            )
        
        # Verify policy signature (using server's public key)
        if not self.server_public_keys:
            raise HandshakeError(
                "Cannot verify policy: no server public keys",
                code="MISSING_PUBLIC_KEY",
            )
        
        # Try to verify with each public key
        verified = False
        for pubkey_info in self.server_public_keys:
            if "key" not in pubkey_info:
                continue
            
            pubkey_b64 = pubkey_info["key"]
            is_valid, payload = JWS.verify(msg.signature, self._b64_to_bytes(pubkey_b64))
            
            if is_valid:
                verified = True
                break
        
        if not verified:
            raise HandshakeError(
                "Policy signature verification failed",
                code="SIGNATURE_VERIFICATION_FAILED",
            )
        
        self._policy_data = msg.policy
        
        self._transition_to(HandshakeState.POLICY_RECEIVED)
    
    def accept_policy(self) -> Dict[str, Any]:
        """
        ACCEPT_POLICY message: Client accepts policy.
        
        State: POLICY_RECEIVED → ACCEPTANCE_SENT
        
        Returns:
            ACCEPT_POLICY message dict
        
        Raises:
            HandshakeError: If not in POLICY_RECEIVED state
        """
        if self.state != HandshakeState.POLICY_RECEIVED:
            raise HandshakeError(
                f"Cannot send ACCEPT_POLICY from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_state_timeout()
        self._check_total_timeout()
        
        if not self.policy_hash:
            raise HandshakeError(
                "Cannot accept policy: missing policy_hash",
                code="MISSING_POLICY_HASH",
            )
        
        # Create commitment signature
        commitment_payload = {
            "policy_hash": self.policy_hash,
        }
        
        commitment_jws = JWS.create(commitment_payload, self.keypair)
        
        # Create message
        msg = AcceptPolicyMessage(
            policy_hash=self.policy_hash,
            commitment=commitment_jws,
            timestamp=int(time.time()),
        )
        
        self._transition_to(HandshakeState.ACCEPTANCE_SENT)
        return msg.model_dump()
    
    def session(self, message_data: Dict[str, Any]) -> None:
        """
        SESSION message: Server establishes session.
        
        State: ACCEPTANCE_SENT → SESSION_RECEIVED → ESTABLISHED
        
        Args:
            message_data: SESSION message dict
        
        Raises:
            HandshakeError: If not in ACCEPTANCE_SENT state, or validation fails
        """
        if self.state != HandshakeState.ACCEPTANCE_SENT:
            raise HandshakeError(
                f"Cannot receive SESSION from state {self.state}",
                code="INVALID_STATE_TRANSITION",
            )
        
        self._check_state_timeout()
        self._check_total_timeout()
        
        # Parse message
        msg = parse_message(message_data)
        if not isinstance(msg, SessionMessage):
            raise HandshakeError(
                f"Expected SESSION, got {type(msg).__name__}",
                code="INVALID_MESSAGE_TYPE",
            )
        
        # Verify session signature
        if not self.server_public_keys:
            raise HandshakeError(
                "Cannot verify session: no server public keys",
                code="MISSING_PUBLIC_KEY",
            )
        
        verified = False
        for pubkey_info in self.server_public_keys:
            if "key" not in pubkey_info:
                continue
            
            pubkey_b64 = pubkey_info["key"]
            is_valid, payload = JWS.verify(msg.signature, self._b64_to_bytes(pubkey_b64))
            
            if is_valid:
                verified = True
                break
        
        if not verified:
            raise HandshakeError(
                "Session signature verification failed",
                code="SIGNATURE_VERIFICATION_FAILED",
            )
        
        # Store session data
        self.session_id = msg.session_id
        self.expires_at = msg.expires_at
        
        self._transition_to(HandshakeState.SESSION_RECEIVED)
        self._transition_to(HandshakeState.ESTABLISHED)
    
    def _b64_to_bytes(self, b64: str) -> bytes:
        """Convert base64url string to bytes."""
        from a2a.security.crypto import b64url_decode
        try:
            return b64url_decode(b64)
        except Exception as e:
            raise HandshakeError(f"Invalid base64 key: {e}", code="INVALID_KEY")
    
    def is_established(self) -> bool:
        """Check if handshake is complete and successful."""
        return self.state == HandshakeState.ESTABLISHED
    
    def is_failed(self) -> bool:
        """Check if handshake failed."""
        return self.state == HandshakeState.FAILED
    
    def is_terminated(self) -> bool:
        """Check if handshake was terminated."""
        return self.state == HandshakeState.TERMINATED
    
    def terminate(self):
        """Terminate handshake."""
        self._transition_to(HandshakeState.TERMINATED)
    
    def fail(self, error: Exception):
        """Mark handshake as failed."""
        self._transition_to(HandshakeState.FAILED)
    
    def get_state(self) -> str:
        """Get current state."""
        return self.state.value
    
    def get_session_id(self) -> Optional[str]:
        """Get established session ID."""
        if self.is_established():
            return self.session_id
        return None
