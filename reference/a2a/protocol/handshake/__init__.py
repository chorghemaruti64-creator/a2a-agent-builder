"""
A2A Handshake Protocol (Phase 3).

Exports:
- HandshakeFSM: Main state machine
- HandshakeState: State enum
- Message types: HelloMessage, ChallengeMessage, ProofMessage, etc.
- HandshakeError: Exception type
"""

from a2a.protocol.handshake.fsm import HandshakeFSM, HandshakeState, HandshakeFSMConfig
from a2a.protocol.handshake.messages import (
    HandshakeError,
    MessageType,
    HandshakeMessage,
    HelloMessage,
    ChallengeMessage,
    ProofMessage,
    PolicyMessage,
    AcceptPolicyMessage,
    SessionMessage,
    parse_message,
)

__all__ = [
    "HandshakeFSM",
    "HandshakeState",
    "HandshakeFSMConfig",
    "HandshakeError",
    "MessageType",
    "HandshakeMessage",
    "HelloMessage",
    "ChallengeMessage",
    "ProofMessage",
    "PolicyMessage",
    "AcceptPolicyMessage",
    "SessionMessage",
    "parse_message",
]
