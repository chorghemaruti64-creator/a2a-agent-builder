"""
Agent identity and cryptographic key management.

Defines:
- DID (Decentralized Identifier) parsing
- Agent manifest and metadata
- Identity binding

Note: Most methods raise NotImplementedError (to be filled in PHASE 2).
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
import json
import time


class DIDMethod(Enum):
    """Supported DID resolution methods."""
    KEY = "key"
    WEB = "web"
    GITHUB = "github"


class DID:
    """
    Decentralized Identifier for an agent.

    Formats:
    - did:key:z6Mk...      (self-signed)
    - did:web:example.com  (DNS-backed)
    - did:github:owner/repo (GitHub-backed)
    """

    def __init__(self, did_string: str):
        self.did = did_string
        self.method = self._extract_method()
        self.identifier = self._extract_identifier()

    def _extract_method(self) -> DIDMethod:
        """Extract DID method from string."""
        if not self.did.startswith("did:"):
            raise ValueError(f"Invalid DID format: {self.did}")
        method_str = self.did.split(":")[1]
        return DIDMethod(method_str)

    def _extract_identifier(self) -> str:
        """Extract identifier portion."""
        return self.did.split(":", 2)[2]

    def __str__(self) -> str:
        return self.did

    def __eq__(self, other) -> bool:
        return self.did == str(other)

    def __hash__(self) -> int:
        return hash(self.did)


@dataclass
class PublicKey:
    """JWK-format public key for agent."""
    kid: str
    kty: str
    alg: str
    use: str
    key: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "kid": self.kid,
            "kty": self.kty,
            "alg": self.alg,
            "use": self.use,
            "key": self.key,
        }


@dataclass
class AgentManifest:
    """
    Signed identity card for an agent.

    See: /spec/AGENT_IDENTITY.md
    """
    manifest_version: str
    agent_did: str
    agent_id: str
    public_keys: List[PublicKey]
    endpoints: List[Dict[str, Any]]
    capabilities: List[Dict[str, Any]] = field(default_factory=list)
    policy: Optional[Dict[str, Any]] = None
    trust_chain: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    published_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: Optional[int] = None
    manifest_hash: Optional[str] = None
    manifest_signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "manifest_version": self.manifest_version,
            "agent_did": self.agent_did,
            "agent_id": self.agent_id,
            "public_keys": [pk.to_dict() for pk in self.public_keys],
            "endpoints": self.endpoints,
            "capabilities": self.capabilities,
            "policy": self.policy,
            "trust_chain": self.trust_chain,
            "metadata": self.metadata,
            "published_at": self.published_at,
            "expires_at": self.expires_at,
            "manifest_hash": self.manifest_hash,
            "manifest_signature": self.manifest_signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentManifest":
        """Create from JSON dict."""
        public_keys = [
            PublicKey(**pk) for pk in data.get("public_keys", [])
        ]
        return cls(
            manifest_version=data["manifest_version"],
            agent_did=data["agent_did"],
            agent_id=data["agent_id"],
            public_keys=public_keys,
            endpoints=data["endpoints"],
            capabilities=data.get("capabilities", []),
            policy=data.get("policy"),
            trust_chain=data.get("trust_chain", []),
            metadata=data.get("metadata", {}),
            published_at=data.get("published_at", int(time.time())),
            expires_at=data.get("expires_at"),
            manifest_hash=data.get("manifest_hash"),
            manifest_signature=data.get("manifest_signature"),
        )


class AgentIdentity:
    """
    An agent's cryptographic identity.

    Binds together DID, public keys, and manifest.
    """

    def __init__(
        self,
        did: DID,
        manifest: AgentManifest,
    ):
        self.did = did
        self.manifest = manifest


class Agent:
    """
    High-level A2A Agent API.

    Usage:
        >>> agent = Agent.from_keypair(keypair, "my-agent")
        >>> session = await agent.connect("did:key:z6Mk...")
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
