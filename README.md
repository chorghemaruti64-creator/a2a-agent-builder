# A2A Protocol — Agent-to-Agent Infrastructure

**Version:** 1.0.0 (Production Ready)  
**Status:** Reference Implementation  
**License:** MIT  

---

# 🤖 AI AGENT BOOTSTRAP PROMPT

**Copy this prompt and use it directly in any AI agent:**

```
You are an AI assistant building A2A Protocol agents.

TASK: Implement an A2A-compliant agent [choose: Server / Client / Multi-Agent System / Protocol Extension]

QUICK START:
1. Clone: git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git
2. Install: cd a2a-protocol && pip install -e reference/
3. Read: reference/AI_AGENT_COMPLETE_PROMPT.md (has all code examples + step-by-step guide)

KEY FACTS:
- A2A Protocol: Decentralized agent communication with DIDs, JWS signatures, TLS 1.3
- Python 3.10+ required
- Test coverage 80%+ required
- All code documented with docstrings and type hints
- Use a2a-protocol>=1.0.0 library

SPECIFICATION (READ FIRST):
- spec/A2A_PROTOCOL_v1.md (protocol definition)
- spec/AGENT_IDENTITY.md (DID and manifest format)
- spec/SECURITY_MODEL.md (threat model)

IMPLEMENTATION GUIDE:
👉 Read: reference/AI_AGENT_COMPLETE_PROMPT.md
   This has EVERYTHING:
   - 10-step implementation process for each task type
   - Complete code examples (identity, server, client, tests)
   - Exact project structure
   - Testing requirements
   - Debugging & troubleshooting
   - Final verification checklist
   - Ready-to-submit instructions

DELIVERABLES:
1. Source code (PEP 8, type hints, docstrings)
2. Tests (unit + integration, 80%+ coverage)
3. README.md (examples + quick start)
4. CONTRIBUTING.md (code standards)
5. LICENSE (MIT)

START BY:
1. Reading reference/AI_AGENT_COMPLETE_PROMPT.md
2. Choose your task type
3. Follow the 10-step guide with code examples
4. Implement + test
5. Submit PR to https://github.com/chorghemaruti64-creator/a2a-protocol

REFERENCES:
- Full prompt: reference/AI_AGENT_COMPLETE_PROMPT.md
- Integration guide: reference/PROJECT_INTEGRATION_GUIDE.md
- Examples: reference/examples/
- Tests: reference/tests/
- Specification: spec/
```

---

# 🚀 Quick Start

## For AI Agents

👉 **Use the bootstrap prompt above. It will guide you to the complete implementation prompt.**

The complete prompt (`reference/AI_AGENT_COMPLETE_PROMPT.md`) includes:
- All 4 task types (Agent Server, Client, Multi-Agent, Extension)
- 10-step implementation process with code examples
- Complete code for identity, server, client, tests
- Debugging and troubleshooting guide
- Final verification checklist

## For Reference Implementers

1. Clone: `git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git`
2. Install: `cd a2a-protocol && pip install -e reference/`
3. Read: `reference/AI_AGENT_COMPLETE_PROMPT.md`
4. Run tests: `pytest tests/ -v`
5. Study: `reference/examples/`

## For Protocol Engineers

Read in order:
1. `spec/A2A_PROTOCOL_v1.md` — Protocol definition
2. `spec/AGENT_IDENTITY.md` — Identity format
3. `spec/SECURITY_MODEL.md` — Trust model
4. `docs/ARCHITECTURE.md` — Layered design

---

# 📚 Key Documentation

| Document | Purpose |
|----------|---------|
| **AI_AGENT_COMPLETE_PROMPT.md** | ⭐ **START HERE** - Complete implementation guide with code examples |
| **PROJECT_INTEGRATION_GUIDE.md** | 5-phase integration guide for new projects |
| **A2A_PROTOCOL_v1.md** | Formal protocol specification |
| **AGENT_IDENTITY.md** | DID and manifest specification |
| **SECURITY_MODEL.md** | Threat analysis and security model |
| **examples/** | Working code examples |
| **tests/** | Test patterns and fixtures |

---

# What This Is

A2A is a **formal protocol specification and reference implementation for agent-to-agent communication**. It defines:

- **Identity:** Cryptographically bound agent identifiers (DIDs)
- **Discovery:** How agents find each other across networks
- **Transport:** Abstract messaging layer (HTTP, gRPC, WebSocket compatible)
- **Handshake:** Cryptographic verification and policy negotiation
- **Session:** Authenticated, audited request/response lifecycle
- **Policy:** Declarative agent constraints (rate limits, capabilities, permissions)

Think of it as **the HTTP/TLS/DNS for AI agents** — foundational infrastructure enabling millions of autonomous agents to interact safely, verifiably, and at scale.

---

# Architecture

```
┌──────────────────────────────────────────────────┐
│ Application Layer                                │
│ (Agent implementation, business logic)           │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ A2A Protocol Layer                               │
│ ├─ Identity (DIDs, manifests, credentials)      │
│ ├─ Discovery (DID resolution, manifest fetching)│
│ ├─ Handshake (authentication, policy exchange)  │
│ ├─ Session (lifecycle, state machine)           │
│ └─ Policy (enforcement, rate limiting)          │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ Transport Abstraction Layer (TAL)                │
│ (pluggable: HTTP/gRPC/WebSocket/custom)         │
└──────────────────┬───────────────────────────────┘
                   │
┌──────────────────▼───────────────────────────────┐
│ Network Layer (TLS 1.3 required)                 │
│ (encryption, confidentiality, integrity)        │
└──────────────────────────────────────────────────┘
```

---

# Handshake Protocol

```
Client                                     Server
  │                                          │
  ├─ 1. HELLO (identity, nonce) ────────────→
  │                                          │
  │ ←─ 2. CHALLENGE (nonce, pubkey) ────────┤
  │                                          │
  ├─ 3. PROOF (signed nonces) ───────────────→
  │                                          │
  │ ←─ 4. POLICY (binding agreement) ───────┤
  │                                          │
  ├─ 5. ACCEPT_POLICY (acknowledge) ────────→
  │                                          │
  │ ←─ 6. SESSION (session_id, expiry) ─────┤
  │                                          │
  | ════ SESSION ESTABLISHED ════════════════|
  │                                          │
  ├─ INTENT (goal, params, signature) ──────→
  │                                          │
  │ ←─ RESULT (response, audit) ────────────┤
```

---

# Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=a2a --cov-report=html

# Run specific phase
pytest tests/unit/test_crypto.py -v
pytest tests/integration/test_e2e.py -v
```

**Test Summary:**
- 178+ tests across all phases
- Unit tests for each component
- Integration tests for end-to-end scenarios
- Security tests for all threats

---

# Security

⚠️ **Read SECURITY.md before deploying to production.**

Key security features:
- **TLS 1.3** required (not optional)
- **Ed25519** signatures (JWS RFC 7515)
- **DID-based** identity (verifiable, decentralized)
- **Manifest** signing (agent credentials)
- **Session** commitment binding (prevents hijacking)
- **Nonce** replay prevention
- **Rate limiting** per-client and per-session
- **Audit logging** (immutable interaction history)
- **Policy enforcement** (capabilities, constraints)

---

# Contributing

1. **Protocol changes:** Submit RFC pull request in `/spec`
2. **Implementation:** Contribute to `/reference` or write your own
3. **Issues:** Use GitHub Issues for bugs or feature requests
4. **Code standards:** See CONTRIBUTING.md

---

# Links

- **GitHub:** https://github.com/chorghemaruti64-creator/a2a-protocol
- **Issues:** https://github.com/chorghemaruti64-creator/a2a-protocol/issues
- **Reference Implementation:** `/reference`
- **Specification:** `/spec`
- **Documentation:** `/docs`

---

**Status:** ✅ Production Ready (v1.0.0)

**Last Updated:** February 2026

**Security Reviewed:** Yes
