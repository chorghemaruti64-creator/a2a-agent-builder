# A2A Protocol — Agent-to-Agent Infrastructure

**Version:** 1.0.0 (Production Ready)  
**Status:** Reference Implementation  
**License:** MIT  

---

# 🤖 COMPLETE PROMPT FOR AI AGENTS

**⭐ Copy this entire section and use it directly in any AI agent. No modification needed.**

This is a **complete, detailed, error-resistant prompt** for AI agents to implement A2A Protocol-compliant projects.

---

## 🎯 Choose Your Task

**IF BUILDING: Agent Server** → Agent Server Task below

**IF BUILDING: Agent Client** → Agent Client Task below

**IF BUILDING: Multi-Agent System** → Multi-Agent System Task below

**IF BUILDING: Protocol Extension** → Protocol Extension Task below

---

## MANDATORY PREREQUISITES

Before starting, verify you have:

```bash
# 1. Python 3.10+
python --version

# 2. Virtual environment
python -m venv venv
source venv/bin/activate

# 3. Clone A2A Protocol repository
git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git
cd a2a-protocol

# 4. Install A2A library
pip install -e reference/

# 5. Verify
python -c "import a2a; print(f'A2A version: {a2a.__version__}')"

# 6. Navigate to project directory
cd reference
```

**If any step fails, STOP. Do not continue.**

---

## 📚 REFERENCE DOCUMENTATION

Keep these open while working:

| Document | Location |
|----------|----------|
| **A2A Protocol Spec** | `spec/A2A_PROTOCOL_v1.md` |
| **Agent Identity Spec** | `spec/AGENT_IDENTITY.md` |
| **Security Model** | `spec/SECURITY_MODEL.md` |
| **Integration Guide** | `reference/PROJECT_INTEGRATION_GUIDE.md` |
| **Code Examples** | `reference/AI_AGENT_COMPLETE_PROMPT.md` |
| **Working Code** | `reference/examples/` |
| **Tests** | `reference/tests/` |

---

## TASK: Agent Server

### 🎯 Objective
Build an A2A-compliant agent server that:
- Generates unique DID-based identity
- Listens for incoming handshakes
- Handles intent requests
- Returns JSON responses
- Logs interactions

### ✅ Requirements

**Code Quality:**
- [ ] PEP 8 compliant (use `black`)
- [ ] 100% type hints on public functions
- [ ] Comprehensive docstrings
- [ ] Error handling for ALL paths
- [ ] Async/await for I/O

**Functionality:**
- [ ] Uses `a2a-protocol>=1.0.0`
- [ ] JWS signature verification
- [ ] Ed25519 key generation
- [ ] TLS 1.3 configured (production)
- [ ] 2+ custom intents
- [ ] Proper error responses

**Testing:**
- [ ] Unit tests for all public functions
- [ ] Integration tests for handshake
- [ ] Intent handling tests
- [ ] Error case tests
- [ ] **80%+ code coverage (minimum)**

**Documentation:**
- [ ] README.md with examples
- [ ] CONTRIBUTING.md with standards
- [ ] Docstrings on every function
- [ ] Comments on non-obvious code

**Security:**
- [ ] No hardcoded credentials
- [ ] Secrets from environment
- [ ] TLS documented
- [ ] No insecure defaults

### 📂 Exact Project Structure

```
my-a2a-server/
├── src/
│   └── my_server/
│       ├── __init__.py
│       ├── agent.py              # Main class
│       ├── identity.py           # DID management
│       ├── intents/
│       │   ├── __init__.py
│       │   ├── echo.py
│       │   └── process.py
│       └── errors.py
├── tests/
│   ├── unit/
│   │   ├── test_agent.py
│   │   └── test_identity.py
│   └── integration/
│       └── test_e2e.py
├── README.md
├── CONTRIBUTING.md
├── LICENSE
├── requirements.txt
└── setup.py
```

### 📝 10-Step Process

**Step 1 (30 min):** Read specification
- spec/A2A_PROTOCOL_v1.md sections 1-6
- spec/AGENT_IDENTITY.md
- reference/PROJECT_INTEGRATION_GUIDE.md Phase 2

**Step 2 (15 min):** Create project structure
```bash
mkdir -p my-a2a-server/{src/my_server/intents,tests/{unit,integration}}
# ... create __init__.py files
```

**Step 3 (10 min):** Install dependencies
```
a2a-protocol>=1.0.0
pydantic>=2.0.0
httpx>=0.25.0
aiohttp>=3.9.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
```

**Step 4-8 (6-8 hours):** Implement code
- Implement identity management
- Implement main server class
- Implement intent handlers
- Write unit tests
- Write integration tests

**Step 9 (1 hour):** Add documentation
- README.md template
- CONTRIBUTING.md template
- API documentation

**Step 10 (30 min):** Verify and test
```bash
pytest tests/ -v --cov=src
black src/ tests/
mypy src/
flake8 src/ tests/
```

**See reference/AI_AGENT_COMPLETE_PROMPT.md for complete code examples for all steps.**

### ✅ Verification Checklist

- [ ] All tests pass
- [ ] Coverage >= 80%
- [ ] Code formatted with black
- [ ] Type checking passes
- [ ] Linting clean
- [ ] README complete
- [ ] CONTRIBUTING.md exists
- [ ] LICENSE exists
- [ ] Server starts without errors
- [ ] 2+ intents implemented
- [ ] Integration tests pass
- [ ] No hardcoded secrets
- [ ] Error handling comprehensive

---

## TASK: Agent Client

### 🎯 Objective
Build an A2A-compliant client that:
- Creates DID-based identity
- Discovers and connects to agents
- Performs handshake
- Sends intent requests
- Validates responses

### 📝 Process
Follow the same 10-step process as Agent Server with differences:
- Client INITIATES connections (doesn't listen)
- Uses `ClientHandshakeFSM` (not ServerHandshakeFSM)
- Handle session caching
- Implement discovery

**Reference:** See `reference/examples/agent_client.py`

---

## TASK: Multi-Agent System

### 🎯 Objective
Design and implement 3+ interconnected agents:
- **Agent A:** Data Processor (intents: analyze_csv, compute_stats, filter_data)
- **Agent B:** Translator (intents: translate, detect_language, supported_languages)
- **Agent C:** Orchestrator (calls A & B, coordinates workflows)

### Requirements
- [ ] 3+ agents with unique DIDs
- [ ] Each agent has 3+ intents
- [ ] Agents call each other
- [ ] PEP 8 compliant
- [ ] 80%+ coverage
- [ ] Architecture documented

**Reference:** See `reference/tests/integration/test_e2e.py`

---

## TASK: Protocol Extension

### 🎯 Objective
Extend A2A with new functionality (examples: gRPC transport, discovery, reputation).

### Requirements
- [ ] RFC-style specification
- [ ] Python reference implementation
- [ ] 85%+ test coverage
- [ ] Backward compatibility verified
- [ ] Security analysis

### Submission
1. Create SPEC.md
2. Implement reference version
3. Write tests
4. Document security
5. Create PR

---

## 🔍 TROUBLESHOOTING

| Problem | Solution |
|---------|----------|
| **ImportError: 'a2a'** | `pip install a2a-protocol>=1.0.0` |
| **DID format invalid** | Use `create_did()` from library |
| **Coverage < 80%** | `pytest --cov-report=html` and add tests |
| **Handshake fails** | Check DIDs, signatures, nonces, clocks |
| **Port in use** | `lsof -i :8000` then `kill -9 <PID>` |
| **TLS certificate error** | Dev: `verify_tls=False` / Prod: generate certificate |

---

## ✅ FINAL CHECKLIST

**Code Quality:**
- [ ] `black src/ tests/` passes
- [ ] `mypy src/` clean
- [ ] `flake8 src/ tests/` clean
- [ ] All functions documented
- [ ] Type hints on all public functions
- [ ] No hardcoded credentials
- [ ] No TODO/FIXME comments

**Testing:**
- [ ] `pytest tests/ -v` all pass
- [ ] Coverage >= 80%
- [ ] Unit tests for all public functions
- [ ] Integration tests present
- [ ] Error cases tested

**Documentation:**
- [ ] README.md complete
- [ ] CONTRIBUTING.md present
- [ ] LICENSE present (MIT recommended)
- [ ] requirements.txt updated
- [ ] setup.py configured
- [ ] All code in English

**A2A Compliance:**
- [ ] Uses `a2a-protocol>=1.0.0`
- [ ] DIDs correctly implemented
- [ ] JWS signatures present
- [ ] TLS configuration present
- [ ] Session management implemented
- [ ] Error handling per spec
- [ ] Audit logging present

---

## 🚀 READY TO SUBMIT?

```bash
# Final verification
pytest tests/ -v --cov=src
black src/ tests/
mypy src/
flake8 src/ tests/

# Commit
git add -A
git commit -m "Complete A2A implementation with full tests and docs"

# Push
git push origin main

# Create PR to https://github.com/chorghemaruti64-creator/a2a-protocol
```

---

## 📞 SUPPORT

**Repository:** https://github.com/chorghemaruti64-creator/a2a-protocol

**Key References:**
- `spec/A2A_PROTOCOL_v1.md` — Protocol specification
- `spec/AGENT_IDENTITY.md` — Identity and DID format
- `reference/PROJECT_INTEGRATION_GUIDE.md` — Full integration guide
- `reference/AI_AGENT_COMPLETE_PROMPT.md` — Complete code examples
- `reference/examples/` — Working code samples
- `reference/tests/` — Test patterns

---

**END OF COMPLETE PROMPT**

**Version:** 1.0.0  
**Status:** Production Ready  
**Language:** 100% English

---

# WHAT THIS IS

A2A is a **formal protocol specification and reference implementation for agent-to-agent communication**. It defines:

- **Identity:** Cryptographically bound agent identifiers (DIDs)
- **Discovery:** How agents find each other across networks
- **Transport:** Abstract messaging layer (HTTP, gRPC, WebSocket compatible)
- **Handshake:** Cryptographic verification and policy negotiation
- **Session:** Authenticated, audited request/response lifecycle
- **Policy:** Declarative agent constraints (rate limits, capabilities, permissions)

Think of it as **the HTTP/TLS/DNS for AI agents** — foundational infrastructure enabling millions of autonomous agents to interact safely, verifiably, and at scale.

---

# QUICK START

## For Reference Implementers

1. `git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git`
2. `cd a2a-protocol/reference && pip install -e .`
3. Run tests: `pytest tests/ -v`
4. Study: `reference/examples/simple_agent.py`

## For Protocol Engineers

Read in order:
1. `spec/A2A_PROTOCOL_v1.md` — Protocol definition
2. `spec/AGENT_IDENTITY.md` — Identity format
3. `spec/SECURITY_MODEL.md` — Trust model
4. `docs/ARCHITECTURE.md` — Layered design

---

# 📚 Documentation

- **[PROJECT_INTEGRATION_GUIDE.md](reference/PROJECT_INTEGRATION_GUIDE.md)** - Complete integration guide (5 phases)
- **[AI_AGENT_COMPLETE_PROMPT.md](reference/AI_AGENT_COMPLETE_PROMPT.md)** - Full code examples for all task types
- **[SECURITY.md](SECURITY.md)** - Security policy and best practices
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Production deployment guide

---

# Links

- **GitHub:** https://github.com/chorghemaruti64-creator/a2a-protocol
- **Issues:** https://github.com/chorghemaruti64-creator/a2a-protocol/issues

---

**Status:** ✅ Production Ready (v1.0.0)
**Last Updated:** February 2026
