# A2A Protocol v1.0.0 - Agent-to-Agent Communication

A secure, protocol-driven communication framework for autonomous agents with cryptographic identity binding, policy-based access control, and comprehensive audit logging.

---

# 🤖 COMPLETE PROMPT FOR AI AGENTS

**⭐ Copy this entire section and use it directly in any AI agent. No modification needed.**

**Version:** 1.0.0  
**Status:** Production Ready  
**Language:** English (100%)  
**For:** Building A2A Protocol-compliant agents

---

## 📌 Overview

This is a **complete, detailed, error-resistant prompt** for AI agents to implement A2A Protocol-compliant projects. Use this prompt as-is without modification for best results.

**Supported Implementation Types:**
1. Agent Server (listens for requests)
2. Agent Client (calls other agents)
3. Multi-Agent System (3+ agents communicating)
4. Protocol Extension (custom transports, discovery, etc.)

---

## 🎯 Choose Your Task

**IF YOU ARE BUILDING: Agent Server** → Use [TASK: Agent Server](#agent-server-task) below

**IF YOU ARE BUILDING: Agent Client** → Use [TASK: Agent Client](#agent-client-task) below

**IF YOU ARE BUILDING: Multi-Agent System** → Use [TASK: Multi-Agent System](#multi-agent-task) below

**IF YOU ARE BUILDING: Protocol Extension** → Use [TASK: Protocol Extension](#extension-task) below

---

## MANDATORY PREREQUISITES

Before starting ANY task, verify you have:

```bash
# 1. Python 3.10+
python --version  # Must be 3.10 or higher

# 2. Virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Clone the A2A Protocol repository
git clone https://github.com/chorghemaruti64-creator/a2a-protocol.git
cd a2a-protocol

# 4. Install A2A library
pip install -e reference/

# 5. Verify installation
python -c "import a2a; print(f'A2A version: {a2a.__version__}')"
# Output should show: A2A version: 1.0.0 (or similar)

# 6. Navigate to project directory
cd reference
```

**If any step fails, STOP and report the error. Do not continue.**

---

## 📚 REFERENCE DOCUMENTATION

Keep these documents open while working:

| Document | Purpose | Location |
|----------|---------|----------|
| **A2A Protocol Spec** | Core protocol definition | `spec/A2A_PROTOCOL_v1.md` |
| **Agent Identity Spec** | DID format and manifests | `spec/AGENT_IDENTITY.md` |
| **Security Model** | Threat analysis | `spec/SECURITY_MODEL.md` |
| **Project Integration Guide** | Step-by-step integration | `reference/PROJECT_INTEGRATION_GUIDE.md` |
| **Examples** | Working code examples | `reference/examples/` |
| **Tests** | Test patterns | `reference/tests/` |

---

## TASK: Agent Server {#agent-server-task}

### 🎯 Objective
Build an A2A-compliant agent server that:
- Generates and manages a unique DID-based identity
- Listens for incoming A2A handshake requests
- Handles intent requests (goal + parameters)
- Returns properly formatted JSON responses
- Logs all interactions for audit trail

### ✅ Requirements (MANDATORY)

#### Code Quality
- [ ] PEP 8 compliant (use `black` for formatting)
- [ ] Type hints on 100% of public functions
- [ ] Comprehensive docstrings on all functions
- [ ] Error handling for ALL failure paths
- [ ] Async/await for all I/O operations

#### Functionality
- [ ] Use `a2a-protocol>=1.0.0` library
- [ ] Cryptographic signature verification (JWS RFC 7515)
- [ ] Ed25519 key generation and management
- [ ] TLS 1.3 enabled (in production configuration)
- [ ] Support at least 2 custom intents (define them yourself)
- [ ] Proper error responses for all error cases

#### Testing
- [ ] Unit tests for all public functions
- [ ] Integration tests for handshake
- [ ] Integration tests for intent handling
- [ ] Tests for error cases
- [ ] **Minimum 80% code coverage** (verify with `pytest --cov`)
- [ ] All tests MUST PASS

#### Documentation
- [ ] README.md with installation, quick start, intents, testing
- [ ] CONTRIBUTING.md with code standards
- [ ] Docstrings on every function
- [ ] Comments on non-obvious code

#### Security
- [ ] No hardcoded credentials
- [ ] Secrets from environment variables
- [ ] TLS configuration documented
- [ ] No insecure defaults

### 📂 Deliverables (EXACT STRUCTURE)

```
my-a2a-server/
├── src/
│   └── my_server/
│       ├── __init__.py
│       ├── agent.py              # Main agent class
│       ├── identity.py           # DID/manifest management
│       ├── intents/              # Intent handlers
│       │   ├── __init__.py
│       │   ├── echo.py           # Example: echo intent
│       │   └── process.py        # Example: process intent
│       └── errors.py             # Custom exceptions
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── __init__.py
│   │   ├── test_agent.py         # Agent tests
│   │   ├── test_identity.py      # Identity tests
│   │   └── test_intents.py       # Intent handler tests
│   └── integration/
│       ├── __init__.py
│       └── test_e2e.py           # End-to-end tests
├── .gitignore
├── README.md                     # Complete documentation
├── CONTRIBUTING.md              # Code standards
├── LICENSE                       # MIT License
├── requirements.txt              # Dependencies
├── setup.py                      # Package setup
└── pytest.ini                    # Test configuration
```

### 📝 10-Step Implementation Process

#### Step 1: Read Documentation (30 minutes)

```bash
1. Read spec/A2A_PROTOCOL_v1.md sections 1-6
   - Handshake protocol, message formats, security
   
2. Read spec/AGENT_IDENTITY.md
   - DID format, manifest structure, signing
   
3. Read reference/PROJECT_INTEGRATION_GUIDE.md Phase 2
   
4. Study reference/examples/
```

Write down: DID format, handshake sequence, message fields, crypto ops.

#### Step 2: Create Project Structure (15 minutes)

```bash
mkdir -p my-a2a-server/{src/my_server/intents,tests/{unit,integration}}
touch my-a2a-server/src/__init__.py
touch my-a2a-server/src/my_server/__init__.py
touch my-a2a-server/src/my_server/intents/__init__.py
touch my-a2a-server/tests/__init__.py
touch my-a2a-server/tests/unit/__init__.py
touch my-a2a-server/tests/integration/__init__.py
cd my-a2a-server
touch README.md CONTRIBUTING.md LICENSE requirements.txt setup.py pytest.ini .gitignore
```

#### Step 3: Set Up Dependencies (10 minutes)

**requirements.txt:**
```
a2a-protocol>=1.0.0
pydantic>=2.0.0
httpx>=0.25.0
aiohttp>=3.9.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
black>=23.0.0
mypy>=1.0.0
```

```bash
pip install -r requirements.txt
```

#### Step 4-10: Implementation & Testing (6-8 hours)

**See AI_AGENT_COMPLETE_PROMPT.md for full code examples and step-by-step guide.**

Key files to create:
1. `src/my_server/identity.py` - DID management (complete code in PROMPT)
2. `src/my_server/agent.py` - Main server (complete code in PROMPT)
3. `src/my_server/intents/echo.py` - Intent handlers (complete code in PROMPT)
4. `tests/unit/test_agent.py` - Unit tests (complete code in PROMPT)
5. `tests/integration/test_e2e.py` - Integration tests (complete code in PROMPT)
6. `README.md` - Documentation (template in PROMPT)
7. `CONTRIBUTING.md` - Code standards (template in PROMPT)

### ✅ Verification Checklist

- [ ] All tests pass (`pytest tests/ -v`)
- [ ] Code coverage >= 80% (`pytest --cov`)
- [ ] Code formatted (`black src/`)
- [ ] Type checking passes (`mypy src/`)
- [ ] No linting errors (`flake8 src/`)
- [ ] README.md is complete
- [ ] CONTRIBUTING.md exists
- [ ] LICENSE file exists
- [ ] Server starts without errors
- [ ] At least 2 custom intents implemented
- [ ] All intents have unit tests
- [ ] Integration tests pass
- [ ] No hardcoded secrets
- [ ] Error handling is comprehensive

---

## TASK: Agent Client {#agent-client-task}

### 🎯 Objective

Build an A2A-compliant agent client that performs handshakes and calls other agents.

**Follow the same 10-step process as Agent Server** with these differences:
- Client INITIATES connections (doesn't listen)
- Uses `ClientHandshakeFSM` (not ServerHandshakeFSM)
- Must handle session caching
- Must implement discovery (finding other agents)

**Reference:** See `reference/examples/agent_client.py` for complete example.

---

## TASK: Multi-Agent System {#multi-agent-task}

### 🎯 Objective

Design and implement a network of 3+ interconnected A2A agents communicating with each other.

### Example Architecture:
- **Agent A: Data Processor** (intents: analyze_csv, compute_stats, filter_data)
- **Agent B: Translator** (intents: translate, detect_language, supported_languages)
- **Agent C: Orchestrator** (calls A and B, coordinates workflows)

### Requirements:
- [ ] 3+ agents with unique DIDs
- [ ] Each agent has 3+ intents
- [ ] Agents call each other (proof of interoperability)
- [ ] All code follows PEP 8
- [ ] Type hints and docstrings everywhere
- [ ] 80%+ test coverage
- [ ] Architecture and workflow documentation

**Reference:** See `reference/tests/integration/test_e2e.py` for patterns.

---

## TASK: Protocol Extension {#extension-task}

### 🎯 Objective

Extend A2A Protocol with new functionality (examples: gRPC transport, discovery, reputation system).

### Requirements:
- [ ] RFC-style specification document
- [ ] Python reference implementation
- [ ] 85%+ test coverage
- [ ] Backward compatibility verified
- [ ] Security analysis included

### Submission:
1. Create SPEC.md with proposal
2. Implement reference version
3. Write comprehensive tests
4. Document security implications
5. Create PR to main repository

---

## 🔍 DEBUGGING & TROUBLESHOOTING

### "ImportError: No module named 'a2a'"
```bash
pip install a2a-protocol>=1.0.0
python -c "import a2a; print(a2a.__version__)"
```

### "DID format invalid"
Use `create_did()` from library, never hardcode DIDs.

### "Tests fail with coverage < 80%"
```bash
pytest tests/ --cov=src --cov-report=html
# Open htmlcov/index.html to find uncovered lines
```

### "Handshake fails"
Check: DID mismatch, invalid signatures, stale nonces, clock sync.

### "Port already in use"
```bash
lsof -i :8000
kill -9 <PID>
# Or use different port: A2AServer(port=8001)
```

### "TLS certificate error (dev)"
```python
transport = HTTPTransport(verify_tls=False)  # Dev only
```

---

## ✅ FINAL CHECKLIST

Before submitting:

### Code Quality
- [ ] `black src/ tests/` passes
- [ ] `mypy src/` has no errors
- [ ] `flake8 src/ tests/` clean
- [ ] All functions have docstrings
- [ ] Type hints on all public functions
- [ ] No hardcoded credentials
- [ ] No TODO/FIXME comments

### Testing
- [ ] `pytest tests/ -v` all pass
- [ ] Coverage >= 80%
- [ ] Unit tests for all public functions
- [ ] Integration tests present
- [ ] Error cases tested

### Documentation
- [ ] README.md complete
- [ ] CONTRIBUTING.md present
- [ ] LICENSE file present
- [ ] requirements.txt updated
- [ ] setup.py configured
- [ ] All code in English

### A2A Compliance
- [ ] Uses `a2a-protocol>=1.0.0`
- [ ] DIDs correctly implemented
- [ ] JWS signatures present
- [ ] TLS configuration present
- [ ] Session management implemented
- [ ] Error handling per spec
- [ ] Audit logging present

### Repository
- [ ] .gitignore configured
- [ ] No secrets committed
- [ ] Clean commit history
- [ ] README in root directory

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

**Key Files:**
- `spec/A2A_PROTOCOL_v1.md` — Protocol specification
- `spec/AGENT_IDENTITY.md` — Identity and DID format
- `reference/PROJECT_INTEGRATION_GUIDE.md` — Full integration guide
- `reference/AI_AGENT_COMPLETE_PROMPT.md` — Complete code examples
- `reference/examples/` — Working code samples
- `reference/tests/` — Test patterns

**Stuck?**
1. Check `reference/tests/` for test patterns
2. Review `spec/SECURITY_MODEL.md` for security requirements
3. Check `reference/examples/` for code patterns
4. Open issue on GitHub

---

**END OF COMPLETE PROMPT**

**Version:** 1.0.0  
**Last Updated:** February 2026  
**Status:** Production Ready  
**Language:** 100% English

---

# 🚀 Quick Start

## For Protocol Engineers

Read in this order:
1. **spec/A2A_PROTOCOL_v1.md** — Formal protocol definition
2. **spec/AGENT_IDENTITY.md** — Identity and manifest format
3. **spec/SECURITY_MODEL.md** — Trust and threat model
4. **docs/ARCHITECTURE.md** — Layered design

## For Reference Implementers

1. Clone this repository
2. Install dependencies: `pip install -e reference/`
3. Run tests: `cd reference && make test`
4. Study `reference/examples/simple_agent.py`
5. Read `docs/QUICKSTART.md`

## For Infrastructure Operators

1. Read `docs/DEPLOYMENT.md`
2. Review security policies in `SECURITY.md`
3. Understand policy enforcement in `spec/A2A_PROTOCOL_v1.md` (Section 7)

---

# 📚 Documentation

- **[PROJECT_INTEGRATION_GUIDE.md](PROJECT_INTEGRATION_GUIDE.md)** - Complete agent project integration (5 phases, code examples)
- **[AI_AGENT_COMPLETE_PROMPT.md](AI_AGENT_COMPLETE_PROMPT.md)** - Full step-by-step code examples for all task types
- **[THREAT_MODEL.md](THREAT_MODEL.md)** - Security threat analysis and mitigations
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Production deployment guide
- **[CHANGELOG.md](CHANGELOG.md)** - Release notes and version history
- **[EXAMPLE_AGENTS.py](EXAMPLE_AGENTS.py)** - Complete working example

---

# ✅ Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=a2a --cov-report=html
```

---

# 🔗 Links

- **GitHub:** https://github.com/chorghemaruti64-creator/a2a-protocol
- **Repository:** This is the reference implementation
- **Issues:** https://github.com/chorghemaruti64-creator/a2a-protocol/issues

---

**Status:** ✅ Production Ready (v1.0.0)

**Last Updated:** February 2026

**Security Reviewed:** Yes
