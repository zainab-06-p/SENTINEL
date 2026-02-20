# ACIR Platform — Full Implementation Plan

**Project:** Autonomous Cyber Incident Response (ACIR) Platform  
**Target:** Barclays Banking Sector  
**Document Version:** 1.0  
**Status:** Active Development Roadmap  
**Confidentiality:** Internal Use Only

---

## Project Philosophy

> "Private-Brain, Permanent-Memory" — The AI reasons at machine speed. The blockchain remembers forever.

The build is split into **4 sequential tasks**. Each task produces a fully testable artifact before the next begins. Nothing is built in isolation — every component feeds the next.

**LLM Strategy:** Google Colab (T4 GPU) + Llama 3.1 8B Instruct (or DeepSeek-R1 8B) during development. Migrates to local Ollama for production deployment.

---

## Tech Stack (Full Reference)

| Category | Tools & Frameworks |
|---|---|
| Agentic AI | LangGraph, LangChain, HuggingFace Transformers, Ollama |
| LLM (Dev) | Llama 3.1 8B / DeepSeek-R1 8B via Google Colab |
| LLM (Prod) | Llama 3.1 70B via local Ollama (air-gapped) |
| Data Intelligence | PyOD (Isolation Forest + ECOD), tsfresh, Elasticsearch |
| Security & Privacy | Microsoft Presidio (PII scrubbing), Python Cryptography |
| Blockchain | Hyperledger Fabric, Go (Chaincode), W3C DIDs |
| Backend API | FastAPI, Uvicorn, Redis |
| Frontend | React, Axios, Recharts |
| Infrastructure | Docker, ngrok (dev tunnel), Pydantic |

---

## Overall Architecture Flow

```
Raw Security Logs (SIEM / EDR / Network)
            │
            ▼
┌─────────────────────────────┐
│  TASK 1 — Ingestion Layer   │
│  Elasticsearch → PyOD       │
│  Presidio PII Scrubber      │
│  → High-Priority Alert JSON │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  TASK 2 — Agentic AI Core   │
│  LangGraph ReAct Loop       │
│  Observe → Think → Act      │
│  LLM: Colab / Ollama        │
│  KYA DID Signing            │
│  → Signed Action Proposal   │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  TASK 3 — Blockchain Layer  │
│  Hyperledger Fabric         │
│  Smart Contract PolicyCheck │
│  → ALLOW / DENY / HITL      │
│  Immutable Audit Ledger     │
└─────────────┬───────────────┘
              │
              ▼
┌─────────────────────────────┐
│  TASK 4 — Interface Layer   │
│  FastAPI Backend            │
│  Redis HITL Queue           │
│  React Dashboard            │
│  → Live Threat Visibility   │
└─────────────────────────────┘
```

---

## Task 1 — Data Ingestion & Anomaly Detection

**Goal:** Build the pipeline that converts raw logs into clean, ranked, privacy-safe alerts.

### What to Build

| Component | Description |
|---|---|
| Log Simulator | Python script generating synthetic SIEM/EDR/Network logs with injected attack patterns (brute force, lateral movement, late-night DB scraping) |
| Elasticsearch | Local Docker instance indexing all logs. Index mappings for: `timestamp`, `source_ip`, `event_type`, `severity`, `raw_payload` |
| PyOD Anomaly Engine | Isolation Forest + ECOD ensemble. Assigns each log a numerical risk score. Only top `RISK_THRESHOLD` (top 5%) are promoted |
| PII Scrubber | Microsoft Presidio strips account numbers, customer names, card data before any log touches the AI |
| tsfresh Feature Extractor | Extracts time-series features: login frequency bursts, inter-event timing deltas, session entropy |

### File Structure

```
acir_platform/
└── task1_ingestion/
    ├── log_simulator.py        # Generates synthetic attack logs
    ├── elasticsearch_client.py # Docker ES connection + index setup
    ├── anomaly_engine.py       # PyOD scoring pipeline
    ├── pii_scrubber.py         # Presidio anonymization wrapper
    ├── feature_extractor.py    # tsfresh time-series features
    └── ingestion_pipeline.py   # Orchestrates all above into one flow
```

### Output Artifact

A clean `HighPriorityAlert` Pydantic object emitted for every anomaly exceeding the risk threshold:

```json
{
  "alert_id": "uuid-1234",
  "timestamp": "2026-02-19T02:34:11Z",
  "source_ip": "10.0.2.15",
  "event_type": "db_query_burst",
  "risk_score": 0.97,
  "scrubbed_payload": "User [REDACTED] executed 847 SELECT queries in 90 seconds",
  "features": { "query_rate_per_min": 565, "session_entropy": 0.12 }
}
```

### Key Dependencies

```
pip install pyod elasticsearch presidio-analyzer presidio-anonymizer tsfresh pydantic faker
```

### Docker Command (Elasticsearch)

```bash
docker run -d --name es-acir -p 9200:9200 -e "discovery.type=single-node" elasticsearch:8.13.0
```

---

## Task 2 — Agentic AI Core (ReAct Brain)

**Goal:** Build the autonomous reasoning engine that observes alerts, thinks through context, and proposes cryptographically signed remediation actions.

### What to Build

| Component | Description |
|---|---|
| LLM Server (Colab) | Llama 3.1 8B or DeepSeek-R1 8B hosted via HuggingFace Transformers + FastAPI + ngrok on Google Colab T4 GPU |
| LangGraph ReAct Orchestrator | Stateful graph with 3 nodes: `Observe`, `Think`, `Act`. Implements the full ReAct (Observation → Thought → Action) reasoning loop |
| Tool Registry | 6 cybersecurity tools registered with the agent (see table below) |
| Shadow Prompt Detector | Scans LLM input/output for prompt injection patterns before and after inference |
| KYA DID Identity | W3C Decentralized Identifier generated for the agent. Every action proposal is SHA-256 hashed and signed with the agent's Ed25519 private key |
| LLM Config Factory | `get_llm()` factory that switches between Colab endpoint and local Ollama via a single config value |

### Tool Registry

| Tool | Risk Level | Auto-Executable | Description |
|---|---|---|---|
| `query_elasticsearch(query)` | LOW | Yes | Read-only log search |
| `block_ip(ip_address)` | LOW | Yes | Firewall rule addition |
| `create_incident_ticket(summary)` | LOW | Yes | SOC ticket creation |
| `isolate_endpoint(hostname)` | MEDIUM | Yes (with policy check) | Network isolation |
| `shutdown_server(server_id)` | HIGH | No — HITL Required | Core server shutdown |
| `escalate_to_human(reason)` | LOW | Yes | Manual SOC escalation |

### LangGraph Node Flow

```
[START]
   │
   ▼
[Observe Node] ← Receives HighPriorityAlert from Task 1
   │             Formats it as structured context
   ▼
[Think Node]  ← Sends context + system prompt to LLM
   │             LLM returns: thought + action + action_input + risk_level
   ▼
[Act Node]    ← Checks risk_level
   │             LOW/MEDIUM → proceeds to Task 3 PolicyCheck
   │             HIGH       → immediately routes to HITL queue
   ▼
[Shadow Prompt Check] ← Validates no injection in LLM output
   │
   ▼
[Sign Action] ← KYA DID signs the action proposal with Ed25519
   │
   ▼
[Output: SignedActionProposal] → Sent to Task 3
```

### File Structure

```
acir_platform/
└── task2_agent/
    ├── colab_inference_server.ipynb  # Colab notebook (runs on Google Colab)
    ├── llm_client.py                 # ColabLLM + OllamaLLM factory
    ├── react_graph.py                # LangGraph ReAct node definitions
    ├── tool_registry.py              # All 6 tools (stubbed, wired in Task 4)
    ├── shadow_prompt_detector.py     # Prompt injection guard
    ├── kya_identity.py               # W3C DID + Ed25519 signing
    └── config.py                     # LLM_MODE, endpoints, thresholds
```

### System Prompt Skeleton

```python
ACIR_SYSTEM_PROMPT = """
You are ACIR-Agent, an autonomous cybersecurity AI in a bank's SOC.
Always respond in strict JSON:
{
  "thought": "your internal reasoning",
  "action": "tool_name",
  "action_input": { "param": "value" },
  "risk_level": "LOW | MEDIUM | HIGH"
}
Rules: Never fabricate data. If uncertain, use escalate_to_human.
Shutdown actions always require risk_level = HIGH.
"""
```

### Output Artifact

```json
{
  "alert_id": "uuid-1234",
  "thought": "IP 10.0.2.15 executed 847 DB queries at 2AM — anomalous pattern consistent with data exfiltration.",
  "action": "block_ip",
  "action_input": { "ip_address": "10.0.2.15" },
  "risk_level": "LOW",
  "agent_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "signature": "3045022100...",
  "action_hash": "sha256:a3f1c9..."
}
```

### Key Dependencies

```
pip install langchain langgraph langchain-community cryptography requests
```

---

## Task 3 — Blockchain & Governance Layer

**Goal:** Wrap every AI action in cryptographic law — immutable audit, policy enforcement, and identity verification.

### What to Build

| Component | Description |
|---|---|
| Hyperledger Fabric Network | Local Docker-based Fabric test network. 1 channel: `acir-audit-channel`. 2 orgs: `SOCOrg` and `AgentOrg` |
| PolicyCheck Chaincode (Go) | Smart contract that evaluates proposed actions against hard-coded rules. Returns `ALLOW`, `DENY`, or `REQUIRE_HITL` |
| DID Verification Chaincode (Go) | Verifies the agent's KYA DID signature before any write to the ledger |
| Immutable Action Ledger Chaincode (Go) | `LogDecision()` stores the SHA-256 hash of the full reasoning chain. Append-only. No delete, no update |
| Python Fabric Bridge | Lightweight Python client that Task 2's agent calls to submit transactions and query chaincode |

### Smart Contract Policy Rules

```go
// PolicyCheck examples (Go Chaincode)
func PolicyCheck(action string, agentDID string) string {
    rules := map[string]string{
        "block_ip":           "ALLOW",
        "query_elasticsearch": "ALLOW",
        "create_incident_ticket": "ALLOW",
        "isolate_endpoint":   "REQUIRE_HITL",
        "shutdown_server":    "REQUIRE_HITL",
        "escalate_to_human":  "ALLOW",
    }
    // Additional check: DID must be registered
    if !IsRegisteredDID(agentDID) {
        return "DENY"
    }
    return rules[action]
}
```

### Transaction Flow

```
Task 2 Agent produces SignedActionProposal
          │
          ▼
Python Fabric Bridge calls PolicyCheck(action, did)
          │
    ┌─────┴──────┐
  ALLOW       REQUIRE_HITL / DENY
    │               │
    ▼               ▼
Execute         → HITL Queue (Task 4)
    │               │ (on approval)
    └───────┬────────┘
            ▼
  LogDecision(thought_hash, action, outcome, timestamp)
  Written to Hyperledger Fabric ledger — PERMANENT
```

### File Structure

```
acir_platform/
└── task3_blockchain/
    ├── fabric_network/
    │   ├── docker-compose.yaml       # Fabric peer, orderer, CA containers
    │   └── configtx.yaml             # Channel & org config
    ├── chaincode/
    │   ├── policy_check.go           # PolicyCheck + DID verification
    │   └── action_ledger.go          # LogDecision (immutable log)
    └── fabric_bridge.py              # Python → Fabric transaction client
```

### Key Dependencies

```bash
# Hyperledger Fabric binaries
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.5

# Python Fabric SDK
pip install fabric-sdk-py
```

### Output Artifact

After a `block_ip` action:
- Chaincode returns `ALLOW`
- Action executes
- Ledger entry written:

```json
{
  "ledger_id": "txn-8f3a2c",
  "agent_did": "did:key:z6Mk...",
  "action": "block_ip",
  "target": "10.0.2.15",
  "outcome": "SUCCESS",
  "reasoning_hash": "sha256:a3f1c9...",
  "timestamp": "2026-02-19T02:34:18Z",
  "block_number": 47
}
```

---

## Task 4 — FastAPI Backend, HITL Workflow & React Dashboard

**Goal:** Wire the entire system together into an operable platform with real-time visibility and human approval controls.

### What to Build

**Backend (FastAPI)**

| Endpoint | Method | Description |
|---|---|---|
| `/ingest` | POST | Receives raw logs, triggers Task 1 pipeline |
| `/alerts` | GET | Returns active high-priority alerts |
| `/agent/status` | GET | Current agent state (Observing / Thinking / Awaiting HITL) |
| `/hitl/pending` | GET | Returns all actions awaiting human approval |
| `/hitl/approve/{action_id}` | POST | Analyst approves a gated action |
| `/hitl/reject/{action_id}` | POST | Analyst rejects with a reason |
| `/audit/trail` | GET | Queries Hyperledger ledger for full decision history |
| `/ws/agent-feed` | WebSocket | Real-time push of agent thought-steps |

**HITL Queue (Redis)**

- Gated actions (`REQUIRE_HITL`) are pushed to a Redis queue with a 5-minute TTL
- If no approval arrives within TTL → agent automatically chooses `escalate_to_human` as fallback
- Approvals trigger the full execution + blockchain log sequence

**React Dashboard — 4 Views**

| View | Description |
|---|---|
| Threat Feed | Live stream of anomaly alerts with risk scores, source IPs, event types |
| Agent Reasoning Panel | Real-time display of the active ReAct loop: Thought → Action → Result |
| HITL Approval Queue | Cards showing pending high-risk actions with `Approve` / `Reject` and countdown timer |
| Audit Timeline | Chronological list of all decisions pulled from the blockchain ledger |

### File Structure

```
acir_platform/
├── task4_interface/
│   ├── backend/
│   │   ├── main.py               # FastAPI app + all route definitions
│   │   ├── hitl_queue.py         # Redis-backed approval queue logic
│   │   ├── websocket_manager.py  # WebSocket connection manager
│   │   └── audit_client.py       # Queries Fabric ledger for audit trail
│   └── frontend/
│       ├── public/
│       └── src/
│           ├── App.jsx
│           ├── components/
│           │   ├── ThreatFeed.jsx          # Live alert stream
│           │   ├── AgentReasoningPanel.jsx # ReAct loop display
│           │   ├── HITLQueue.jsx           # Approval cards
│           │   └── AuditTimeline.jsx       # Blockchain audit view
│           └── services/
│               └── api.js                  # Axios + WebSocket client
```

### Key Dependencies

```bash
# Backend
pip install fastapi uvicorn redis websockets

# Frontend
npx create-react-app frontend
cd frontend && npm install axios recharts react-query
```

### End-to-End Integration Test

A single script that validates the full pipeline:

```python
# test_full_pipeline.py
# 1. Inject a simulated brute-force attack log
# 2. Confirm PyOD scores it above RISK_THRESHOLD
# 3. Confirm agent's ReAct loop produces a signed action
# 4. Confirm Fabric PolicyCheck returns REQUIRE_HITL for isolate_endpoint
# 5. Simulate analyst approving via /hitl/approve
# 6. Confirm action executes
# 7. Confirm blockchain ledger entry is written and retrievable
# 8. Assert all 7 steps complete in < 15 seconds
```

---

## Build Timeline

```
Week 1–2  │  Task 1  │  Log simulator + Elasticsearch + PyOD + Presidio
Week 3–4  │  Task 2  │  Colab LLM server + LangGraph ReAct + KYA DID signing
Week 5–6  │  Task 3  │  Hyperledger Fabric network + Go chaincode + Python bridge
Week 7–8  │  Task 4  │  FastAPI + Redis HITL + React dashboard + integration test
```

---

## Where to Start Right Now

### Step 1 — Environment Setup

```bash
# Install Docker Desktop (needed for Elasticsearch, Fabric, Redis)
# https://docs.docker.com/desktop/install/windows-install/

# Create Python virtual environment
python -m venv acir_env
acir_env\Scripts\activate

# Install Task 1 dependencies
pip install pyod elasticsearch presidio-analyzer presidio-anonymizer tsfresh pydantic faker
```

### Step 2 — Launch Elasticsearch

```bash
docker run -d --name es-acir -p 9200:9200 -e "discovery.type=single-node" elasticsearch:8.13.0
```

### Step 3 — Set Up Colab LLM Server

1. Go to [colab.research.google.com](https://colab.research.google.com)
2. Set runtime to **T4 GPU**
3. Follow the notebook setup in `ACIR_Colab_Model_Strategy.md`
4. Copy the ngrok URL into `config.py`

### Step 4 — Build the Log Simulator

Start here. Every downstream component needs an alert object as input. Build `log_simulator.py` first so you always have test data flowing through the system.

---

## Project Folder Structure (Complete)

```
d:\Sentinel\
├── ACIR_Implementation_Plan.md        ← This document
├── ACIR_Colab_Model_Strategy.md       ← LLM & Colab setup guide
└── acir_platform/
    ├── config.py                      ← Global config (LLM_MODE, thresholds, URLs)
    ├── models.py                      ← Shared Pydantic models (Alert, ActionProposal)
    ├── task1_ingestion/
    │   ├── log_simulator.py
    │   ├── elasticsearch_client.py
    │   ├── anomaly_engine.py
    │   ├── pii_scrubber.py
    │   ├── feature_extractor.py
    │   └── ingestion_pipeline.py
    ├── task2_agent/
    │   ├── colab_inference_server.ipynb
    │   ├── llm_client.py
    │   ├── react_graph.py
    │   ├── tool_registry.py
    │   ├── shadow_prompt_detector.py
    │   └── kya_identity.py
    ├── task3_blockchain/
    │   ├── fabric_network/
    │   │   ├── docker-compose.yaml
    │   │   └── configtx.yaml
    │   ├── chaincode/
    │   │   ├── policy_check.go
    │   │   └── action_ledger.go
    │   └── fabric_bridge.py
    └── task4_interface/
        ├── backend/
        │   ├── main.py
        │   ├── hitl_queue.py
        │   ├── websocket_manager.py
        │   └── audit_client.py
        └── frontend/
            └── src/
                ├── App.jsx
                └── components/
                    ├── ThreatFeed.jsx
                    ├── AgentReasoningPanel.jsx
                    ├── HITLQueue.jsx
                    └── AuditTimeline.jsx
```

---

*Document Status: Final Version 1.0 | Confidentiality: Internal Development Use Only*
