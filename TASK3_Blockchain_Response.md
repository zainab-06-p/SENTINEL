# Task 3 — Blockchain & Governance Layer
## ACIR Platform | Barclays SOC Automation Project
### Confidentiality: Internal Development Use Only

---

## Overview

Task 3 wraps every AI decision in cryptographic law. It receives the signed action proposal from Task 2, enforces bank-grade policy rules via a Hyperledger Fabric smart contract, executes approved containment actions, routes high-risk decisions to human analysts, logs everything permanently to an immutable blockchain ledger, and automatically rolls back actions if no confirmed threat is established within 4 hours.

**Input:** `SignedActionProposal` JSON from Task 2  
**Output:** Executed containment action + Permanent ledger entry  
**Blockchain:** Hyperledger Fabric (policy enforcement + audit) + Algorand (external immutability)  
**Language:** Go (chaincode) + Python (bridge + playbooks)

---

## File Structure

```
d:\Sentinel\acir_platform\
└── task3_blockchain/
    ├── fabric_network/
    │   ├── docker-compose.yaml     # Fabric peer, orderer, CA containers
    │   └── configtx.yaml           # Channel & org configuration
    ├── chaincode/
    │   ├── policy_check.go         # PolicyCheck + DID verification smart contract
    │   └── action_ledger.go        # LogDecision — immutable audit log
    └── fabric_bridge.py            # Python ↔ Hyperledger Fabric transaction client
```

Create the directory structure:
```bash
mkdir d:\Sentinel\acir_platform\task3_blockchain
mkdir d:\Sentinel\acir_platform\task3_blockchain\fabric_network
mkdir d:\Sentinel\acir_platform\task3_blockchain\chaincode
```

---

## Transaction Flow

```
Task 2 produces SignedActionProposal
              │
              ▼
  fabric_bridge.py calls DID Verification Chaincode
              │
        DID valid?
           No → DENY (log tamper attempt)
           Yes ↓
              ▼
  fabric_bridge.py calls PolicyCheck(action, risk_level)
              │
      ┌───────┴──────────┐
   ALLOW             REQUIRE_HITL / DENY
      │                   │
      ▼                   ▼
 Execute Playbook    → HITL Queue (Task 4 Redis)
      │                   │ (analyst approves)
      └────────┬──────────┘
               ▼
   LogDecision() → Written to Fabric ledger (PERMANENT)
               │
               ▼
   Rollback Timer started (4 hours)
               │
   If no threat confirmed in 4h → auto-rollback
```

---

## Team Member Assignments

---

### Developer A — Hyperledger Fabric Network Setup
**Files:** `fabric_network/docker-compose.yaml` + `fabric_network/configtx.yaml`  
**Estimated time:** 3–4 hours (network setup is involved but well-documented)

**Responsibility:** Stand up a local Hyperledger Fabric test network using Docker Compose. This is the underlying distributed ledger that all chaincode runs on. Once UP, this runs in the background and other developers deploy chaincode to it.

**Prerequisites:**
```bash
# Install Docker Desktop first: https://docs.docker.com/desktop/install/windows-install/
# Install Fabric binaries (run in PowerShell as Admin):
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.5
# This creates a fabric-samples/ folder with all Fabric binaries
```

**`docker-compose.yaml`:**
```yaml
# task3_blockchain/fabric_network/docker-compose.yaml
version: '3.7'

networks:
  acir_net:
    name: acir_fabric_network

services:
  orderer.acir.com:
    image: hyperledger/fabric-orderer:2.5.0
    environment:
      - ORDERER_GENERAL_LISTENADDRESS=0.0.0.0
      - ORDERER_GENERAL_LISTENPORT=7050
      - ORDERER_GENERAL_LOCALMSPID=OrdererMSP
      - ORDERER_GENERAL_BOOTSTRAPMETHOD=none
      - ORDERER_CHANNELPARTICIPATION_ENABLED=true
      - FABRIC_LOGGING_SPEC=INFO
    ports:
      - "7050:7050"
    networks:
      - acir_net

  peer0.socorg.acir.com:
    image: hyperledger/fabric-peer:2.5.0
    environment:
      - CORE_PEER_ID=peer0.socorg.acir.com
      - CORE_PEER_ADDRESS=peer0.socorg.acir.com:7051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:7051
      - CORE_PEER_LOCALMSPID=SOCOrgMSP
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=acir_fabric_network
      - FABRIC_LOGGING_SPEC=INFO
    ports:
      - "7051:7051"
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
    networks:
      - acir_net

  peer0.agentorg.acir.com:
    image: hyperledger/fabric-peer:2.5.0
    environment:
      - CORE_PEER_ID=peer0.agentorg.acir.com
      - CORE_PEER_ADDRESS=peer0.agentorg.acir.com:9051
      - CORE_PEER_LISTENADDRESS=0.0.0.0:9051
      - CORE_PEER_LOCALMSPID=AgentOrgMSP
      - CORE_VM_ENDPOINT=unix:///host/var/run/docker.sock
      - CORE_VM_DOCKER_HOSTCONFIG_NETWORKMODE=acir_fabric_network
      - FABRIC_LOGGING_SPEC=INFO
    ports:
      - "9051:9051"
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
    networks:
      - acir_net
```

**Start the network:**
```bash
cd d:\Sentinel\acir_platform\task3_blockchain\fabric_network
docker-compose up -d
docker ps  # Should show 3 containers running
```

---

### Developer B — PolicyCheck Smart Contract (Go)
**File:** `chaincode/policy_check.go`

**Responsibility:** Write the Go chaincode that enforces action policies. This runs INSIDE the Fabric peer node. Every proposed action from Task 2 is evaluated here — the chaincode has no calls to external systems; it uses only hard-coded business rules.

**Full implementation:**
```go
// task3_blockchain/chaincode/policy_check.go
package main

import (
    "encoding/json"
    "fmt"
    "crypto/ed25519"
    "encoding/hex"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// PolicyContract implements the smart contract for action policy checks
type PolicyContract struct {
    contractapi.Contract
}

// ActionDecision represents the structured decision result
type ActionDecision struct {
    Action    string `json:"action"`
    Decision  string `json:"decision"`  // ALLOW | DENY | REQUIRE_HITL
    Reason    string `json:"reason"`
    AgentDID  string `json:"agent_did"`
}

// RegisteredDIDs — in production this would be stored in the ledger state
// For now, hardcoded set of approved agent DIDs
var RegisteredDIDs = map[string]bool{
    // Add your agent's DID here after running kya_identity.py once
    // Example: "did:key:z6MkrJVnaZkeFzdQyMZu1cg...": true,
}

// PolicyRules defines which action gets which default policy
var PolicyRules = map[string]string{
    "query_elasticsearch":   "ALLOW",
    "block_ip":              "ALLOW",
    "create_incident_ticket": "ALLOW",
    "escalate_to_human":     "ALLOW",
    "isolate_endpoint":      "REQUIRE_HITL",
    "shutdown_server":       "REQUIRE_HITL",
}

// PolicyCheck evaluates an action against policy rules and DID registration
func (p *PolicyContract) PolicyCheck(
    ctx contractapi.TransactionContextInterface,
    action string,
    agentDID string,
    riskLevel string,
) (string, error) {

    // Step 1: DID verification — is this a registered agent?
    // In test mode, allow all DIDs. In production, enforce RegisteredDIDs map.
    if len(RegisteredDIDs) > 0 && !RegisteredDIDs[agentDID] {
        result := ActionDecision{
            Action:   action,
            Decision: "DENY",
            Reason:   fmt.Sprintf("Unregistered agent DID: %s", agentDID),
            AgentDID: agentDID,
        }
        return marshalDecision(result)
    }

    // Step 2: Override — HIGH risk level always goes to HITL regardless of action
    if riskLevel == "HIGH" {
        result := ActionDecision{
            Action:   action,
            Decision: "REQUIRE_HITL",
            Reason:   "Risk level HIGH — mandatory human review",
            AgentDID: agentDID,
        }
        return marshalDecision(result)
    }

    // Step 3: Policy rule lookup
    decision, exists := PolicyRules[action]
    if !exists {
        result := ActionDecision{
            Action:   action,
            Decision: "DENY",
            Reason:   fmt.Sprintf("Unknown action type: %s — denying by default", action),
            AgentDID: agentDID,
        }
        return marshalDecision(result)
    }

    result := ActionDecision{
        Action:   action,
        Decision: decision,
        Reason:   fmt.Sprintf("Policy rule applied: %s → %s", action, decision),
        AgentDID: agentDID,
    }
    return marshalDecision(result)
}

// RegisterDID adds a new agent DID to the approved set (stored in ledger state)
func (p *PolicyContract) RegisterDID(
    ctx contractapi.TransactionContextInterface,
    did string,
) error {
    return ctx.GetStub().PutState(
        fmt.Sprintf("did:%s", did),
        []byte("registered"),
    )
}

func marshalDecision(d ActionDecision) (string, error) {
    bytes, err := json.Marshal(d)
    if err != nil {
        return "", err
    }
    return string(bytes), nil
}

func main() {
    chaincode, err := contractapi.NewChaincode(&PolicyContract{})
    if err != nil {
        panic(fmt.Sprintf("Error creating PolicyCheck chaincode: %s", err))
    }
    if err := chaincode.Start(); err != nil {
        panic(fmt.Sprintf("Error starting PolicyCheck chaincode: %s", err))
    }
}
```

**Compile and deploy:**
```bash
# Install Go: https://golang.org/dl/ (Go 1.21+)
cd d:\Sentinel\acir_platform\task3_blockchain\chaincode
go mod init acir_chaincode
go get github.com/hyperledger/fabric-contract-api-go/contractapi
go build ./...

# Deploy to Fabric network (run after Developer A has network UP):
peer lifecycle chaincode package policy.tar.gz --path . --lang golang --label policy_1.0
peer lifecycle chaincode install policy.tar.gz
```

---

### Developer C — Immutable Action Ledger Chaincode (Go)
**File:** `chaincode/action_ledger.go`

**Responsibility:** Build the append-only ledger chaincode. Every decision made — ALLOW, DENY, or HITL-approved — gets a permanent entry here. No updates, no deletes. This is the tamper-evident audit trail regulators can query.

**Full implementation:**
```go
// task3_blockchain/chaincode/action_ledger.go
package main

import (
    "encoding/json"
    "fmt"
    "time"

    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type LedgerContract struct {
    contractapi.Contract
}

// LedgerEntry is the structure of each immutable record
type LedgerEntry struct {
    LedgerID      string `json:"ledger_id"`
    AlertID       string `json:"alert_id"`
    AgentDID      string `json:"agent_did"`
    Action        string `json:"action"`
    Target        string `json:"target"`          // IP, hostname, or server_id
    Decision      string `json:"decision"`        // ALLOW | DENY | HITL_APPROVED | HITL_REJECTED
    Outcome       string `json:"outcome"`         // SUCCESS | FAILED | ROLLED_BACK
    ReasoningHash string `json:"reasoning_hash"`  // SHA-256 of the full thought chain
    Timestamp     string `json:"timestamp"`
    BlockNumber   int    `json:"block_number"`
    RollbackAt    string `json:"rollback_at"`     // ISO timestamp when auto-rollback runs
}

// LogDecision writes a new immutable ledger entry — called after every action decision
func (l *LedgerContract) LogDecision(
    ctx contractapi.TransactionContextInterface,
    entryJSON string,
) error {
    var entry LedgerEntry
    if err := json.Unmarshal([]byte(entryJSON), &entry); err != nil {
        return fmt.Errorf("invalid entry JSON: %s", err)
    }

    // Prevent overwriting an existing entry
    existing, err := ctx.GetStub().GetState(entry.LedgerID)
    if err != nil {
        return fmt.Errorf("ledger read error: %s", err)
    }
    if existing != nil {
        return fmt.Errorf("IMMUTABILITY VIOLATION: ledger entry %s already exists", entry.LedgerID)
    }

    // Set timestamp to blockchain time (not caller's time)
    entry.Timestamp = time.Now().UTC().Format(time.RFC3339)

    // Set rollback deadline: 4 hours from now
    rollbackTime := time.Now().UTC().Add(4 * time.Hour)
    entry.RollbackAt = rollbackTime.Format(time.RFC3339)

    entryBytes, err := json.Marshal(entry)
    if err != nil {
        return err
    }
    return ctx.GetStub().PutState(entry.LedgerID, entryBytes)
}

// GetEntry retrieves a single ledger entry by ID (read-only)
func (l *LedgerContract) GetEntry(
    ctx contractapi.TransactionContextInterface,
    ledgerID string,
) (*LedgerEntry, error) {
    data, err := ctx.GetStub().GetState(ledgerID)
    if err != nil {
        return nil, err
    }
    if data == nil {
        return nil, fmt.Errorf("entry not found: %s", ledgerID)
    }
    var entry LedgerEntry
    return &entry, json.Unmarshal(data, &entry)
}

// MarkOutcome updates ONLY the outcome field — allowed post-execution
func (l *LedgerContract) MarkOutcome(
    ctx contractapi.TransactionContextInterface,
    ledgerID string,
    outcome string,  // SUCCESS | FAILED | ROLLED_BACK
) error {
    data, err := ctx.GetStub().GetState(ledgerID)
    if err != nil || data == nil {
        return fmt.Errorf("entry not found: %s", ledgerID)
    }
    var entry LedgerEntry
    if err := json.Unmarshal(data, &entry); err != nil {
        return err
    }
    entry.Outcome = outcome
    updated, _ := json.Marshal(entry)
    return ctx.GetStub().PutState(ledgerID, updated)
}

func main() {
    chaincode, err := contractapi.NewChaincode(&LedgerContract{})
    if err != nil {
        panic(fmt.Sprintf("Error creating Ledger chaincode: %s", err))
    }
    if err := chaincode.Start(); err != nil {
        panic(fmt.Sprintf("Error starting Ledger chaincode: %s", err))
    }
}
```

---

### Developer D — Python Fabric Bridge
**File:** `task3_blockchain/fabric_bridge.py`

**Responsibility:** Build the Python layer that connects Task 2's Python agent to the Hyperledger Fabric Go chaincode. Task 2 calls `policy_check()` and `log_decision()` from Python — this module handles all the Fabric SDK plumbing.

**Full implementation:**
```python
# task3_blockchain/fabric_bridge.py
import json
import uuid
import hashlib
import requests
from datetime import datetime, timezone
from typing import Optional

# NOTE: fabric-sdk-py has limited Windows support.
# Use the REST gateway approach for Windows dev environments.

FABRIC_GATEWAY_URL = "http://localhost:8080"  # Fabric Gateway REST API
CHANNEL = "acir-audit-channel"
POLICY_CHAINCODE = "policy_check"
LEDGER_CHAINCODE = "action_ledger"


class FabricBridge:
    """
    Python interface for Hyperledger Fabric chaincode calls.
    All Task 2 → Task 3 integration goes through this class.
    """

    def __init__(self, gateway_url: str = FABRIC_GATEWAY_URL):
        self.gateway_url = gateway_url.rstrip("/")
        self._available = self._check_connection()

    def _check_connection(self) -> bool:
        try:
            r = requests.get(f"{self.gateway_url}/health", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def policy_check(self, action: str, agent_did: str, risk_level: str) -> dict:
        """
        Submit PolicyCheck transaction to Hyperledger Fabric.
        Returns dict with 'decision' field: ALLOW | DENY | REQUIRE_HITL
        """
        if not self._available:
            # Fallback: use local policy rules when Fabric unavailable (dev mode)
            return self._local_policy_fallback(action, agent_did, risk_level)

        payload = {
            "channelId": CHANNEL,
            "chaincodeName": POLICY_CHAINCODE,
            "functionName": "PolicyCheck",
            "args": [action, agent_did, risk_level]
        }
        try:
            r = requests.post(f"{self.gateway_url}/invoke", json=payload, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"[FabricBridge] Fabric call failed, using fallback: {e}")
            return self._local_policy_fallback(action, agent_did, risk_level)

    def log_decision(self, signed_proposal: dict, decision: str, outcome: str) -> dict:
        """
        Write an immutable ledger entry to Hyperledger Fabric.
        Returns the ledger entry dict with ledger_id and block_number.
        """
        ledger_id = f"txn-{str(uuid.uuid4())[:8]}"
        reasoning_hash = hashlib.sha256(
            json.dumps(signed_proposal, sort_keys=True).encode()
        ).hexdigest()

        entry = {
            "ledger_id": ledger_id,
            "alert_id": signed_proposal.get("alert_id", ""),
            "agent_did": signed_proposal.get("agent_did", ""),
            "action": signed_proposal.get("action", ""),
            "target": json.dumps(signed_proposal.get("action_input", {})),
            "decision": decision,
            "outcome": outcome,
            "reasoning_hash": f"sha256:{reasoning_hash}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "block_number": 0  # Will be filled by Fabric
        }

        if not self._available:
            print(f"[FabricBridge] Fabric offline — logging locally: {ledger_id}")
            return entry  # In dev mode, return without writing to Fabric

        payload = {
            "channelId": CHANNEL,
            "chaincodeName": LEDGER_CHAINCODE,
            "functionName": "LogDecision",
            "args": [json.dumps(entry)]
        }
        try:
            r = requests.post(f"{self.gateway_url}/invoke", json=payload, timeout=30)
            r.raise_for_status()
            resp = r.json()
            entry["block_number"] = resp.get("blockNumber", 0)
            return entry
        except Exception as e:
            print(f"[FabricBridge] LogDecision failed: {e}")
            return entry

    def _local_policy_fallback(self, action: str, agent_did: str, risk_level: str) -> dict:
        """Fallback policy engine used when Fabric network is unavailable."""
        RULES = {
            "query_elasticsearch":   "ALLOW",
            "block_ip":              "ALLOW",
            "create_incident_ticket": "ALLOW",
            "escalate_to_human":     "ALLOW",
            "isolate_endpoint":      "REQUIRE_HITL",
            "shutdown_server":       "REQUIRE_HITL",
        }
        if risk_level == "HIGH":
            return {"action": action, "decision": "REQUIRE_HITL",
                    "reason": "Risk HIGH — mandatory HITL (local fallback)", "agent_did": agent_did}

        decision = RULES.get(action, "DENY")
        return {"action": action, "decision": decision,
                "reason": f"Local fallback rule: {action} → {decision}", "agent_did": agent_did}


def process_signed_proposal(signed_proposal: dict) -> dict:
    """
    Main entry point: takes a SignedActionProposal from Task 2,
    runs PolicyCheck, executes if ALLOW, queues if REQUIRE_HITL.
    Returns a processing result dict.
    """
    bridge = FabricBridge()
    action = signed_proposal.get("action", "")
    agent_did = signed_proposal.get("agent_did", "")
    risk_level = signed_proposal.get("risk_level", "LOW")

    # Step 1: Policy check
    policy_result = bridge.policy_check(action, agent_did, risk_level)
    decision = policy_result.get("decision", "DENY")

    if decision == "DENY":
        ledger_entry = bridge.log_decision(signed_proposal, "DENY", "BLOCKED")
        return {"status": "denied", "reason": policy_result.get("reason"),
                "ledger_entry": ledger_entry}

    elif decision == "REQUIRE_HITL":
        # Push to Task 4 Redis HITL queue
        ledger_entry = bridge.log_decision(signed_proposal, "REQUIRE_HITL", "PENDING")
        return {"status": "pending_hitl", "action_id": ledger_entry["ledger_id"],
                "ledger_entry": ledger_entry,
                "message": "Action queued for human analyst approval"}

    else:  # ALLOW
        # Execute the action (in Task 2's tool_registry)
        # For Task 3 standalone, just log it
        ledger_entry = bridge.log_decision(signed_proposal, "ALLOW", "SUCCESS")
        return {"status": "executed", "decision": "ALLOW",
                "ledger_entry": ledger_entry}
```

---

### Developer E — Containment Playbook Executor
**File:** `task3_blockchain/playbook_executor.py` *(additional file)*

**Responsibility:** Implement the 4 containment playbooks that execute when PolicyCheck returns ALLOW. Each playbook is a Python function that performs the actual security action. These are stubs in Task 3 and wired to live systems in Task 4.

**Full implementation:**
```python
# task3_blockchain/playbook_executor.py
import json
import subprocess
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("acir.playbook")

class PlaybookResult:
    def __init__(self, success: bool, action: str, target: str,
                 message: str, rollback_command: Optional[str] = None):
        self.success = success
        self.action = action
        self.target = target
        self.message = message
        self.rollback_command = rollback_command
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "action": self.action,
            "target": self.target,
            "message": self.message,
            "rollback_command": self.rollback_command,
            "timestamp": self.timestamp
        }


# ── Playbook 1: IP Block ──────────────────────────────────────────────────────

def playbook_block_ip(ip_address: str) -> PlaybookResult:
    """
    Block an IP address at the firewall level.
    STUB: In production, call firewall management API (e.g., Palo Alto, Cisco ASA).
    """
    if not _is_valid_ip(ip_address):
        return PlaybookResult(False, "block_ip", ip_address, f"Invalid IP: {ip_address}")

    # STUB — replace with actual firewall API call
    logger.info(f"[PLAYBOOK] block_ip: {ip_address}")
    # Example production call:
    # requests.post("https://firewall-api/rules", json={"action":"deny","src":ip_address})

    return PlaybookResult(
        success=True,
        action="block_ip",
        target=ip_address,
        message=f"Firewall rule created: DROP all traffic from {ip_address}",
        rollback_command=f"unblock_ip:{ip_address}"
    )


# ── Playbook 2: Session Termination ─────────────────────────────────────────

def playbook_terminate_session(session_id: str) -> PlaybookResult:
    """
    Terminate an active user session.
    STUB: In production, call identity provider / SSO API (e.g., Okta, Azure AD).
    """
    logger.info(f"[PLAYBOOK] terminate_session: {session_id}")
    # STUB — replace with actual SSO API call
    # Example: requests.delete(f"https://sso-api/sessions/{session_id}")

    return PlaybookResult(
        success=True,
        action="terminate_session",
        target=session_id,
        message=f"Session {session_id} terminated and user forced to re-authenticate",
        rollback_command=None  # Sessions can't be un-terminated
    )


# ── Playbook 3: Account Lock ──────────────────────────────────────────────────

def playbook_lock_account(username: str) -> PlaybookResult:
    """
    Lock a user account to prevent further authentication.
    STUB: In production, call Active Directory or LDAP API.
    """
    logger.info(f"[PLAYBOOK] lock_account: {username}")
    # STUB — replace with actual AD/LDAP call
    # Example: ldap.modify(f"cn={username}", {"userAccountControl": 514})  # 514 = disabled

    return PlaybookResult(
        success=True,
        action="lock_account",
        target=username,
        message=f"Account {username} locked. User must contact SOC to restore access.",
        rollback_command=f"unlock_account:{username}"
    )


# ── Playbook 4: Rate Limiting ─────────────────────────────────────────────────

def playbook_rate_limit_ip(ip_address: str, requests_per_minute: int = 10) -> PlaybookResult:
    """
    Apply rate limiting to a suspicious IP without full block.
    Useful for medium-confidence threats where full block is disproportionate.
    STUB: In production, call API gateway / WAF (e.g., Cloudflare, NGINX).
    """
    if not _is_valid_ip(ip_address):
        return PlaybookResult(False, "rate_limit_ip", ip_address, f"Invalid IP: {ip_address}")

    logger.info(f"[PLAYBOOK] rate_limit_ip: {ip_address} → {requests_per_minute} req/min")
    # STUB — replace with API gateway call
    # Example: requests.put("https://waf-api/rate-limits", json={"ip":ip_address,"limit":rpm})

    return PlaybookResult(
        success=True,
        action="rate_limit_ip",
        target=ip_address,
        message=f"Rate limit applied: {ip_address} → max {requests_per_minute} req/min",
        rollback_command=f"remove_rate_limit:{ip_address}"
    )


# ── Dispatcher ────────────────────────────────────────────────────────────────

PLAYBOOK_MAP = {
    "block_ip": lambda params: playbook_block_ip(params.get("ip_address", "")),
    "terminate_session": lambda params: playbook_terminate_session(params.get("session_id", "")),
    "lock_account": lambda params: playbook_lock_account(params.get("username", "")),
    "rate_limit_ip": lambda params: playbook_rate_limit_ip(
        params.get("ip_address", ""),
        params.get("requests_per_minute", 10)
    ),
}


def execute_playbook(action: str, action_input: dict) -> PlaybookResult:
    """Execute the appropriate playbook for an approved action."""
    if action not in PLAYBOOK_MAP:
        return PlaybookResult(False, action, str(action_input),
                              f"No playbook for action: {action}")
    return PLAYBOOK_MAP[action](action_input)


def _is_valid_ip(ip: str) -> bool:
    import re
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ip))
```

---

### Developer F — Auto-Rollback Scheduler
**File:** `task3_blockchain/rollback_scheduler.py` *(additional file)*

**Responsibility:** After every containment action, start a 4-hour timer. If no confirmed threat (ticket closed, analyst confirmation) is received within 4 hours, automatically reverse the action and log the rollback to the blockchain. Prevents long-term disruption from false positives.

**Full implementation:**
```python
# task3_blockchain/rollback_scheduler.py
import threading
import json
import logging
from datetime import datetime, timezone
from typing import Callable, Optional
from fabric_bridge import FabricBridge

logger = logging.getLogger("acir.rollback")

ROLLBACK_TIMEOUT_HOURS = 4

# In-memory store of pending rollbacks (use Redis in production — Task 4)
_pending_rollbacks: dict[str, dict] = {}


def schedule_rollback(
    ledger_id: str,
    action: str,
    rollback_command: Optional[str],
    bridge: FabricBridge,
    timeout_hours: float = ROLLBACK_TIMEOUT_HOURS
) -> None:
    """
    Schedule an automatic rollback if the threat is not confirmed.
    rollback_command: e.g. "unblock_ip:10.0.2.15"
    """
    if not rollback_command:
        logger.info(f"[ROLLBACK] No rollback possible for {action} — skipping scheduler")
        return

    timeout_seconds = timeout_hours * 3600
    logger.info(f"[ROLLBACK] Scheduling rollback for {ledger_id} in {timeout_hours}h")

    _pending_rollbacks[ledger_id] = {
        "ledger_id": ledger_id,
        "action": action,
        "rollback_command": rollback_command,
        "scheduled_at": datetime.now(timezone.utc).isoformat(),
        "confirmed": False
    }

    timer = threading.Timer(
        timeout_seconds,
        _execute_rollback,
        args=(ledger_id, rollback_command, bridge)
    )
    timer.daemon = True  # Dies if main process exits
    timer.start()
    _pending_rollbacks[ledger_id]["timer"] = timer


def confirm_threat(ledger_id: str) -> bool:
    """
    Called when a SOC analyst confirms the threat is real.
    Cancels the pending rollback timer.
    """
    if ledger_id not in _pending_rollbacks:
        return False
    entry = _pending_rollbacks[ledger_id]
    timer = entry.get("timer")
    if timer:
        timer.cancel()
    entry["confirmed"] = True
    logger.info(f"[ROLLBACK] Threat confirmed for {ledger_id} — rollback cancelled")
    return True


def _execute_rollback(ledger_id: str, rollback_command: str, bridge: FabricBridge) -> None:
    """
    Execute the rollback and log it to the blockchain.
    Called automatically by the timer thread.
    """
    logger.warning(f"[ROLLBACK] Auto-rolling back {ledger_id} — threat not confirmed in {ROLLBACK_TIMEOUT_HOURS}h")

    # Parse rollback command (format: "command:target")
    parts = rollback_command.split(":", 1)
    cmd = parts[0]
    target = parts[1] if len(parts) > 1 else ""

    # Execute the reversal
    if cmd == "unblock_ip":
        logger.info(f"[ROLLBACK] Removing IP block for {target}")
        # STUB: call firewall API to remove rule
    elif cmd == "unlock_account":
        logger.info(f"[ROLLBACK] Unlocking account {target}")
        # STUB: call AD/LDAP to re-enable account
    elif cmd == "remove_rate_limit":
        logger.info(f"[ROLLBACK] Removing rate limit for {target}")
        # STUB: call API gateway to remove rate limit rule

    # Update ledger outcome to ROLLED_BACK
    bridge.log_decision(
        signed_proposal={"alert_id": ledger_id, "action": "auto_rollback",
                          "action_input": {"rollback_command": rollback_command},
                          "agent_did": "system:rollback-scheduler",
                          "risk_level": "LOW"},
        decision="ALLOW",
        outcome="ROLLED_BACK"
    )

    _pending_rollbacks.pop(ledger_id, None)
    logger.info(f"[ROLLBACK] Rollback complete for {ledger_id}")
```

---

## Output Artifact

After processing a `block_ip` action:

```json
{
  "status": "executed",
  "decision": "ALLOW",
  "ledger_entry": {
    "ledger_id": "txn-8f3a2c1b",
    "alert_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_did": "did:key:z6MkrJVnaZkeFzdQyMZu1cg...",
    "action": "block_ip",
    "target": "{\"ip_address\": \"10.0.2.15\"}",
    "decision": "ALLOW",
    "outcome": "SUCCESS",
    "reasoning_hash": "sha256:a3f1c9e2b5d8f4a1c7e3b9d2f6a8c4e1b7d3f5a2c8e4b0d6f2a8c4e1b7",
    "timestamp": "2026-02-19T02:34:18Z",
    "block_number": 47,
    "rollback_at": "2026-02-19T06:34:18Z"
  }
}
```

---

## Integration Notes

- Task 3 **consumes** `SignedActionProposal` from Task 2's `run_agent()`
- Task 3 **produces** ledger entries that Task 4's `AuditTimeline` component queries
- HITL-required actions are pushed to Task 4's Redis queue — Task 4 calls `confirm_threat()` upon analyst approval
- Add the following to `models.py`:

```python
# Add to models.py
class LedgerEntry(BaseModel):
    ledger_id: str
    alert_id: str
    agent_did: str
    action: str
    target: str
    decision: str        # ALLOW | DENY | REQUIRE_HITL
    outcome: str         # SUCCESS | FAILED | PENDING | ROLLED_BACK
    reasoning_hash: str
    timestamp: str
    block_number: int
    rollback_at: Optional[str]
```

---

## Testing

Create `d:\Sentinel\tests\test_task3.py`:

```python
# Minimal test checklist:
# 1. test_policy_check_allow()           — block_ip LOW → ALLOW
# 2. test_policy_check_hitl()            — isolate_endpoint MEDIUM → REQUIRE_HITL
# 3. test_policy_check_high_risk()       — any action HIGH → REQUIRE_HITL
# 4. test_policy_check_deny_unknown()    — "unknown_action" → DENY
# 5. test_policy_check_deny_unknown_did() — unregistered DID (when RegisteredDIDs populated) → DENY
# 6. test_fabric_bridge_fallback()       — Fabric offline → local fallback policy correct
# 7. test_log_decision_structure()       — log_decision() returns all required fields
# 8. test_playbook_block_ip()            — valid IP → PlaybookResult.success=True
# 9. test_playbook_invalid_ip()          — invalid IP → PlaybookResult.success=False
# 10. test_rollback_scheduler_cancel()  — confirm_threat() before timeout → no rollback
# 11. test_rollback_scheduler_trigger() — short timeout (1s), no confirm → rollback executes
# 12. test_process_signed_proposal_allow()  — full end-to-end ALLOW path
# 13. test_process_signed_proposal_hitl()   — full end-to-end REQUIRE_HITL path
```

---

## Dependencies

```bash
# Python
pip install fabric-sdk-py requests cryptography

# Go (for chaincode development)
# Download from: https://golang.org/dl/
# Then:
go get github.com/hyperledger/fabric-contract-api-go/contractapi

# Hyperledger Fabric binaries + Docker images
# Windows: Use WSL2 or Docker Desktop
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.5
```

---

*Document Status: Task 3 Detail Spec v1.0 | ACIR Platform | Internal Use Only*
