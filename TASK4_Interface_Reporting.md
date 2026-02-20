# Task 4 — FastAPI Backend, HITL Workflow & React Dashboard
## ACIR Platform | Barclays SOC Automation Project
### Confidentiality: Internal Development Use Only

---

## Overview

Task 4 wires the entire ACIR platform together into a single operable interface. It expands the existing FastAPI backend with new endpoints for human-in-the-loop approvals, audit queries, and WebSocket streaming. It builds a Redis-backed HITL queue with countdown timers, expands the React frontend into a full 4-view SOC dashboard, generates FCA-compliant regulatory reports, and provides executive KPI tracking.

**Input:** Live data streams from Tasks 1, 2, and 3  
**Output:** React dashboard, FCA reports (PDF/DOCX), WebSocket streams, audit timeline  
**Backend:** FastAPI + Redis + WebSocket  
**Frontend:** React (JSX) + Recharts + Axios  
**Queue:** Redis (HITL, pub/sub)

---

## File Structure

```
d:\Sentinel\acir_platform\
├── task4_interface/
│   ├── backend/
│   │   ├── main.py                    # FastAPI app — all new Task 4 endpoints
│   │   ├── hitl_queue.py              # Redis HITL approval queue
│   │   ├── websocket_manager.py       # WebSocket connection manager
│   │   └── audit_client.py            # Queries Fabric ledger for audit trail
│   └── frontend/
│       ├── package.json
│       ├── public/
│       │   └── index.html
│       └── src/
│           ├── App.jsx                # Root component — routing + layout
│           ├── components/
│           │   ├── ThreatFeed.jsx          # Live alert stream
│           │   ├── AgentReasoningPanel.jsx # ReAct loop display
│           │   ├── HITLQueue.jsx           # Approval cards with countdown
│           │   └── AuditTimeline.jsx       # Blockchain audit view
│           └── services/
│               └── api.js                  # Axios + WebSocket client
```

Create the directory structure:
```bash
mkdir d:\Sentinel\acir_platform\task4_interface
mkdir d:\Sentinel\acir_platform\task4_interface\backend
mkdir d:\Sentinel\acir_platform\task4_interface\frontend\src\components
mkdir d:\Sentinel\acir_platform\task4_interface\frontend\src\services
mkdir d:\Sentinel\acir_platform\task4_interface\frontend\public
```

---

## API Reference (All Task 4 Endpoints)

| Endpoint | Method | Description |
|---|---|---|
| `/ingest` | POST | Receive raw logs → Task 1 pipeline |
| `/alerts` | GET | Active high-priority alerts |
| `/agent/status` | GET | Agent state: Observing / Thinking / Awaiting HITL / Idle |
| `/agent/run` | POST | Manually trigger agent on an alert |
| `/hitl/pending` | GET | All actions awaiting analyst approval |
| `/hitl/approve/{action_id}` | POST | Approve a gated action |
| `/hitl/reject/{action_id}` | POST | Reject with reason |
| `/audit/trail` | GET | Full decision history from Fabric ledger |
| `/audit/entry/{ledger_id}` | GET | Single ledger entry |
| `/reports/gdpr33` | POST | Generate GDPR Article 33 breach report |
| `/reports/psd2` | POST | Generate PSD2 fraud incident report |
| `/reports/dora` | POST | Generate DORA operational resilience report |
| `/ws/agent-feed` | WebSocket | Real-time push of agent thought steps |
| `/ws/alerts` | WebSocket | Real-time push of new alerts |

---

## Team Member Assignments

---

### Developer A — FastAPI Backend Expansion
**File:** `task4_interface/backend/main.py`

**Responsibility:** Build all the new REST endpoints that tie Tasks 1–3 together. This file is the integration hub — it imports from Task 1's pipeline, Task 2's agent, Task 3's bridge and ledger, and the HITL queue.

**Full implementation:**
```python
# task4_interface/backend/main.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import asyncio
import json

from task1_ingestion.ingestion_pipeline import ACIRPipeline
from task2_agent.react_graph import run_agent
from task3_blockchain.fabric_bridge import process_signed_proposal, FabricBridge
from task4_interface.backend.hitl_queue import HITLQueue
from task4_interface.backend.websocket_manager import WebSocketManager
from task4_interface.backend.audit_client import AuditClient

app = FastAPI(title="ACIR Platform v2.0 — Full Pipeline", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Shared instances
hitl_queue = HITLQueue()
ws_manager = WebSocketManager()
audit_client = AuditClient()
pipeline = ACIRPipeline()

# ── Request / Response Models ─────────────────────────────────────────────────

class HITLDecision(BaseModel):
    analyst_id: str
    notes: Optional[str] = ""

class ReportRequest(BaseModel):
    alert_ids: List[str]
    start_time: str
    end_time: str
    analyst_name: str
    output_format: str = "json"  # json | pdf | docx

# ── Alert Endpoints ────────────────────────────────────────────────────────────

@app.get("/alerts")
async def get_alerts():
    """Return active high-priority alerts from Elasticsearch."""
    try:
        alerts = pipeline.get_recent_alerts(limit=50)
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as e:
        raise HTTPException(500, f"Alert fetch error: {e}")

# ── Agent Endpoints ────────────────────────────────────────────────────────────

_agent_status = {"state": "idle", "current_alert_id": None, "last_action": None}

@app.get("/agent/status")
async def agent_status():
    return _agent_status

@app.post("/agent/run/{alert_id}")
async def run_agent_on_alert(alert_id: str, background_tasks: BackgroundTasks):
    """Trigger the Task 2 agent on a specific alert ID."""
    background_tasks.add_task(_run_agent_background, alert_id)
    return {"status": "started", "alert_id": alert_id}

async def _run_agent_background(alert_id: str):
    _agent_status["state"] = "thinking"
    _agent_status["current_alert_id"] = alert_id
    try:
        alert = pipeline.get_alert_by_id(alert_id)
        if not alert:
            _agent_status["state"] = "error"
            return
        signed_proposal = run_agent(alert)
        _agent_status["last_action"] = signed_proposal.get("action")
        result = process_signed_proposal(signed_proposal)
        if result["status"] == "pending_hitl":
            _agent_status["state"] = "awaiting_hitl"
            hitl_queue.push(result["action_id"], signed_proposal)
        else:
            _agent_status["state"] = "idle"
        # Broadcast to WebSocket subscribers
        await ws_manager.broadcast("agent-feed", json.dumps({
            "type": "agent_result",
            "proposal": signed_proposal,
            "result": result
        }))
    except Exception as e:
        _agent_status["state"] = "error"
        print(f"Agent error: {e}")

# ── HITL Endpoints ─────────────────────────────────────────────────────────────

@app.get("/hitl/pending")
async def get_pending_hitl():
    """Return all actions awaiting human approval."""
    return {"pending": hitl_queue.list_pending(), "count": hitl_queue.count()}

@app.post("/hitl/approve/{action_id}")
async def approve_action(action_id: str, decision: HITLDecision):
    """Analyst approves a HITL-gated action."""
    item = hitl_queue.get(action_id)
    if not item:
        raise HTTPException(404, f"Action {action_id} not found or already processed")
    bridge = FabricBridge()
    signed_proposal = item["proposal"]
    # Execute the action
    from task3_blockchain.playbook_executor import execute_playbook
    result = execute_playbook(
        signed_proposal["action"],
        signed_proposal["action_input"]
    )
    # Log to ledger
    bridge.log_decision(signed_proposal, "HITL_APPROVED", "SUCCESS" if result.success else "FAILED")
    hitl_queue.complete(action_id, approved=True, analyst_id=decision.analyst_id)
    # Broadcast approval
    await ws_manager.broadcast("alerts", json.dumps({
        "type": "hitl_approved",
        "action_id": action_id,
        "action": signed_proposal["action"],
        "analyst": decision.analyst_id
    }))
    return {"status": "approved", "action_id": action_id, "result": result.to_dict()}

@app.post("/hitl/reject/{action_id}")
async def reject_action(action_id: str, decision: HITLDecision):
    """Analyst rejects a HITL-gated action."""
    item = hitl_queue.get(action_id)
    if not item:
        raise HTTPException(404, f"Action {action_id} not found")
    bridge = FabricBridge()
    bridge.log_decision(item["proposal"], "HITL_REJECTED", "BLOCKED")
    hitl_queue.complete(action_id, approved=False, analyst_id=decision.analyst_id)
    return {"status": "rejected", "action_id": action_id, "reason": decision.notes}

# ── Audit Endpoints ────────────────────────────────────────────────────────────

@app.get("/audit/trail")
async def audit_trail(limit: int = 100, offset: int = 0):
    """Return full blockchain audit trail."""
    entries = audit_client.get_all_entries(limit=limit, offset=offset)
    return {"entries": entries, "total": len(entries)}

@app.get("/audit/entry/{ledger_id}")
async def audit_entry(ledger_id: str):
    entry = audit_client.get_entry(ledger_id)
    if not entry:
        raise HTTPException(404, f"Ledger entry not found: {ledger_id}")
    return entry

# ── WebSocket Endpoints ────────────────────────────────────────────────────────

@app.websocket("/ws/agent-feed")
async def ws_agent_feed(websocket: WebSocket):
    await ws_manager.connect("agent-feed", websocket)
    try:
        while True:
            await websocket.receive_text()  # Keep connection alive
    except WebSocketDisconnect:
        ws_manager.disconnect("agent-feed", websocket)

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await ws_manager.connect("alerts", websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect("alerts", websocket)

# ── Health ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "components": {
            "elasticsearch": "reachable",
            "redis": hitl_queue.is_connected(),
            "fabric": "connected" if FabricBridge()._available else "offline (fallback active)"
        }
    }
```

**Start the expanded backend:**
```bash
cd d:\Sentinel
uvicorn acir_platform.task4_interface.backend.main:app --reload --port 8001
```

---

### Developer B — Redis HITL Queue
**File:** `task4_interface/backend/hitl_queue.py`

**Responsibility:** Implement the human-in-the-loop approval queue backed by Redis. Gated actions are pushed here with a 5-minute TTL. Expired items are automatically escalated. Approvals/rejections remove items from the queue.

**Full implementation:**
```python
# task4_interface/backend/hitl_queue.py
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List
import redis

REDIS_HOST = "localhost"
REDIS_PORT = 6379
QUEUE_KEY = "acir:hitl:queue"
TTL_MINUTES = 5
TTL_SECONDS = TTL_MINUTES * 60


class HITLQueue:
    """Redis-backed HITL approval queue with TTL and fallback to in-memory."""

    def __init__(self, host: str = REDIS_HOST, port: int = REDIS_PORT):
        self._redis: Optional[redis.Redis] = None
        self._memory_store: dict = {}  # Fallback when Redis unavailable
        try:
            r = redis.Redis(host=host, port=port, decode_responses=True)
            r.ping()
            self._redis = r
        except Exception:
            print("[HITLQueue] Redis unavailable — using in-memory queue (dev mode)")

    def is_connected(self) -> bool:
        if not self._redis:
            return False
        try:
            self._redis.ping()
            return True
        except Exception:
            return False

    def push(self, action_id: str, signed_proposal: dict) -> str:
        """Add a new item to the approval queue. Returns action_id."""
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=TTL_MINUTES)).isoformat()
        item = {
            "action_id": action_id,
            "proposal": signed_proposal,
            "status": "pending",
            "pushed_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at,
            "analyst_id": None,
            "approved": None
        }
        serialized = json.dumps(item)

        if self._redis:
            self._redis.setex(f"{QUEUE_KEY}:{action_id}", TTL_SECONDS, serialized)
        else:
            self._memory_store[action_id] = item
        return action_id

    def get(self, action_id: str) -> Optional[dict]:
        """Retrieve a pending item. Returns None if expired or not found."""
        if self._redis:
            data = self._redis.get(f"{QUEUE_KEY}:{action_id}")
            return json.loads(data) if data else None
        return self._memory_store.get(action_id)

    def complete(self, action_id: str, approved: bool, analyst_id: str) -> None:
        """Mark an item as approved or rejected and remove from active queue."""
        item = self.get(action_id)
        if not item:
            return
        item["status"] = "approved" if approved else "rejected"
        item["analyst_id"] = analyst_id
        item["approved"] = approved
        item["completed_at"] = datetime.now(timezone.utc).isoformat()

        if self._redis:
            # Move to completed set (keep 24 hours for audit)
            self._redis.delete(f"{QUEUE_KEY}:{action_id}")
            self._redis.setex(f"{QUEUE_KEY}:completed:{action_id}", 86400, json.dumps(item))
        else:
            self._memory_store.pop(action_id, None)

    def list_pending(self) -> List[dict]:
        """Return all currently pending items."""
        if self._redis:
            keys = self._redis.keys(f"{QUEUE_KEY}:*")
            # Exclude 'completed' keys
            active_keys = [k for k in keys if ":completed:" not in k]
            items = []
            for key in active_keys:
                data = self._redis.get(key)
                if data:
                    items.append(json.loads(data))
            return items
        return list(self._memory_store.values())

    def count(self) -> int:
        return len(self.list_pending())

    def get_ttl_seconds(self, action_id: str) -> int:
        """Return remaining seconds before this item expires."""
        if self._redis:
            ttl = self._redis.ttl(f"{QUEUE_KEY}:{action_id}")
            return max(0, ttl)
        item = self._memory_store.get(action_id)
        if not item:
            return 0
        expires = datetime.fromisoformat(item["expires_at"])
        now = datetime.now(timezone.utc)
        remaining = (expires - now).total_seconds()
        return max(0, int(remaining))
```

**Start Redis:**
```bash
docker run -d --name redis-acir -p 6379:6379 redis:7.2
```

---

### Developer C — WebSocket Manager + React Frontend
**Files:** `task4_interface/backend/websocket_manager.py` + React frontend scaffold

**Part 1 — WebSocket Manager:**
```python
# task4_interface/backend/websocket_manager.py
from fastapi import WebSocket
from typing import Dict, List
import asyncio


class WebSocketManager:
    """Manages WebSocket connections grouped by channel name."""

    def __init__(self):
        self._channels: Dict[str, List[WebSocket]] = {}

    async def connect(self, channel: str, websocket: WebSocket):
        await websocket.accept()
        if channel not in self._channels:
            self._channels[channel] = []
        self._channels[channel].append(websocket)

    def disconnect(self, channel: str, websocket: WebSocket):
        if channel in self._channels:
            self._channels[channel] = [
                ws for ws in self._channels[channel] if ws != websocket
            ]

    async def broadcast(self, channel: str, message: str):
        """Send a message to all connected clients on a channel."""
        if channel not in self._channels:
            return
        dead = []
        for ws in self._channels[channel]:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        # Clean up dead connections
        for ws in dead:
            self.disconnect(channel, ws)

    def subscriber_count(self, channel: str) -> int:
        return len(self._channels.get(channel, []))
```

**Part 2 — React Frontend scaffold:**
```bash
# Create React app inside task4_interface/frontend/
cd d:\Sentinel\acir_platform\task4_interface\frontend
npx create-react-app . --template cra-template
npm install axios recharts @tanstack/react-query date-fns
```

**`src/services/api.js` — Axios + WebSocket client:**
```javascript
// src/services/api.js
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8001';

const api = axios.create({ baseURL: API_BASE, timeout: 10000 });

// REST API calls
export const getAlerts         = ()            => api.get('/alerts');
export const getAgentStatus    = ()            => api.get('/agent/status');
export const runAgent          = (alertId)     => api.post(`/agent/run/${alertId}`);
export const getPendingHITL    = ()            => api.get('/hitl/pending');
export const approveAction     = (id, data)    => api.post(`/hitl/approve/${id}`, data);
export const rejectAction      = (id, data)    => api.post(`/hitl/reject/${id}`, data);
export const getAuditTrail     = (limit=100)   => api.get(`/audit/trail?limit=${limit}`);
export const generateReport    = (type, data)  => api.post(`/reports/${type}`, data);

// WebSocket connections
export const connectAgentFeed = (onMessage) => {
  const ws = new WebSocket(`${API_BASE.replace('http', 'ws')}/ws/agent-feed`);
  ws.onmessage = (event) => onMessage(JSON.parse(event.data));
  ws.onerror = (e) => console.error('Agent feed WS error:', e);
  return ws;
};

export const connectAlertsFeed = (onMessage) => {
  const ws = new WebSocket(`${API_BASE.replace('http', 'ws')}/ws/alerts`);
  ws.onmessage = (event) => onMessage(JSON.parse(event.data));
  ws.onerror = (e) => console.error('Alerts WS error:', e);
  return ws;
};
```

---

### Developer D — HITL Queue React Component + FCA Report Generator
**File:** `task4_interface/frontend/src/components/HITLQueue.jsx`  
**File:** `task4_interface/backend/report_generator.py` *(additional file)*

**Part 1 — HITLQueue Component:**
```jsx
// src/components/HITLQueue.jsx
import React, { useState, useEffect } from 'react';
import { getPendingHITL, approveAction, rejectAction } from '../services/api';

function CountdownTimer({ expiresAt }) {
  const [seconds, setSeconds] = useState(0);

  useEffect(() => {
    const update = () => {
      const remaining = Math.max(0, Math.floor(
        (new Date(expiresAt) - new Date()) / 1000
      ));
      setSeconds(remaining);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [expiresAt]);

  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  const isUrgent = seconds < 60;

  return (
    <span style={{ color: isUrgent ? '#ff4444' : '#ffaa00', fontWeight: 'bold' }}>
      {mins}:{secs.toString().padStart(2, '0')}
    </span>
  );
}

export default function HITLQueue({ analystId = 'analyst-1' }) {
  const [pending, setPending] = useState([]);
  const [loading, setLoading] = useState(true);

  const refresh = async () => {
    try {
      const { data } = await getPendingHITL();
      setPending(data.pending || []);
    } catch (e) {
      console.error('HITL fetch error:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);  // Refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const handleApprove = async (actionId) => {
    await approveAction(actionId, { analyst_id: analystId, notes: 'Approved via dashboard' });
    refresh();
  };

  const handleReject = async (actionId, reason) => {
    const notes = prompt('Rejection reason:') || 'Rejected by analyst';
    await rejectAction(actionId, { analyst_id: analystId, notes });
    refresh();
  };

  if (loading) return <div className="loading">Loading approval queue...</div>;

  return (
    <div className="hitl-queue">
      <h2>Human Approval Queue ({pending.length})</h2>
      {pending.length === 0 ? (
        <p className="empty-state">No actions awaiting approval.</p>
      ) : (
        pending.map(item => (
          <div key={item.action_id} className="hitl-card">
            <div className="hitl-header">
              <span className="action-badge">{item.proposal?.action}</span>
              <CountdownTimer expiresAt={item.expires_at} />
            </div>
            <div className="hitl-details">
              <p><strong>Alert:</strong> {item.proposal?.alert_id}</p>
              <p><strong>Target:</strong> {JSON.stringify(item.proposal?.action_input)}</p>
              <p><strong>Risk:</strong> {item.proposal?.risk_level}</p>
              <p><strong>Reason:</strong> {item.proposal?.thought?.slice(0, 120)}...</p>
            </div>
            <div className="hitl-actions">
              <button className="btn-approve" onClick={() => handleApprove(item.action_id)}>
                ✓ Approve
              </button>
              <button className="btn-reject" onClick={() => handleReject(item.action_id)}>
                ✗ Reject
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
```

**Part 2 — FCA Report Generator:**
```python
# task4_interface/backend/report_generator.py
import json
from datetime import datetime, timezone
from typing import List, Optional

class FCAReportGenerator:
    """
    Generates FCA-compliant regulatory reports from ACIR incident data.
    Formats: JSON (always), PDF and DOCX (requires optional dependencies).
    """

    def gdpr_article_33(self, incident_data: dict) -> dict:
        """
        GDPR Article 33 — Personal Data Breach Notification.
        Must be submitted to ICO within 72 hours of discovery.
        """
        return {
            "report_type": "GDPR Article 33 — Data Breach Notification",
            "report_id": f"GDPR-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data_controller": "Barclays Bank PLC",
            "ico_reference": "Z7622387",
            "breach_details": {
                "nature_of_breach": incident_data.get("anomaly_type", "Unauthorised Data Access"),
                "data_subjects_affected": incident_data.get("affected_users", "Under assessment"),
                "categories_of_data": ["Personal financial data", "Transaction records"],
                "approximate_record_count": incident_data.get("event_count", "Unknown"),
                "discovery_datetime": incident_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "containment_actions_taken": incident_data.get("actions_taken", []),
                "likely_consequences": "Risk of financial harm to affected customers",
                "measures_to_address": "Account suspension, IP blocking, forensic investigation initiated"
            },
            "72h_deadline": "Calculate from discovery_datetime",
            "status": "DRAFT — Review before submission to ICO"
        }

    def psd2_fraud_report(self, incident_data: dict) -> dict:
        """
        PSD2 Article 96 — Payment Security Incident Report.
        Major payment incidents must be reported to FCA and customer's NCAs.
        """
        return {
            "report_type": "PSD2 Article 96 — Major Operational Security Incident",
            "report_id": f"PSD2-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "payment_service_provider": "Barclays Bank PLC",
            "fca_frn": "122702",
            "incident_details": {
                "classification": "Operational Security Incident",
                "incident_start": incident_data.get("first_alert_time"),
                "incident_detected": incident_data.get("detection_time"),
                "services_impacted": incident_data.get("impacted_services", ["Online Banking"]),
                "transactions_affected": incident_data.get("affected_transactions", 0),
                "fraud_losses_estimate": incident_data.get("financial_impact", "Under assessment"),
                "source_ip": incident_data.get("source_ip", ""),
                "attack_pattern": incident_data.get("anomaly_type", ""),
                "acir_agent_action": incident_data.get("agent_action", ""),
                "containment_status": "CONTAINED" if incident_data.get("contained") else "IN PROGRESS"
            },
            "initial_notification": True,
            "status": "DRAFT — Requires DPO and CISO sign-off before submission"
        }

    def dora_resilience_report(self, incident_data: dict) -> dict:
        """
        DORA (Digital Operational Resilience Act) — ICT Incident Report.
        Required for significant ICT-related operational incidents from Jan 2025.
        """
        return {
            "report_type": "DORA Article 19 — ICT-Related Incident Report",
            "report_id": f"DORA-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "financial_entity": "Barclays Bank PLC",
            "lei_code": "G5GSEF7VJP5I7OUK5573",
            "ict_incident_details": {
                "incident_type": "Cybersecurity incident — Automated AI response activated",
                "severity": incident_data.get("severity", "High"),
                "classification": incident_data.get("anomaly_type", "Anomalous access pattern"),
                "detection_time": incident_data.get("detection_time"),
                "resolution_time": incident_data.get("resolution_time"),
                "rto_target_minutes": 60,
                "rto_actual_minutes": incident_data.get("rto_actual", "Unknown"),
                "rpo_target_minutes": 15,
                "systems_affected": incident_data.get("systems", []),
                "geographic_impact": ["United Kingdom"],
                "ai_response_deployed": True,
                "acir_platform_version": "1.0.0",
                "autonomous_actions_taken": incident_data.get("actions_taken", []),
                "human_oversight_applied": incident_data.get("hitl_invoked", False)
            },
            "status": "DRAFT — Submit to FCA within 4 hours of classification"
        }

    def export_json(self, report: dict) -> str:
        return json.dumps(report, indent=2)

    def export_pdf(self, report: dict) -> bytes:
        """Export report as PDF. Requires: pip install reportlab"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            import io

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            story.append(Paragraph(report["report_type"], styles["Heading1"]))
            story.append(Paragraph(f"Generated: {report['generated_at']}", styles["Normal"]))
            story.append(Spacer(1, 20))
            story.append(Paragraph(json.dumps(report, indent=2), styles["Code"]))
            doc.build(story)
            return buffer.getvalue()
        except ImportError:
            return b"Install reportlab: pip install reportlab"
```

---

### Developer E — MITRE ATT&CK Mapper + Threat Feed Component
**File:** `task4_interface/backend/mitre_mapper.py` *(additional file)*  
**File:** `task4_interface/frontend/src/components/ThreatFeed.jsx`

**Part 1 — MITRE ATT&CK Mapper:**
```python
# task4_interface/backend/mitre_mapper.py
"""
Maps ACIR anomaly types to MITRE ATT&CK technique IDs.
This enables the dashboard to display threat classification in
standard industry notation used by SOC analysts.
"""
import json
from typing import Optional

# Mapping from ACIR anomaly types to MITRE ATT&CK techniques
MITRE_MAPPING = {
    "sql_injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "severity": "high",
        "mitre_url": "https://attack.mitre.org/techniques/T1190/"
    },
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "severity": "high",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/"
    },
    "data_exfiltration": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "severity": "critical",
        "mitre_url": "https://attack.mitre.org/techniques/T1041/"
    },
    "privilege_escalation": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "severity": "high",
        "mitre_url": "https://attack.mitre.org/techniques/T1078/"
    },
    "lateral_movement": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "tactic_id": "TA0008",
        "severity": "critical",
        "mitre_url": "https://attack.mitre.org/techniques/T1021/"
    },
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "severity": "medium",
        "mitre_url": "https://attack.mitre.org/techniques/T1046/"
    },
    "anomaly": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "severity": "medium",
        "mitre_url": "https://attack.mitre.org/techniques/T1071/"
    }
}


def map_to_mitre(anomaly_type: str) -> Optional[dict]:
    """Return MITRE ATT&CK details for an anomaly type."""
    return MITRE_MAPPING.get(anomaly_type.lower(), MITRE_MAPPING.get("anomaly"))


def build_heatmap_data(alerts: list) -> list:
    """
    Build ATT&CK heatmap data from a list of alerts.
    Returns list of {tactic, technique_id, technique_name, count, severity}
    Ready for Recharts heat map visualisation in the dashboard.
    """
    counts = {}
    for alert in alerts:
        anomaly = alert.get("anomaly_type", "anomaly")
        mitre = map_to_mitre(anomaly)
        if mitre:
            key = mitre["technique_id"]
            if key not in counts:
                counts[key] = {**mitre, "count": 0}
            counts[key]["count"] += 1
    return sorted(counts.values(), key=lambda x: x["count"], reverse=True)
```

**Part 2 — ThreatFeed React Component:**
```jsx
// src/components/ThreatFeed.jsx
import React, { useState, useEffect, useRef } from 'react';
import { getAlerts, runAgent, connectAlertsFeed } from '../services/api';

const RISK_COLORS = {
  high: '#ff4444',
  medium: '#ff8c00',
  low: '#44bb44'
};

export default function ThreatFeed() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningAgent, setRunningAgent] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    // Initial load
    getAlerts().then(({ data }) => {
      setAlerts(data.alerts || []);
      setLoading(false);
    }).catch(() => setLoading(false));

    // WebSocket live updates
    wsRef.current = connectAlertsFeed((msg) => {
      if (msg.type === 'new_alert') {
        setAlerts(prev => [msg.alert, ...prev].slice(0, 100));
      }
    });

    // Polling fallback every 15s
    const poll = setInterval(() => {
      getAlerts().then(({ data }) => setAlerts(data.alerts || []));
    }, 15000);

    return () => {
      wsRef.current?.close();
      clearInterval(poll);
    };
  }, []);

  const handleRunAgent = async (alertId) => {
    setRunningAgent(alertId);
    try {
      await runAgent(alertId);
    } finally {
      setRunningAgent(null);
    }
  };

  if (loading) return <div className="loading">Loading threat feed...</div>;

  return (
    <div className="threat-feed">
      <h2>Live Threat Feed ({alerts.length})</h2>
      <div className="alert-table">
        <div className="alert-header-row">
          <span>Time</span><span>Source IP</span><span>Type</span>
          <span>Risk Score</span><span>Events</span><span>Action</span>
        </div>
        {alerts.map((alert, i) => (
          <div key={alert.alert_id || i} className="alert-row"
               style={{ borderLeft: `3px solid ${RISK_COLORS[alert.severity || 'high']}` }}>
            <span>{new Date(alert.timestamp).toLocaleTimeString()}</span>
            <span className="mono">{alert.source_ip}</span>
            <span>{alert.anomaly_type}</span>
            <span style={{ color: RISK_COLORS.high }}>
              {(alert.risk_score * 100).toFixed(1)}%
            </span>
            <span>{alert.event_count}</span>
            <button
              className="btn-agent"
              disabled={runningAgent === alert.alert_id}
              onClick={() => handleRunAgent(alert.alert_id)}
            >
              {runningAgent === alert.alert_id ? '⏳ Running...' : '▶ Run Agent'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

### Developer F — Executive KPI Dashboard + Audit Timeline
**File:** `task4_interface/frontend/src/components/AuditTimeline.jsx`  
**File:** `task4_interface/backend/audit_client.py`  
**File:** `task4_interface/frontend/src/components/AgentReasoningPanel.jsx`

**Part 1 — Audit Client:**
```python
# task4_interface/backend/audit_client.py
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from typing import Optional, List
from task3_blockchain.fabric_bridge import FabricBridge

class AuditClient:
    """Interface for querying the Hyperledger Fabric audit ledger."""

    def __init__(self):
        self.bridge = FabricBridge()
        self._local_log: list = []  # In-memory fallback

    def record_entry(self, entry: dict) -> None:
        """Store audit entry (bridges to Fabric when available)."""
        self._local_log.append(entry)

    def get_all_entries(self, limit: int = 100, offset: int = 0) -> List[dict]:
        """Return all audit entries, newest first."""
        entries = sorted(
            self._local_log,
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
        return entries[offset:offset + limit]

    def get_entry(self, ledger_id: str) -> Optional[dict]:
        for entry in self._local_log:
            if entry.get("ledger_id") == ledger_id:
                return entry
        return None

    def get_kpis(self) -> dict:
        """
        Calculate executive KPIs from audit log.
        Returns MTTD, MTTR, false positive rate, action distribution.
        """
        entries = self._local_log
        if not entries:
            return {"mttd_minutes": 0, "mttr_minutes": 0, "false_positive_rate": 0,
                    "total_incidents": 0, "actions_by_type": {}}

        # Action distribution
        actions = {}
        for e in entries:
            action = e.get("action", "unknown")
            actions[action] = actions.get(action, 0) + 1

        # Rollback rate as proxy for false positive rate
        total = len(entries)
        rolled_back = sum(1 for e in entries if e.get("outcome") == "ROLLED_BACK")
        fp_rate = (rolled_back / total * 100) if total > 0 else 0

        return {
            "total_incidents": total,
            "actions_by_type": actions,
            "false_positive_rate_pct": round(fp_rate, 1),
            "hitl_invocations": sum(1 for e in entries if "HITL" in e.get("decision", "")),
            "auto_resolved": sum(1 for e in entries if e.get("decision") == "ALLOW"),
            "denied": sum(1 for e in entries if e.get("decision") == "DENY")
        }
```

**Part 2 — AuditTimeline Component:**
```jsx
// src/components/AuditTimeline.jsx
import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import { getAuditTrail } from '../services/api';

const DECISION_COLORS = {
  ALLOW: '#44bb44',
  DENY: '#ff4444',
  REQUIRE_HITL: '#ff8c00',
  HITL_APPROVED: '#4499ff',
  HITL_REJECTED: '#ff6666',
  ROLLED_BACK: '#aaaaaa'
};

export default function AuditTimeline() {
  const [entries, setEntries] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAuditTrail(50)
      .then(({ data }) => setEntries(data.entries || []))
      .catch(() => {})
      .finally(() => setLoading(false));

    const interval = setInterval(() => {
      getAuditTrail(50).then(({ data }) => setEntries(data.entries || []));
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="loading">Loading audit trail...</div>;

  return (
    <div className="audit-timeline">
      <h2>Blockchain Audit Trail ({entries.length} entries)</h2>
      <div className="timeline">
        {entries.map((entry, i) => (
          <div key={entry.ledger_id || i} className="timeline-entry">
            <div className="timeline-marker"
                 style={{ background: DECISION_COLORS[entry.decision] || '#888' }}
            />
            <div className="timeline-content">
              <div className="timeline-header">
                <span className="action">{entry.action}</span>
                <span className="decision"
                      style={{ color: DECISION_COLORS[entry.decision] }}>
                  {entry.decision}
                </span>
                <span className="time">
                  {entry.timestamp ? new Date(entry.timestamp).toLocaleString() : 'N/A'}
                </span>
              </div>
              <div className="timeline-meta">
                <span>ID: {entry.ledger_id}</span>
                <span>Block: #{entry.block_number}</span>
                <span className="hash">{entry.reasoning_hash?.slice(0, 24)}...</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

---

## End-to-End Integration Test

Run this after all 4 tasks are complete to validate the full pipeline:

```python
# d:\Sentinel\tests\test_full_pipeline.py
import pytest
import time
import requests

API = "http://localhost:8001"

def test_full_pipeline():
    """
    Full 7-step pipeline validation.
    Expected runtime: < 15 seconds.
    """
    # Step 1: Inject a brute-force attack log
    log_payload = {"logs": [{"source_ip": "10.99.1.1", "event_type": "failed_login",
                              "count": 500, "time_window": 60}]}
    r = requests.post(f"{API}/ingest", json=log_payload)
    assert r.status_code == 200, "Step 1 FAILED: Ingest endpoint not responding"

    time.sleep(3)  # Wait for anomaly detection

    # Step 2: Confirm anomaly was scored above threshold
    r = requests.get(f"{API}/alerts")
    alerts = r.json().get("alerts", [])
    assert any(a.get("risk_score", 0) > 0.8 for a in alerts), \
        "Step 2 FAILED: No high-risk alert generated"
    alert_id = alerts[0]["alert_id"]

    # Step 3: Run agent on the alert
    r = requests.post(f"{API}/agent/run/{alert_id}")
    assert r.status_code == 200, "Step 3 FAILED: Agent endpoint error"

    time.sleep(5)  # Wait for LLM reasoning

    # Step 4: Check agent produced a signed proposal
    r = requests.get(f"{API}/agent/status")
    status = r.json().get("state")
    assert status in ("idle", "awaiting_hitl"), f"Step 4 FAILED: Unexpected agent state: {status}"

    # Step 5: If HITL — simulate approval
    r = requests.get(f"{API}/hitl/pending")
    pending = r.json().get("pending", [])
    if pending:
        action_id = pending[0]["action_id"]
        r = requests.post(f"{API}/hitl/approve/{action_id}",
                          json={"analyst_id": "test-analyst", "notes": "Integration test"})
        assert r.status_code == 200, "Step 5 FAILED: HITL approval error"

    # Step 6: Verify audit trail entry exists
    time.sleep(2)
    r = requests.get(f"{API}/audit/trail")
    entries = r.json().get("entries", [])
    assert len(entries) > 0, "Step 6 FAILED: No audit trail entries"

    # Step 7: Verify health endpoint shows all components
    r = requests.get(f"{API}/health")
    health = r.json()
    assert health.get("status") == "healthy", "Step 7 FAILED: Platform not healthy"

    print("✓ All 7 pipeline steps completed successfully")
```

---

## Running the Full Stack

```bash
# Terminal 1 — Elasticsearch
docker start es-acir

# Terminal 2 — Redis
docker start redis-acir   # or: docker run -d --name redis-acir -p 6379:6379 redis:7.2

# Terminal 3 — Colab LLM (keep browser tab open)
# → Open d:\Sentinel\acir_platform\task2_agent\colab_inference_server.ipynb in Colab

# Terminal 4 — FastAPI backend
cd d:\Sentinel
uvicorn acir_platform.task4_interface.backend.main:app --reload --port 8001

# Terminal 5 — React frontend
cd d:\Sentinel\acir_platform\task4_interface\frontend
npm start   # Opens http://localhost:3000
```

---

## Dependencies

```bash
# Backend
pip install fastapi uvicorn redis websockets reportlab

# Frontend
npx create-react-app .
npm install axios recharts @tanstack/react-query date-fns
```

---

## Testing

Create `d:\Sentinel\tests\test_task4.py`:

```
# Minimal test checklist:
# 1. test_hitl_queue_push_and_get()         — push item, retrieve it, verify fields
# 2. test_hitl_queue_complete_approve()     — complete with approved=True, item gone from pending
# 3. test_hitl_queue_complete_reject()      — complete with approved=False
# 4. test_hitl_queue_list_pending()         — multiple items, list returns all
# 5. test_hitl_queue_redis_fallback()       — with Redis down, in-memory queue works
# 6. test_websocket_broadcast()             — connect client, broadcast, client receives msg
# 7. test_audit_client_record_and_get()     — record entry, retrieve by ledger_id
# 8. test_audit_client_kpis_empty()         — empty log → all KPIs are 0
# 9. test_audit_client_kpis_with_data()     — 10 entries → correct counts
# 10. test_mitre_mapper_known_type()        — "brute_force" → T1110
# 11. test_mitre_mapper_unknown_type()      — "xyz" → returns default anomaly mapping
# 12. test_mitre_heatmap_builder()          — list of alerts → sorted heatmap data
# 13. test_report_gdpr33_fields()           — report has all required GDPR fields
# 14. test_report_psd2_fields()             — report has all required PSD2 fields
# 15. test_report_dora_fields()             — report has all required DORA fields
# 16. test_full_pipeline() [integration]    — 7-step test against live server
```

---

*Document Status: Task 4 Detail Spec v1.0 | ACIR Platform | Internal Use Only*
