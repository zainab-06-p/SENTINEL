# ACIR Platform — Task 1: Data Ingestion & Anomaly Detection
## Status Report & Improvement Roadmap

---

## What Has Been Built

### 1. Core Modules

| Module | File | Description |
|--------|------|-------------|
| Log Simulator | `task1_ingestion/log_simulator.py` | Generates synthetic SIEM/EDR/Network logs with 5 injected attack patterns (brute force, DB scraping, lateral movement, port scan, data exfiltration) using Faker UK locale |
| Anomaly Engine | `task1_ingestion/anomaly_engine.py` | Weighted PyOD ensemble — IForest (40%) + ECOD (40%) + LOF (20%); contamination=0.05; 8-feature matrix per log |
| PII Scrubber | `task1_ingestion/pii_scrubber.py` | Microsoft Presidio NLP scrubber + post-processing regex layer; always redacts external IPs while preserving RFC-1918 internal addresses |
| Feature Extractor | `task1_ingestion/feature_extractor.py` | Per-IP time-series features: event count, unique dest IPs, login failure rate, query rate/min, inter-event timing stats, Shannon session entropy, off-hours ratio |
| Ingestion Pipeline | `task1_ingestion/ingestion_pipeline.py` | Orchestrates the full 5-step flow: simulate → ES index → anomaly score → PII scrub → alert assembly |
| Elasticsearch Client | `task1_ingestion/elasticsearch_client.py` | Thin wrapper over `elasticsearch-py` 8.x — index management, bulk log indexing, alert querying, `search_by_ip()` |
| FastAPI Backend | `task1_ingestion/api.py` | 10 REST endpoints on port 8001 with CORS enabled |
| Frontend Dashboard | `task1_frontend/index.html` | Single-file HTML/JS/CSS dashboard — no build step; auto-detects ES and switches between `/ingest` and `/simulate` mode |

### 2. FastAPI Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Service liveness check |
| `GET` | `/status` | ES connectivity + scrubber backend info |
| `POST` | `/ingest` | Full pipeline run with ES persistence |
| `POST` | `/simulate` | Offline pipeline (no ES required) |
| `GET` | `/alerts` | Fetch stored high-priority alerts from ES |
| `GET` | `/logs` | Recent raw logs from ES |
| `GET` | `/logs/ip/{ip}` | Logs filtered by source IP |
| `POST` | `/reset` | Wipe ES indices and re-create them |
| `POST` | `/scrubber/demo` | Test PII scrubbing on arbitrary text |
| `GET` | `/scrubber/demo` | Pre-baked PII scrubbing examples |

### 3. Test Suite

**84 tests — 84 passing, 0 failing, 0 skipped**

| Class | Tests | Coverage |
|-------|-------|----------|
| `TestLogSimulator` | 15 | Attack pattern injection, field types, severity distribution |
| `TestAnomalyEngine` | 11 | Scoring range, cold-start fit, minimum logs, ensemble weighting |
| `TestPIIScrubber` | 14 | Email, credit card, IBAN, NHS, external IP redaction, internal IP preservation |
| `TestFeatureExtractor` | 12 | Shannon entropy, off-hours ratio, DB scraping rate, empty log edge case |
| `TestIngestionPipeline` | 11 | End-to-end offline run, alert thresholds, response schema |
| `TestAPIEndpoints` | 13 | All endpoints including scrubber demo and OpenAPI schema |
| `TestElasticsearch` | 6 | Live ES ping, health, index creation, log indexing, pipeline + API with ES |

### 4. Infrastructure

- **Elasticsearch 8.13.0** running in Docker container `es-acir` on port 9200 (single-node, no security, 512 MB JVM heap)
- **FastAPI + Uvicorn** running on port 8001 with hot-reload
- **Python 3.13.7** system install with all dependencies pre-installed

### 5. Bugs Fixed During Build

| Bug | Root Cause | Fix |
|-----|-----------|-----|
| Internal IP `10.x.x.x` being redacted | `IP_ADDRESS` entity in Presidio redacts all IPs | Removed `IP_ADDRESS` from `PII_ENTITIES`; added post-processing regex that only targets public IPs |
| External IP `203.0.113.x` not redacted | Presidio returned early when no other entities found, bypassing IP regex | `_redact_external_ips()` now always runs after Presidio regardless of result |
| AnomalyEngine raised `ValueError` with 5 logs | Cold-start `fit()` requires ≥10 logs minimum; test passed only 5 | Test fixture increased to 15 logs |
| ES integration tests always skipped | `pytest.mark.skipif(not ping())` evaluated at import time before ES was ready | Replaced with `autouse` fixture that skips at runtime |
| `ping()` returned `False` despite ES being up | `elasticsearch-py` v9.3.0 incompatible with ES server 8.13 | Downgraded client to `elasticsearch==8.19.3` |

---

## What Can Be Improved

### A. Performance & Efficiency

#### A1. Bulk Indexing with Async I/O
**Current:** `index_logs()` uses synchronous `helpers.bulk()` — blocks the event loop during large ingestion runs.  
**Improvement:** Replace with `AsyncElasticsearch` + `async_bulk()`. This would allow the API to handle concurrent ingest requests without thread-blocking and reduce wall-clock time for large batches.

```python
# Current (blocking)
helpers.bulk(self.client, actions)

# Improved (async)
from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk
await async_bulk(self.async_client, actions)
```

**Estimated gain:** 3–5× throughput on >1,000 log batches.

---

#### A2. Anomaly Engine: Pre-trained Model Persistence
**Current:** `AnomalyEngine` fits from scratch on every pipeline run. For 1,000 logs this takes ~2–4 seconds.  
**Improvement:** Serialize the fitted ensemble to disk with `joblib` and reload on startup. Re-fit only when a rolling window of N logs has accumulated since the last fit (e.g., every 10,000 logs).

```python
import joblib

def save(self, path: str):
    joblib.dump({"models": self._models, "fitted": self._fitted}, path)

def load(self, path: str):
    state = joblib.load(path)
    self._models = state["models"]
    self._fitted = state["fitted"]
```

**Estimated gain:** Eliminates 2–4s cold-start on every API call.

---

#### A3. Feature Extraction: Vectorised NumPy Pipeline
**Current:** `extract_all_features()` loops over IPs with nested list comprehensions — O(n²) for large log sets.  
**Improvement:** Use `pandas` groupby + vectorised aggregations:

```python
import pandas as pd

df = pd.DataFrame([log.model_dump() for log in logs])
features = df.groupby("source_ip").agg(
    event_count=("log_id", "count"),
    unique_dest_ips=("dest_ip", "nunique"),
    off_hours_ratio=("timestamp", lambda ts: (ts.dt.hour < 6).mean()),
    ...
)
```

**Estimated gain:** 10–50× faster on batches of >5,000 logs.

---

#### A4. PII Scrubber: Batch Processing
**Current:** `scrub_logs()` calls `scrub_text()` per log in a Python `for` loop — Presidio model is re-invoked for each payload individually.  
**Improvement:** Use Presidio's `batch_analyze_dict()` method to process all payloads in a single NLP pass, reducing tokenisation overhead.

**Estimated gain:** ~40% reduction in scrubbing time for batches >100 logs.

---

### B. Reliability & Robustness

#### B1. Elasticsearch Connection Pooling & Retry Logic
**Current:** Each `ACIRElasticClient()` instantiation creates a new connection. No retry on transient ES errors.  
**Improvement:** Use a module-level singleton with exponential-backoff retry decorator:

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def index_logs(self, logs):
    ...
```

---

#### B2. Dead Letter Queue for Failed Indexed Logs
**Current:** `helpers.bulk()` silently drops failed documents if ES returns a partial error.  
**Improvement:** Capture `errors` from bulk response and write failed docs to a local `failed_logs.jsonl` file for re-indexing.

---

#### B3. Schema Validation on Ingest
**Current:** `RawLog` is validated by Pydantic only at creation. Malformed logs from external sources bypass validation.  
**Improvement:** Add a strict validation pass at the API boundary before any downstream processing, returning structured 422 errors with field-level detail.

---

### C. Security

#### C1. API Authentication
**Current:** All endpoints are unauthenticated — any host can call `/ingest`, `/reset`, etc.  
**Improvement:** Add Bearer token middleware or API key header (`X-API-Key`) validated against a secrets store. Critical endpoints like `/reset` should require elevated privileges.

---

#### C2. Elasticsearch TLS & Credentials
**Current:** ES runs with `xpack.security.enabled=false` — no TLS, no authentication.  
**Improvement:** Enable X-Pack security for production, configure TLS certificates, and pass credentials via environment variables rather than hardcoding in `config.py`.

---

#### C3. PII Scrubber Audit Log
**Current:** Scrubbed text is returned but there is no record of what was redacted or how many entities were found.  
**Improvement:** Log entity types and counts (not the values) to a separate `acir-pii-audit` ES index for compliance reporting — useful in a FCA-regulated banking context.

---

### D. Observability

#### D1. Structured Logging with Correlation IDs
**Current:** Modules use Python's standard `logging` with plain text output.  
**Improvement:** Add `structlog` or `python-json-logger` with a per-request `correlation_id` (UUID) injected via FastAPI middleware, so every log line for a single `/ingest` call is traceable end-to-end.

---

#### D2. Prometheus Metrics Endpoint
**Current:** No metrics are exposed.  
**Improvement:** Add `prometheus_fastapi_instrumentator` to expose `/metrics` — track ingestion latency, anomaly detection rate, alert count per run, and ES indexing throughput. This integrates directly with Grafana dashboards.

---

#### D3. ES Index Lifecycle Management (ILM)
**Current:** The `acir-logs` index grows indefinitely with no rollover policy.  
**Improvement:** Apply an ILM policy to roll over the index at 10 GB or 30 days and delete shards older than 90 days — preventing unbounded disk usage.

---

### E. Testing

#### E1. Property-Based Testing with Hypothesis
**Current:** Test data is generated with fixed seeds and deterministic Faker calls.  
**Improvement:** Use `hypothesis` to fuzz the anomaly engine and PII scrubber with random inputs, catching edge cases like empty payloads, unicode characters, and extreme IP addresses.

---

#### E2. Load / Performance Tests
**Current:** No benchmarks exist for ingestion throughput.  
**Improvement:** Add `locust` or `pytest-benchmark` tests that measure:  
- Logs/second through the full pipeline  
- ES indexing throughput at 10k/50k/100k log batches  
- API response time at 10 concurrent clients

---

#### E3. Contract Tests for ES Index Mappings
**Current:** Index mapping is defined in code but never validated against a schema contract.  
**Improvement:** Add tests that assert the live ES mapping matches the expected schema — catching silent mapping drift between deployments.

---

## Priority Summary

| Priority | Improvement | Effort | Impact |
|----------|------------|--------|--------|
| 🔴 High | A1 — Async Elasticsearch bulk indexing | Medium | High throughput |
| 🔴 High | A2 — Pre-trained model persistence | Low | Eliminates cold-start |
| 🔴 High | C1 — API authentication | Low | Critical for production |
| 🟡 Medium | A3 — Vectorised feature extraction | Medium | High on large batches |
| 🟡 Medium | A4 — Presidio batch processing | Low | Moderate scrub speed gain |
| 🟡 Medium | B1 — ES retry logic | Low | Resilience |
| 🟡 Medium | D1 — Structured logging + correlation IDs | Medium | Debuggability |
| 🟡 Medium | D2 — Prometheus metrics | Medium | Operational visibility |
| 🟢 Low | B2 — Dead letter queue | Medium | Data integrity |
| 🟢 Low | C2 — ES TLS/auth | Medium | Production hardening |
| 🟢 Low | C3 — PII audit log | Low | FCA compliance |
| 🟢 Low | D3 — ILM policy | Low | Disk management |
| 🟢 Low | E1 — Hypothesis fuzzing | Medium | Test coverage |
| 🟢 Low | E2 — Load tests | Medium | Capacity planning |
