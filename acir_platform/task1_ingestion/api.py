# =============================================================================
# api.py — FastAPI backend for Task 1 (Data Ingestion & Anomaly Detection)
#
# Endpoints:
#   GET  /health            — Elasticsearch + API health
#   GET  /status            — System status (indices, counts, scrubber info)
#   POST /ingest            — Run full ingestion pipeline
#   GET  /alerts            — Fetch stored high-priority alerts
#   GET  /logs              — Fetch recent raw logs
#   GET  /simulate          — Simulate logs (no ES indexing, for quick demo)
#   POST /reset             — Reset Elasticsearch indices
#   GET  /scrubber/demo     — Demo PII scrubbing on sample text
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from models import IngestRequest, IngestResponse, HighPriorityAlert
import config

from task1_ingestion.elasticsearch_client import ACIRElasticClient
from task1_ingestion.ingestion_pipeline   import IngestionPipeline
from task1_ingestion.pii_scrubber         import scrub_text, scrubber_info
from task1_ingestion.log_simulator        import simulate_logs

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ACIR Platform — Task 1: Data Ingestion API",
    description=(
        "Autonomous Cyber Incident Response — Data Ingestion & Anomaly Detection Layer. "
        "Ingests simulated security logs, scores with PyOD, scrubs PII, and raises alerts."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Shared instances ──────────────────────────────────────────────────────────
es_client = ACIRElasticClient()
pipeline  = IngestionPipeline(es_client=es_client)


# ── Request / response schemas ────────────────────────────────────────────────

class ScrubDemoRequest(BaseModel):
    text: str


class ScrubDemoResponse(BaseModel):
    original: str
    scrubbed: str
    backend:  str


class StatusResponse(BaseModel):
    api_version:      str
    timestamp:        str
    es_reachable:     bool
    es_health:        dict
    total_raw_logs:   int
    total_alerts:     int
    scrubber_backend: str
    risk_threshold:   float
    contamination:    float


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health", summary="API & Elasticsearch health check")
def health():
    """Returns OK if the API is running. Checks Elasticsearch connectivity."""
    es_up = es_client.ping()
    return {
        "status":     "ok",
        "timestamp":  datetime.utcnow().isoformat(),
        "api":        "running",
        "elasticsearch": "reachable" if es_up else "unreachable",
    }


@app.get("/status", response_model=StatusResponse, summary="Full system status")
def status():
    """Returns detailed system status including ES health and data counts."""
    es_up   = es_client.ping()
    es_health = es_client.health() if es_up else {"status": "unreachable"}

    raw_count   = 0
    alert_count = 0
    if es_up:
        try:
            es_client.ensure_indices()
            raw_count   = es_client.count_logs()
            alert_count = es_client.count_alerts()
        except Exception as e:
            logger.warning(f"Could not count docs: {e}")

    info = scrubber_info()
    return StatusResponse(
        api_version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
        es_reachable=es_up,
        es_health=es_health,
        total_raw_logs=raw_count,
        total_alerts=alert_count,
        scrubber_backend=info["backend"],
        risk_threshold=config.RISK_THRESHOLD,
        contamination=config.CONTAMINATION,
    )


@app.post("/ingest", response_model=IngestResponse, summary="Run full ingestion pipeline")
def ingest(req: IngestRequest):
    """
    Simulate security logs, run anomaly detection, scrub PII,
    build alerts, and index everything to Elasticsearch.
    """
    if not es_client.ping():
        raise HTTPException(
            status_code=503,
            detail="Elasticsearch is not reachable. Start it with: "
                   "docker run -d --name es-acir -p 9200:9200 "
                   "-e 'discovery.type=single-node' elasticsearch:8.13.0",
        )
    try:
        result = pipeline.run(
            num_logs=req.num_logs,
            attack_fraction=req.attack_fraction,
            index_to_es=True,
            reset_indices=False,
        )
        return result
    except Exception as e:
        logger.exception("Pipeline error")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/simulate", response_model=IngestResponse, summary="Simulate without ES (offline mode)")
def simulate(req: IngestRequest):
    """
    Run the full pipeline in offline mode — no Elasticsearch required.
    Results are returned but NOT persisted. Great for testing without Docker.
    """
    try:
        result = pipeline.run(
            num_logs=req.num_logs,
            attack_fraction=req.attack_fraction,
            index_to_es=False,
        )
        return result
    except Exception as e:
        logger.exception("Simulation error")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts", summary="Fetch high-priority alerts from Elasticsearch")
def get_alerts(
    min_risk: float = Query(default=0.0, ge=0.0, le=1.0,
                            description="Minimum risk score filter"),
    limit: int = Query(default=50, ge=1, le=500,
                       description="Maximum number of alerts to return"),
):
    """Retrieve stored alerts from Elasticsearch, sorted by risk score descending."""
    if not es_client.ping():
        raise HTTPException(status_code=503, detail="Elasticsearch unreachable")
    try:
        return es_client.get_alerts(min_risk=min_risk, size=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs", summary="Fetch recent raw logs from Elasticsearch")
def get_logs(
    limit: int = Query(default=100, ge=1, le=1000,
                       description="Number of recent logs to return"),
):
    """Retrieve the most recent raw logs from Elasticsearch."""
    if not es_client.ping():
        raise HTTPException(status_code=503, detail="Elasticsearch unreachable")
    try:
        return es_client.get_recent_logs(size=limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs/ip/{ip}", summary="Search logs by source IP")
def logs_by_ip(ip: str):
    """Return all raw logs for a specific source IP."""
    if not es_client.ping():
        raise HTTPException(status_code=503, detail="Elasticsearch unreachable")
    try:
        return es_client.search_by_ip(ip)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/reset", summary="Reset Elasticsearch indices")
def reset_indices():
    """Drop and recreate both raw-log and alert indices. WARNING: deletes all data."""
    if not es_client.ping():
        raise HTTPException(status_code=503, detail="Elasticsearch unreachable")
    try:
        es_client.reset()
        return {"status": "ok", "message": "Indices reset successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/scrubber/demo", response_model=ScrubDemoResponse,
          summary="Demo PII scrubbing on custom text")
def scrubber_demo(req: ScrubDemoRequest):
    """
    Scrub PII from the provided text and return the original vs scrubbed comparison.
    Uses Presidio if available, otherwise regex fallback.
    """
    scrubbed = scrub_text(req.text)
    info     = scrubber_info()
    return ScrubDemoResponse(
        original=req.text,
        scrubbed=scrubbed,
        backend=info["backend"],
    )


@app.get("/scrubber/demo", summary="Demo PII scrubbing on built-in samples")
def scrubber_demo_get():
    """Returns pre-built PII scrubbing examples."""
    samples = [
        "User john.smith@barclays.com called from +44 7911 123456.",
        "FAILED LOGIN: user=alice card=4532015112830366 from=185.220.101.5",
        "DB query by john_doe IBAN=GB29NWBK60161331926819 rows=847",
        "Transfer to 203.0.113.42 size=250MB email=victim@bank.com",
    ]
    info = scrubber_info()
    return {
        "backend": info["backend"],
        "examples": [
            {"original": s, "scrubbed": scrub_text(s)}
            for s in samples
        ],
    }


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("task1_ingestion.api:app", host=config.API_HOST,
                port=config.API_PORT, reload=True)
