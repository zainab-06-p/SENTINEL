# acir_platform/models.py
# Shared Pydantic models used across all tasks

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime
import uuid


class RawLog(BaseModel):
    """A single raw security log entry from SIEM/EDR/Network sensor."""
    log_id:     str       = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:  datetime  = Field(default_factory=datetime.utcnow)
    source_ip:  str
    dest_ip:    Optional[str] = None
    event_type: str                        # e.g. "login_failed", "db_query", "ssh_connect"
    username:   Optional[str] = None
    payload:    str                        # Raw log message (may contain PII)
    severity:   str       = "INFO"        # INFO | WARNING | CRITICAL
    source:     str       = "SIEM"        # SIEM | EDR | NETWORK


class ScoredLog(BaseModel):
    """A raw log enriched with an anomaly score."""
    log:           RawLog
    anomaly_score: float   # 0.0 (normal) → 1.0 (highly anomalous)
    is_anomaly:    bool


class ScrubbedLog(BaseModel):
    """A scored log with PII removed, ready for AI consumption."""
    log_id:          str
    timestamp:       datetime
    source_ip:       str
    dest_ip:         Optional[str] = None
    event_type:      str
    scrubbed_payload: str          # PII replaced with <REDACTED_TYPE> tokens
    anomaly_score:   float
    severity:        str
    source:          str


class TimeSeriesFeatures(BaseModel):
    """Time-series features extracted from a window of logs for one source IP."""
    source_ip:           str
    window_start:        datetime
    window_end:          datetime
    event_count:         int
    unique_dest_ips:     int
    login_failure_rate:  float     # failures / total logins
    query_rate_per_min:  float
    inter_event_mean_ms: float     # mean time between events
    inter_event_std_ms:  float
    session_entropy:     float     # Shannon entropy of event_types
    off_hours_ratio:     float     # fraction of events outside 08:00–18:00


class HighPriorityAlert(BaseModel):
    """Final output of the ingestion pipeline — passed to the AI agent."""
    alert_id:        str       = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:       datetime  = Field(default_factory=datetime.utcnow)
    source_ip:       str
    event_type:      str
    risk_score:      float
    severity:        str
    scrubbed_payload: str
    features:        TimeSeriesFeatures
    raw_log_ids:     list[str] = []    # IDs of contributing raw logs


class IngestRequest(BaseModel):
    """API request body for /ingest endpoint."""
    num_logs:        int  = Field(default=200, ge=10, le=2000)
    attack_fraction: float = Field(default=0.08, ge=0.0, le=1.0)


class IngestResponse(BaseModel):
    """API response from /ingest endpoint."""
    total_logs_generated: int
    total_logs_indexed:   int
    anomalies_detected:   int
    alerts_raised:        int
    alerts:               list[HighPriorityAlert]
