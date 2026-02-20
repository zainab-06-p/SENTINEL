# acir_platform/config.py
# Global configuration for the ACIR platform

# ── Elasticsearch ──────────────────────────────────────────────────────────────
ES_HOST        = "http://localhost:9200"
ES_INDEX       = "acir-logs"
ES_ALERT_INDEX = "acir-alerts"

# ── Anomaly Detection ──────────────────────────────────────────────────────────
RISK_THRESHOLD      = 0.80   # Anomaly score above this => high-priority alert
CONTAMINATION       = 0.05   # Expected fraction of outliers in training data (5%)
ANOMALY_WINDOW_SECS = 300    # 5-minute sliding window for feature extraction

# ── Log Simulator ──────────────────────────────────────────────────────────────
SIM_TOTAL_LOGS      = 500    # Total logs generated per simulation run
SIM_ATTACK_FRACTION = 0.08   # 8% of logs are injected attack events

# ── PII Scrubbing ──────────────────────────────────────────────────────────────
PII_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "CREDIT_CARD", "IBAN_CODE", "UK_NHS",
    "DATE_TIME", "LOCATION"
    # NOTE: IP_ADDRESS intentionally excluded — IPs are critical for
    # security analysis. External IPs are redacted by the regex fallback
    # layer in pii_scrubber.py via _REGEX_PATTERNS.
]

# ── API ────────────────────────────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8001

# ── LLM (used in Task 2) ───────────────────────────────────────────────────────
LLM_MODE           = "colab"
COLAB_ENDPOINT_URL = "https://PASTE_NGROK_URL_HERE"
OLLAMA_BASE_URL    = "http://localhost:11434"
MODEL_NAME         = "meta-llama/Meta-Llama-3.1-8B-Instruct"

# ── HITL (used in Task 4) ──────────────────────────────────────────────────────
HITL_TIMEOUT_SECS = 300
