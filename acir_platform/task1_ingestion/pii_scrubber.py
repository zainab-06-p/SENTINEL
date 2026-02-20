# =============================================================================
# pii_scrubber.py — Microsoft Presidio PII anonymization wrapper
#
# Scrubs the following entities from log payloads before AI processing:
#   PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, IBAN_CODE,
#   IP_ADDRESS, UK_NHS, UK_NINO, DATE_TIME, LOCATION
#
# Falls back to a regex-based scrubber if Presidio is not installed.
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import logging
from models import ScoredLog, ScrubbedLog
import config

logger = logging.getLogger(__name__)

# ── Try Presidio ──────────────────────────────────────────────────────────────

_presidio_available = False
try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
    from presidio_anonymizer.entities import OperatorConfig
    _presidio_available = True
    logger.info("Presidio loaded successfully.")
except ImportError:
    logger.warning("Presidio not installed — using regex fallback scrubber.")

# ── Presidio engine (lazy init) ───────────────────────────────────────────────
_analyzer:   "AnalyzerEngine   | None" = None
_anonymizer: "AnonymizerEngine | None" = None


def _get_presidio():
    global _analyzer, _anonymizer
    if _analyzer is None:
        _analyzer   = AnalyzerEngine()
        _anonymizer = AnonymizerEngine()
    return _analyzer, _anonymizer


# ── Regex fallback patterns ────────────────────────────────────────────────────

_REGEX_PATTERNS = [
    # Credit card numbers
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), "<CREDIT_CARD>"),
    # IBAN
    (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'), "<IBAN>"),
    # UK phone numbers
    (re.compile(r'\b(?:\+44|0044|0)[\s\-]?\d{4}[\s\-]?\d{6}\b'), "<PHONE_NUMBER>"),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b'), "<EMAIL>"),
    # IPv4 addresses (keep internal RFC1918, redact public)
    (re.compile(
        r'\b(?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)'
        r'(?:\d{1,3}\.){3}\d{1,3}\b'
    ), "<EXTERNAL_IP>"),
    # NHS numbers (3-3-4 digit pattern)
    (re.compile(r'\b\d{3}[\s\-]\d{3}[\s\-]\d{4}\b'), "<NHS_NUMBER>"),
    # UK National Insurance Number
    (re.compile(r'\b[A-Z]{2}\s?\d{6}\s?[A-D]\b'), "<NINO>"),
    # Dates (various formats)
    (re.compile(r'\b\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{2,4}\b'), "<DATE>"),
]


# ── External IP regex applied after Presidio ────────────────────────────────

_EXTERNAL_IP_RE = re.compile(
    r'\b(?!(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.)'
    r'(?:\d{1,3}\.){3}\d{1,3}\b'
)

def _redact_external_ips(text: str) -> str:
    """Redact public IPv4 addresses; leave RFC-1918 internal IPs intact."""
    return _EXTERNAL_IP_RE.sub("<EXTERNAL_IP>", text)


def _regex_scrub(text: str) -> str:
    """Apply regex-based PII redaction as a fallback."""
    for pattern, replacement in _REGEX_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ── Core scrubbing functions ───────────────────────────────────────────────────

def scrub_text(text: str) -> str:
    """
    Scrub PII from a text string.
    Uses Presidio if available, otherwise falls back to regex patterns.
    """
    if not text:
        return text

    if _presidio_available:
        try:
            analyzer, anonymizer = _get_presidio()
            results = analyzer.analyze(
                text=text,
                entities=config.PII_ENTITIES,
                language="en",
            )
            if results:
                operators = {
                    entity: OperatorConfig("replace", {"new_value": f"<{entity}>"})
                    for entity in config.PII_ENTITIES
                }
                anonymized = anonymizer.anonymize(
                    text=text,
                    analyzer_results=results,
                    operators=operators,
                )
                return _redact_external_ips(anonymized.text)
            return _redact_external_ips(text)
        except Exception as e:
            logger.warning(f"Presidio scrub failed ({e}), falling back to regex.")
            return _regex_scrub(text)
    else:
        return _regex_scrub(text)


def scrub_logs(scored_logs: list[ScoredLog]) -> list[ScrubbedLog]:
    """
    Convert a list of ScoredLog objects into ScrubbedLog objects
    with PII removed from payloads. Only processes anomalies by default
    but will process all if passed in.
    """
    scrubbed = []
    for sl in scored_logs:
        clean_payload = scrub_text(sl.log.payload)
        scrubbed.append(ScrubbedLog(
            log_id=sl.log.log_id,
            timestamp=sl.log.timestamp,
            source_ip=sl.log.source_ip,
            dest_ip=sl.log.dest_ip,
            event_type=sl.log.event_type,
            scrubbed_payload=clean_payload,
            anomaly_score=sl.anomaly_score,
            severity=sl.log.severity,
            source=sl.log.source,
        ))
    return scrubbed


# ── Diagnostic ────────────────────────────────────────────────────────────────

def scrubber_info() -> dict:
    """Return information about the active scrubbing backend."""
    return {
        "backend":           "presidio" if _presidio_available else "regex_fallback",
        "presidio_available": _presidio_available,
        "entities_configured": config.PII_ENTITIES,
    }


if __name__ == "__main__":
    samples = [
        "User john.smith@barclays.com called from +44 7911 123456.",
        "FAILED LOGIN: user=alice card=4532015112830366 from=185.220.101.5",
        "DB query by john_doe IBAN=GB29NWBK60161331926819 rows=847",
        "Transfer to 203.0.113.42 size=250MB email=victim@bank.com NHS=485 777 3456",
    ]
    print(f"Backend: {scrubber_info()['backend']}\n")
    for s in samples:
        print(f"  ORIGINAL : {s}")
        print(f"  SCRUBBED : {scrub_text(s)}")
        print()
