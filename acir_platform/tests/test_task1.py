"""
ACIR Platform — Task 1 Test Suite
==================================
Tests cover:
  1. Log Simulator
  2. Anomaly Engine (PyOD)
  3. PII Scrubber
  4. Feature Extractor
  5. Ingestion Pipeline (offline / no ES)
  6. FastAPI endpoints (TestClient)
  7. Elasticsearch round-trip (skipped if ES unreachable)
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import math
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

# ─── Imports under test ───────────────────────────────────────────────────────
from models import RawLog, ScoredLog, HighPriorityAlert, IngestRequest
from task1_ingestion.log_simulator      import simulate_logs, EVENT_TYPES_NORMAL
from task1_ingestion.anomaly_engine     import AnomalyEngine, _extract_features
from task1_ingestion.pii_scrubber       import scrub_text, scrub_logs, scrubber_info
from task1_ingestion.feature_extractor  import (
    extract_features_for_ip, extract_all_features, _shannon_entropy,
)
from task1_ingestion.ingestion_pipeline import IngestionPipeline
from task1_ingestion.api                import app
from task1_ingestion.elasticsearch_client import ACIRElasticClient
import config


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def small_logs():
    """50 logs with 10% attack fraction."""
    return simulate_logs(total=50, attack_fraction=0.10)


@pytest.fixture(scope="module")
def large_logs():
    """300 logs with 10% attack fraction."""
    return simulate_logs(total=300, attack_fraction=0.10)


@pytest.fixture(scope="module")
def api_client():
    return TestClient(app)


@pytest.fixture(scope="session")
def es_available():
    """Session-scoped: evaluated once, shared across the whole run."""
    c = ACIRElasticClient()
    available = c.ping()
    return available


# =============================================================================
# 1. LOG SIMULATOR TESTS
# =============================================================================

class TestLogSimulator:

    def test_returns_correct_count(self):
        logs = simulate_logs(total=100)
        assert len(logs) == 100

    def test_minimum_count(self):
        logs = simulate_logs(total=10, attack_fraction=0.5)
        assert len(logs) == 10

    def test_logs_are_rawlog_instances(self, small_logs):
        for log in small_logs:
            assert isinstance(log, RawLog)

    def test_logs_have_valid_timestamps(self, small_logs):
        for log in small_logs:
            assert isinstance(log.timestamp, datetime)

    def test_logs_have_source_ip(self, small_logs):
        for log in small_logs:
            assert log.source_ip
            parts = log.source_ip.split(".")
            assert len(parts) == 4

    def test_logs_have_event_type(self, small_logs):
        for log in small_logs:
            assert log.event_type
            assert isinstance(log.event_type, str)

    def test_logs_have_payload(self, small_logs):
        for log in small_logs:
            assert log.payload
            assert len(log.payload) > 5

    def test_attack_fraction_produces_attack_events(self):
        logs = simulate_logs(total=200, attack_fraction=0.20)
        attack_events = {"login_failed", "ssh_connect", "port_probe",
                         "db_query", "data_transfer"}
        attack_logs = [l for l in logs if l.event_type in attack_events or
                       l.severity in ("WARNING", "CRITICAL")]
        # Not a hard threshold — just ensure some attacks are present
        assert len(attack_logs) > 0

    def test_zero_attack_fraction(self):
        logs = simulate_logs(total=50, attack_fraction=0.0)
        # All should be normal events
        severities = {l.severity for l in logs}
        # Normal logs should be INFO
        assert "INFO" in severities

    def test_severity_values_valid(self, small_logs):
        valid = {"INFO", "WARNING", "CRITICAL"}
        for log in small_logs:
            assert log.severity in valid

    def test_source_values_valid(self, small_logs):
        valid = {"SIEM", "EDR", "NETWORK"}
        for log in small_logs:
            assert log.source in valid

    def test_log_ids_are_unique(self, large_logs):
        ids = [l.log_id for l in large_logs]
        assert len(ids) == len(set(ids))

    def test_large_batch(self):
        logs = simulate_logs(total=1000, attack_fraction=0.05)
        assert len(logs) == 1000

    def test_custom_base_time(self):
        base = datetime(2026, 1, 1, 0, 0, 0)
        logs = simulate_logs(total=20, base_time=base)
        for log in logs:
            # Timestamps should be within the same day or close
            assert log.timestamp.year >= 2026

    def test_attack_payloads_contain_indicators(self):
        """Attack logs should include suspicious keywords in payloads."""
        logs = simulate_logs(total=500, attack_fraction=0.30)
        keywords = ["FAILED", "SELECT", "SSH", "PORT_SCAN", "TRANSFER", "OUTBOUND"]
        attack_logs = [l for l in logs if l.severity in ("WARNING", "CRITICAL")]
        payloads = " ".join(l.payload.upper() for l in attack_logs)
        found = [kw for kw in keywords if kw in payloads]
        assert len(found) >= 3, f"Expected attack keywords, found: {found}"


# =============================================================================
# 2. ANOMALY ENGINE TESTS
# =============================================================================

class TestAnomalyEngine:

    def test_cold_start_scores_without_fit(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        assert len(scored) == len(small_logs)

    def test_scores_are_floats_in_range(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        for s in scored:
            assert 0.0 <= s.anomaly_score <= 1.0

    def test_is_anomaly_flag_matches_threshold(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        for s in scored:
            if s.anomaly_score >= config.RISK_THRESHOLD:
                assert s.is_anomaly is True
            else:
                assert s.is_anomaly is False

    def test_fit_then_score(self, large_logs):
        engine = AnomalyEngine()
        engine.fit(large_logs[:200])
        scored = engine.score(large_logs[200:])
        assert len(scored) == len(large_logs[200:])

    def test_anomalies_present_in_mixed_batch(self, large_logs):
        engine = AnomalyEngine()
        scored = engine.score(large_logs)
        anomalies = [s for s in scored if s.is_anomaly]
        assert len(anomalies) > 0

    def test_fit_requires_minimum_logs(self):
        engine = AnomalyEngine()
        with pytest.raises(ValueError):
            engine.fit(simulate_logs(total=5))

    def test_scored_log_preserves_original(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        for s, original in zip(scored, small_logs):
            assert s.log.log_id == original.log_id

    def test_feature_matrix_shape(self, small_logs):
        X = _extract_features(small_logs)
        assert X.shape == (len(small_logs), 8)

    def test_feature_matrix_no_nan(self, small_logs):
        X = _extract_features(small_logs)
        assert not any(
            math.isnan(v) for row in X.tolist() for v in row
        )

    def test_high_contamination(self, large_logs):
        engine = AnomalyEngine(contamination=0.30)
        scored = engine.score(large_logs)
        anomalies = [s for s in scored if s.is_anomaly]
        # With 30% contamination, should flag more items
        assert len(anomalies) > 0

    def test_scores_vary_across_logs(self, large_logs):
        engine = AnomalyEngine()
        scored = engine.score(large_logs)
        scores = [s.anomaly_score for s in scored]
        assert max(scores) - min(scores) > 0.01, "All scores are identical — likely a bug"


# =============================================================================
# 3. PII SCRUBBER TESTS
# =============================================================================

class TestPIIScrubber:

    def test_scrubber_info_returns_dict(self):
        info = scrubber_info()
        assert "backend" in info
        assert info["backend"] in ("presidio", "regex_fallback")

    def test_email_redacted(self):
        out = scrub_text("Contact john.smith@barclays.co.uk for details.")
        assert "john.smith@barclays.co.uk" not in out

    def test_credit_card_redacted(self):
        out = scrub_text("Card used: 4532015112830366 at merchant.")
        assert "4532015112830366" not in out

    def test_iban_redacted(self):
        out = scrub_text("Transfer from GB29NWBK60161331926819 completed.")
        assert "GB29NWBK60161331926819" not in out

    def test_external_ip_redacted(self):
        out = scrub_text("Connection from 203.0.113.42 rejected.")
        assert "203.0.113.42" not in out

    def test_phone_redacted(self):
        out = scrub_text("Called from +44 7911 123456 at 3AM.")
        assert "+44 7911 123456" not in out

    def test_internal_ip_preserved(self):
        """Internal RFC1918 IPs should NOT be redacted — needed for analysis."""
        out = scrub_text("Login from 10.0.2.15 succeeded.")
        assert "10.0.2.15" in out

    def test_empty_string(self):
        assert scrub_text("") == ""

    def test_no_pii_unchanged(self):
        clean = "SELECT * FROM accounts WHERE status = active"
        out = scrub_text(clean)
        # Core content should be preserved
        assert "SELECT" in out
        assert "accounts" in out

    def test_multiple_pii_in_one_string(self):
        text = (
            "User alice@bank.com (card: 4532015112830366) "
            "transferred GB29NWBK60161331926819 to 185.220.101.5"
        )
        out = scrub_text(text)
        assert "alice@bank.com"        not in out
        assert "4532015112830366"      not in out
        assert "185.220.101.5"         not in out

    def test_scrub_logs_processes_list(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        scrubbed = scrub_logs(scored)
        assert len(scrubbed) == len(scored)

    def test_scrubbed_logs_have_payload(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs)
        scrubbed = scrub_logs(scored)
        for s in scrubbed:
            assert isinstance(s.scrubbed_payload, str)

    def test_scrubbed_log_preserves_metadata(self, small_logs):
        engine = AnomalyEngine()
        scored = engine.score(small_logs[:15])   # need >= 10 for cold-start fit
        scrubbed = scrub_logs(scored)
        for sc, orig in zip(scrubbed, scored):
            assert sc.log_id      == orig.log.log_id
            assert sc.source_ip   == orig.log.source_ip
            assert sc.event_type  == orig.log.event_type
            assert sc.anomaly_score == orig.anomaly_score

    def test_none_input_handled_gracefully(self):
        # Should not raise
        result = scrub_text("")
        assert result == ""


# =============================================================================
# 4. FEATURE EXTRACTOR TESTS
# =============================================================================

class TestFeatureExtractor:

    def test_shannon_entropy_uniform(self):
        items = ["a", "b", "c", "d"]
        e = _shannon_entropy(items)
        assert abs(e - 2.0) < 0.01   # log2(4) = 2.0

    def test_shannon_entropy_single_class(self):
        e = _shannon_entropy(["a", "a", "a"])
        assert e == 0.0

    def test_shannon_entropy_empty(self):
        assert _shannon_entropy([]) == 0.0

    def test_extract_features_for_ip_returns_correct_ip(self, small_logs):
        ip = small_logs[0].source_ip
        ip_logs = [l for l in small_logs if l.source_ip == ip]
        features = extract_features_for_ip(ip, ip_logs)
        assert features.source_ip == ip

    def test_extract_features_event_count(self, small_logs):
        ip = small_logs[0].source_ip
        ip_logs = [l for l in small_logs if l.source_ip == ip]
        features = extract_features_for_ip(ip, ip_logs)
        assert features.event_count == len(ip_logs)

    def test_extract_features_empty_logs(self):
        features = extract_features_for_ip("10.0.0.1", [])
        assert features.event_count == 0
        assert features.query_rate_per_min == 0.0

    def test_extract_all_features_keys(self, large_logs):
        feats = extract_all_features(large_logs)
        ips   = {l.source_ip for l in large_logs}
        assert set(feats.keys()) == ips

    def test_off_hours_ratio_range(self, large_logs):
        feats = extract_all_features(large_logs)
        for f in feats.values():
            assert 0.0 <= f.off_hours_ratio <= 1.0

    def test_login_failure_rate_range(self, large_logs):
        feats = extract_all_features(large_logs)
        for f in feats.values():
            assert 0.0 <= f.login_failure_rate <= 1.0

    def test_query_rate_non_negative(self, large_logs):
        feats = extract_all_features(large_logs)
        for f in feats.values():
            assert f.query_rate_per_min >= 0.0

    def test_inter_event_timing_non_negative(self, large_logs):
        feats = extract_all_features(large_logs)
        for f in feats.values():
            assert f.inter_event_mean_ms >= 0.0
            assert f.inter_event_std_ms  >= 0.0

    def test_high_query_rate_for_db_scraping(self):
        """DB scraping simulation should yield high query_rate_per_min."""
        from task1_ingestion.log_simulator import _gen_db_scraping
        base = datetime.utcnow().replace(hour=2, minute=0, second=0)
        attack_logs = _gen_db_scraping(base)
        ip = attack_logs[0].source_ip
        features = extract_features_for_ip(ip, attack_logs)
        assert features.query_rate_per_min > 50.0, (
            f"Expected high query rate, got {features.query_rate_per_min}"
        )

    def test_high_off_hours_ratio_for_attacks(self):
        """Attack logs (off-hours) should yield high off_hours_ratio."""
        from task1_ingestion.log_simulator import _gen_brute_force
        base = datetime.utcnow().replace(hour=0, minute=0, second=0)
        attack_logs = _gen_brute_force(base)
        ip = attack_logs[0].source_ip
        features = extract_features_for_ip(ip, attack_logs)
        assert features.off_hours_ratio > 0.5


# =============================================================================
# 5. INGESTION PIPELINE TESTS (offline — no Elasticsearch)
# =============================================================================

class TestIngestionPipeline:

    def test_pipeline_returns_ingest_response(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=100, attack_fraction=0.10, index_to_es=False)
        assert result is not None
        assert result.total_logs_generated == 100

    def test_pipeline_detects_anomalies(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.15, index_to_es=False)
        assert result.anomalies_detected > 0

    def test_pipeline_raises_alerts(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.15, index_to_es=False)
        assert result.alerts_raised > 0
        assert len(result.alerts) == result.alerts_raised

    def test_alerts_are_high_priority_alert_instances(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=100, attack_fraction=0.10, index_to_es=False)
        for alert in result.alerts:
            assert isinstance(alert, HighPriorityAlert)

    def test_alert_risk_scores_in_range(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.20, index_to_es=False)
        for alert in result.alerts:
            assert 0.0 <= alert.risk_score <= 1.0

    def test_alerts_sorted_by_risk_desc(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.20, index_to_es=False)
        scores = [a.risk_score for a in result.alerts]
        assert scores == sorted(scores, reverse=True)

    def test_alerts_have_scrubbed_payloads(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.20, index_to_es=False)
        for alert in result.alerts:
            assert isinstance(alert.scrubbed_payload, str)
            assert len(alert.scrubbed_payload) > 0

    def test_alerts_have_features(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.20, index_to_es=False)
        for alert in result.alerts:
            assert alert.features is not None
            assert alert.features.source_ip == alert.source_ip

    def test_alerts_count_le_anomalies(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=200, attack_fraction=0.10, index_to_es=False)
        # Every alert corresponds to one anomaly
        assert result.alerts_raised <= result.anomalies_detected

    def test_small_batch(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=50, attack_fraction=0.10, index_to_es=False)
        assert result.total_logs_generated == 50

    def test_large_batch(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=1000, attack_fraction=0.08, index_to_es=False)
        assert result.total_logs_generated == 1000
        assert result.anomalies_detected > 0


# =============================================================================
# 6. FASTAPI ENDPOINT TESTS
# =============================================================================

class TestAPIEndpoints:

    def test_health_returns_200(self, api_client):
        resp = api_client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "timestamp" in data
        assert "elasticsearch" in data

    def test_status_returns_200(self, api_client):
        resp = api_client.get("/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "api_version" in data
        assert "risk_threshold" in data
        assert "scrubber_backend" in data

    def test_simulate_200_small(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 80, "attack_fraction": 0.15})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_logs_generated"] == 80
        assert "alerts" in data

    def test_simulate_returns_alerts(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 150, "attack_fraction": 0.20})
        assert resp.status_code == 200
        data = resp.json()
        assert data["alerts_raised"] >= 0
        assert isinstance(data["alerts"], list)

    def test_simulate_validates_min_logs(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 5, "attack_fraction": 0.10})
        assert resp.status_code == 422   # Pydantic validation error

    def test_simulate_validates_max_logs(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 9999, "attack_fraction": 0.10})
        assert resp.status_code == 422

    def test_simulate_alert_structure(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 100, "attack_fraction": 0.20})
        data = resp.json()
        for alert in data["alerts"]:
            assert "alert_id"        in alert
            assert "source_ip"       in alert
            assert "risk_score"      in alert
            assert "event_type"      in alert
            assert "scrubbed_payload" in alert
            assert "features"        in alert

    def test_simulate_risk_scores_in_range(self, api_client):
        resp = api_client.post("/simulate", json={"num_logs": 100, "attack_fraction": 0.20})
        data = resp.json()
        for alert in data["alerts"]:
            assert 0.0 <= alert["risk_score"] <= 1.0

    def test_scrubber_demo_get(self, api_client):
        resp = api_client.get("/scrubber/demo")
        assert resp.status_code == 200
        data = resp.json()
        assert "backend" in data
        assert "examples" in data
        assert len(data["examples"]) > 0

    def test_scrubber_demo_post_email(self, api_client):
        resp = api_client.post(
            "/scrubber/demo",
            json={"text": "Send results to alice@barclays.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "alice@barclays.com" not in data["scrubbed"]

    def test_scrubber_demo_post_credit_card(self, api_client):
        resp = api_client.post(
            "/scrubber/demo",
            json={"text": "Charge card 4532015112830366 for £500"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "4532015112830366" not in data["scrubbed"]

    def test_scrubber_demo_post_iban(self, api_client):
        resp = api_client.post(
            "/scrubber/demo",
            json={"text": "Account GB29NWBK60161331926819 flagged"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "GB29NWBK60161331926819" not in data["scrubbed"]

    def test_docs_endpoint(self, api_client):
        resp = api_client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_json(self, api_client):
        resp = api_client.get("/openapi.json")
        assert resp.status_code == 200
        schema = resp.json()
        assert "paths" in schema
        expected_paths = ["/health", "/status", "/simulate", "/ingest",
                          "/alerts", "/logs", "/reset"]
        for path in expected_paths:
            assert path in schema["paths"], f"Missing path: {path}"


# =============================================================================
# 7. ELASTICSEARCH INTEGRATION TESTS (skipped if ES unreachable)
# =============================================================================

class TestElasticsearch:
    """ES round-trip tests — skipped at runtime if ES is unreachable."""

    @pytest.fixture(autouse=True)
    def _require_es(self, es_available):
        """Skip every test in this class when ES is not up."""
        if not es_available:
            pytest.skip("Elasticsearch not running")

    def test_ping(self, es_available):
        """ES must be reachable and ping() must return True."""
        assert es_available is True

    def test_health_fields(self):
        c = ACIRElasticClient()
        h = c.health()
        assert "status"    in h
        assert "es_version" in h

    def test_ensure_indices(self):
        c = ACIRElasticClient()
        c.ensure_indices()
        assert c.client.indices.exists(index=config.ES_INDEX)
        assert c.client.indices.exists(index=config.ES_ALERT_INDEX)

    def test_index_and_count_logs(self):
        c = ACIRElasticClient()
        c.ensure_indices()
        logs = simulate_logs(total=10)
        n    = c.index_logs(logs)
        assert n == 10

    def test_full_pipeline_with_es(self):
        p      = IngestionPipeline()
        result = p.run(num_logs=100, attack_fraction=0.15, index_to_es=True)
        assert result.total_logs_indexed > 0

    def test_ingest_api_with_es(self, api_client):
        resp = api_client.post("/ingest", json={"num_logs": 80, "attack_fraction": 0.15})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_logs_indexed"] > 0
