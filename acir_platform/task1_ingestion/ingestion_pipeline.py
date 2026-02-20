# =============================================================================
# ingestion_pipeline.py — Orchestrates the full Task 1 pipeline
#
# Flow:
#   simulate_logs()
#       → index raw logs to Elasticsearch
#       → score with PyOD anomaly engine
#       → scrub PII with Presidio / regex
#       → extract time-series features per IP
#       → assemble HighPriorityAlert objects
#       → index alerts to Elasticsearch
#       → return IngestResponse
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
from datetime import datetime
from models import (
    RawLog, ScoredLog, ScrubbedLog, TimeSeriesFeatures,
    HighPriorityAlert, IngestResponse,
)
import config

from task1_ingestion.log_simulator    import simulate_logs
from task1_ingestion.elasticsearch_client import ACIRElasticClient
from task1_ingestion.anomaly_engine   import AnomalyEngine
from task1_ingestion.pii_scrubber     import scrub_logs
from task1_ingestion.feature_extractor import extract_all_features

logger = logging.getLogger(__name__)


# ── Pipeline ───────────────────────────────────────────────────────────────────

class IngestionPipeline:
    """
    Main entry point for Task 1: ingests simulated logs and produces
    HighPriorityAlert objects, indexing everything to Elasticsearch.
    """

    def __init__(self, es_client: ACIRElasticClient | None = None):
        self.es      = es_client or ACIRElasticClient()
        self.engine  = AnomalyEngine(contamination=config.CONTAMINATION)
        self._fitted = False

    # ── Internal steps ─────────────────────────────────────────────────────────

    def _score(self, logs: list[RawLog]) -> list[ScoredLog]:
        if not self._fitted:
            scored = self.engine.score(logs)   # cold-start: fits + scores
            self._fitted = True
        else:
            scored = self.engine.score(logs)
        return scored

    def _build_alerts(
        self,
        scored_anomalies: list[ScoredLog],
        scrubbed:         list[ScrubbedLog],
        all_logs:         list[RawLog],
    ) -> list[HighPriorityAlert]:
        """
        For each anomaly, assemble a HighPriorityAlert using:
          - the scrubbed payload from the PII scrubber
          - time-series features extracted from all logs for the same source IP
        """
        # Build a dict: log_id → scrubbed_payload
        scrub_map = {s.log_id: s for s in scrubbed}

        # Extract features for all IPs using the full log batch
        ip_features = extract_all_features(all_logs)

        alerts = []
        for scored in sorted(scored_anomalies, key=lambda s: s.anomaly_score, reverse=True):
            log       = scored.log
            scrubbed_entry = scrub_map.get(log.log_id)
            scrubbed_payload = (
                scrubbed_entry.scrubbed_payload if scrubbed_entry
                else log.payload
            )

            features = ip_features.get(
                log.source_ip,
                TimeSeriesFeatures(
                    source_ip=log.source_ip,
                    window_start=log.timestamp,
                    window_end=log.timestamp,
                    event_count=1,
                    unique_dest_ips=1,
                    login_failure_rate=0.0,
                    query_rate_per_min=0.0,
                    inter_event_mean_ms=0.0,
                    inter_event_std_ms=0.0,
                    session_entropy=0.0,
                    off_hours_ratio=float(
                        log.timestamp.hour < 8 or log.timestamp.hour >= 18
                    ),
                ),
            )

            alerts.append(HighPriorityAlert(
                timestamp=log.timestamp,
                source_ip=log.source_ip,
                event_type=log.event_type,
                risk_score=round(scored.anomaly_score, 4),
                severity=log.severity,
                scrubbed_payload=scrubbed_payload,
                features=features,
                raw_log_ids=[log.log_id],
            ))

        return alerts

    # ── Public API ──────────────────────────────────────────────────────────────

    def run(
        self,
        num_logs: int = 500,
        attack_fraction: float = 0.08,
        index_to_es: bool = True,
        reset_indices: bool = False,
    ) -> IngestResponse:
        """
        Execute the full ingestion pipeline.

        Args:
            num_logs:        Number of logs to simulate.
            attack_fraction: Fraction of logs that are attack events.
            index_to_es:     Whether to write to Elasticsearch.
            reset_indices:   Whether to reset ES indices before running.

        Returns:
            IngestResponse summary.
        """
        start = datetime.utcnow()
        logger.info(f"Pipeline starting — {num_logs} logs, "
                    f"attack_fraction={attack_fraction:.0%}")

        # ── 1. Simulate logs ───────────────────────────────────────────────────
        logs = simulate_logs(total=num_logs, attack_fraction=attack_fraction)
        logger.info(f"  [1/5] Simulated {len(logs)} logs")

        # ── 2. Index raw logs to Elasticsearch ────────────────────────────────
        if index_to_es:
            if reset_indices:
                self.es.reset()
            else:
                self.es.ensure_indices()
            indexed = self.es.index_logs(logs)
            logger.info(f"  [2/5] Indexed {indexed} logs to Elasticsearch")
        else:
            indexed = 0
            logger.info("  [2/5] ES indexing skipped (index_to_es=False)")

        # ── 3. Score with anomaly engine ──────────────────────────────────────
        scored = self._score(logs)
        anomalies = [s for s in scored if s.is_anomaly]
        logger.info(f"  [3/5] Detected {len(anomalies)} anomalies "
                    f"(threshold={config.RISK_THRESHOLD})")

        # ── 4. Scrub PII from anomalies ───────────────────────────────────────
        scrubbed = scrub_logs(anomalies)
        logger.info(f"  [4/5] PII scrubbed from {len(scrubbed)} anomalous logs")

        # ── 5. Assemble and index alerts ──────────────────────────────────────
        alerts = self._build_alerts(anomalies, scrubbed, logs)

        if index_to_es:
            for alert in alerts:
                self.es.index_alert(alert)
            logger.info(f"  [5/5] Indexed {len(alerts)} alerts")

        elapsed = (datetime.utcnow() - start).total_seconds()
        logger.info(f"Pipeline complete in {elapsed:.2f}s — "
                    f"{len(alerts)} alerts raised.")

        return IngestResponse(
            total_logs_generated=len(logs),
            total_logs_indexed=indexed,
            anomalies_detected=len(anomalies),
            alerts_raised=len(alerts),
            alerts=alerts,
        )


# ── Convenience function ───────────────────────────────────────────────────────

def run_pipeline(
    num_logs: int = 500,
    attack_fraction: float = 0.08,
    index_to_es: bool = True,
    reset_indices: bool = False,
) -> IngestResponse:
    """Run the ingestion pipeline with default settings."""
    pipeline = IngestionPipeline()
    return pipeline.run(
        num_logs=num_logs,
        attack_fraction=attack_fraction,
        index_to_es=index_to_es,
        reset_indices=reset_indices,
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  [%(levelname)s]  %(name)s: %(message)s",
    )

    print("Running ACIR Task 1 ingestion pipeline...\n")
    result = run_pipeline(num_logs=300, attack_fraction=0.10, index_to_es=False)

    print(f"\n{'='*55}")
    print(f"  Logs generated   : {result.total_logs_generated}")
    print(f"  Anomalies found  : {result.anomalies_detected}")
    print(f"  Alerts raised    : {result.alerts_raised}")
    print(f"{'='*55}")
    if result.alerts:
        top = result.alerts[0]
        print(f"\nTop alert:")
        print(f"  IP         : {top.source_ip}")
        print(f"  Event type : {top.event_type}")
        print(f"  Risk score : {top.risk_score}")
        print(f"  Severity   : {top.severity}")
        print(f"  Payload    : {top.scrubbed_payload[:120]}...")
