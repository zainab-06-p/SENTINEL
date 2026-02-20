# =============================================================================
# elasticsearch_client.py — Elasticsearch connection, index management,
#                            log indexing and querying helpers
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import NotFoundError, ConnectionError as ESConnectionError
from datetime import datetime
from models import RawLog, HighPriorityAlert
import config
import logging

logger = logging.getLogger(__name__)

# ── Index mappings ─────────────────────────────────────────────────────────────

RAW_LOG_MAPPING = {
    "mappings": {
        "properties": {
            "log_id":      {"type": "keyword"},
            "timestamp":   {"type": "date"},
            "source_ip":   {"type": "ip"},
            "dest_ip":     {"type": "ip"},
            "event_type":  {"type": "keyword"},
            "username":    {"type": "keyword"},
            "payload":     {"type": "text"},
            "severity":    {"type": "keyword"},
            "source":      {"type": "keyword"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}

ALERT_MAPPING = {
    "mappings": {
        "properties": {
            "alert_id":          {"type": "keyword"},
            "timestamp":         {"type": "date"},
            "source_ip":         {"type": "ip"},
            "event_type":        {"type": "keyword"},
            "risk_score":        {"type": "float"},
            "severity":          {"type": "keyword"},
            "scrubbed_payload":  {"type": "text"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
}


class ACIRElasticClient:
    """Thin wrapper around the Elasticsearch Python client for ACIR operations."""

    def __init__(self, host: str = config.ES_HOST):
        self.host = host
        self.client = Elasticsearch(host, request_timeout=10)

    # ── Connection ────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Returns True if Elasticsearch is reachable."""
        try:
            return self.client.ping()
        except ESConnectionError:
            return False

    def health(self) -> dict:
        """Cluster health summary."""
        if not self.ping():
            return {"status": "unreachable"}
        info = self.client.info()
        cluster = self.client.cluster.health()
        return {
            "status":          cluster["status"],
            "cluster_name":    info["cluster_name"],
            "es_version":      info["version"]["number"],
            "active_shards":   cluster["active_shards"],
        }

    # ── Index management ──────────────────────────────────────────────────────

    def ensure_indices(self):
        """Create indices if they don't already exist."""
        for index, mapping in [
            (config.ES_INDEX, RAW_LOG_MAPPING),
            (config.ES_ALERT_INDEX, ALERT_MAPPING),
        ]:
            if not self.client.indices.exists(index=index):
                self.client.indices.create(index=index, body=mapping)
                logger.info(f"Created index: {index}")
            else:
                logger.debug(f"Index already exists: {index}")

    def delete_indices(self):
        """Drop both indices (useful for resetting demo state)."""
        for index in [config.ES_INDEX, config.ES_ALERT_INDEX]:
            try:
                self.client.indices.delete(index=index)
                logger.info(f"Deleted index: {index}")
            except NotFoundError:
                pass

    def reset(self):
        """Delete and recreate all indices."""
        self.delete_indices()
        self.ensure_indices()

    # ── Indexing ──────────────────────────────────────────────────────────────

    def index_logs(self, logs: list[RawLog]) -> int:
        """Bulk-index a list of RawLog objects. Returns count of indexed docs."""
        if not logs:
            return 0

        actions = [
            {
                "_index": config.ES_INDEX,
                "_id":    log.log_id,
                "_source": {
                    **log.model_dump(),
                    "timestamp": log.timestamp.isoformat(),
                },
            }
            for log in logs
        ]
        success, _ = helpers.bulk(self.client, actions, raise_on_error=False)
        self.client.indices.refresh(index=config.ES_INDEX)
        return success

    def index_alert(self, alert: HighPriorityAlert) -> str:
        """Index a single HighPriorityAlert. Returns document ID."""
        doc = alert.model_dump()
        doc["timestamp"]    = alert.timestamp.isoformat()
        doc["features"]     = alert.features.model_dump()
        doc["features"]["window_start"] = alert.features.window_start.isoformat()
        doc["features"]["window_end"]   = alert.features.window_end.isoformat()

        resp = self.client.index(
            index=config.ES_ALERT_INDEX,
            id=alert.alert_id,
            document=doc,
        )
        self.client.indices.refresh(index=config.ES_ALERT_INDEX)
        return resp["_id"]

    # ── Querying ──────────────────────────────────────────────────────────────

    def get_recent_logs(self, size: int = 100) -> list[dict]:
        """Return the most recent raw logs."""
        resp = self.client.search(
            index=config.ES_INDEX,
            body={
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": size,
            },
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def get_alerts(self, min_risk: float = 0.0, size: int = 100) -> list[dict]:
        """Return alerts above a minimum risk score, newest first."""
        resp = self.client.search(
            index=config.ES_ALERT_INDEX,
            body={
                "query": {"range": {"risk_score": {"gte": min_risk}}},
                "sort":  [{"risk_score": {"order": "desc"}}],
                "size":  size,
            },
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def count_logs(self) -> int:
        """Total number of raw logs indexed."""
        return self.client.count(index=config.ES_INDEX)["count"]

    def count_alerts(self) -> int:
        """Total number of alerts indexed."""
        return self.client.count(index=config.ES_ALERT_INDEX)["count"]

    def search_by_ip(self, ip: str, index: str | None = None) -> list[dict]:
        """Find all log entries from a given source IP."""
        idx = index or config.ES_INDEX
        resp = self.client.search(
            index=idx,
            body={
                "query": {"term": {"source_ip": ip}},
                "sort":  [{"timestamp": {"order": "asc"}}],
                "size":  500,
            },
        )
        return [hit["_source"] for hit in resp["hits"]["hits"]]


# ── Module-level convenience instance ─────────────────────────────────────────
_client: ACIRElasticClient | None = None


def get_es_client() -> ACIRElasticClient:
    global _client
    if _client is None:
        _client = ACIRElasticClient()
    return _client


if __name__ == "__main__":
    c = ACIRElasticClient()
    if c.ping():
        print("✓ Elasticsearch reachable")
        c.ensure_indices()
        print("Health:", c.health())
    else:
        print("✗ Cannot reach Elasticsearch at", config.ES_HOST)
