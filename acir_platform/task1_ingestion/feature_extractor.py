# =============================================================================
# feature_extractor.py — Time-series feature extraction per source IP
#
# Groups logs into sliding windows per source IP and extracts:
#   - Event rate statistics
#   - Login failure rates
#   - Session entropy (Shannon)
#   - Off-hours activity ratio
#   - Inter-event timing statistics
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from models import RawLog, ScrubbedLog, TimeSeriesFeatures
import config
import logging

logger = logging.getLogger(__name__)


# ── Shannon entropy ────────────────────────────────────────────────────────────

def _shannon_entropy(items: list) -> float:
    """Compute Shannon entropy of a list of categorical values."""
    if not items:
        return 0.0
    counts = Counter(items)
    total  = len(items)
    return -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )


# ── Per-IP feature extraction ─────────────────────────────────────────────────

def extract_features_for_ip(
    ip: str,
    logs: list[RawLog],
    window_secs: int = config.ANOMALY_WINDOW_SECS,
) -> TimeSeriesFeatures:
    """
    Extract time-series features from a window of logs for a single source IP.

    Args:
        ip:          The source IP address.
        logs:        All logs from this IP (pre-filtered).
        window_secs: Window size in seconds.

    Returns:
        TimeSeriesFeatures Pydantic model.
    """
    if not logs:
        now = datetime.utcnow()
        return TimeSeriesFeatures(
            source_ip=ip,
            window_start=now - timedelta(seconds=window_secs),
            window_end=now,
            event_count=0,
            unique_dest_ips=0,
            login_failure_rate=0.0,
            query_rate_per_min=0.0,
            inter_event_mean_ms=0.0,
            inter_event_std_ms=0.0,
            session_entropy=0.0,
            off_hours_ratio=0.0,
        )

    # Sort by timestamp
    logs_sorted = sorted(logs, key=lambda l: l.timestamp)
    window_start = logs_sorted[0].timestamp
    window_end   = logs_sorted[-1].timestamp

    # ── Counts ────────────────────────────────────────────────────────────────
    event_count    = len(logs_sorted)
    dest_ips       = {l.dest_ip for l in logs_sorted if l.dest_ip}
    unique_dests   = len(dest_ips)

    # ── Login failure rate ─────────────────────────────────────────────────
    login_events  = [l for l in logs_sorted if "login" in l.event_type]
    login_failures = [l for l in login_events if l.event_type == "login_failed"]
    login_failure_rate = (
        len(login_failures) / len(login_events) if login_events else 0.0
    )

    # ── Query rate ─────────────────────────────────────────────────────────
    db_queries  = [l for l in logs_sorted if "db_query" in l.event_type or "data_transfer" in l.event_type]
    duration_min = max(
        (window_end - window_start).total_seconds() / 60.0,
        1 / 60.0   # floor at 1 second to avoid division by zero
    )
    query_rate_per_min = len(db_queries) / duration_min

    # ── Inter-event timing ─────────────────────────────────────────────────
    if len(logs_sorted) > 1:
        deltas_ms = [
            (logs_sorted[i+1].timestamp - logs_sorted[i].timestamp).total_seconds() * 1000
            for i in range(len(logs_sorted) - 1)
        ]
        mean_ms = sum(deltas_ms) / len(deltas_ms)
        variance = sum((d - mean_ms) ** 2 for d in deltas_ms) / len(deltas_ms)
        std_ms   = math.sqrt(variance)
    else:
        mean_ms = 0.0
        std_ms  = 0.0

    # ── Shannon entropy of event types ────────────────────────────────────
    event_types   = [l.event_type for l in logs_sorted]
    sess_entropy  = _shannon_entropy(event_types)

    # ── Off-hours ratio ────────────────────────────────────────────────────
    off_hours = sum(
        1 for l in logs_sorted
        if l.timestamp.hour < 8 or l.timestamp.hour >= 18
    )
    off_hours_ratio = off_hours / event_count

    return TimeSeriesFeatures(
        source_ip=ip,
        window_start=window_start,
        window_end=window_end,
        event_count=event_count,
        unique_dest_ips=unique_dests,
        login_failure_rate=round(login_failure_rate, 4),
        query_rate_per_min=round(query_rate_per_min, 4),
        inter_event_mean_ms=round(mean_ms, 2),
        inter_event_std_ms=round(std_ms, 2),
        session_entropy=round(sess_entropy, 4),
        off_hours_ratio=round(off_hours_ratio, 4),
    )


def extract_all_features(
    logs: list[RawLog],
    window_secs: int = config.ANOMALY_WINDOW_SECS,
) -> dict[str, TimeSeriesFeatures]:
    """
    Group logs by source IP and extract features per IP.

    Returns:
        dict mapping source_ip → TimeSeriesFeatures
    """
    by_ip: dict[str, list[RawLog]] = defaultdict(list)
    for log in logs:
        by_ip[log.source_ip].append(log)

    features = {}
    for ip, ip_logs in by_ip.items():
        features[ip] = extract_features_for_ip(ip, ip_logs, window_secs)

    logger.info(f"Extracted features for {len(features)} unique source IPs.")
    return features


if __name__ == "__main__":
    from task1_ingestion.log_simulator import simulate_logs

    logs  = simulate_logs(total=300, attack_fraction=0.1)
    feats = extract_all_features(logs)

    # Show the IP with highest query rate
    top = max(feats.values(), key=lambda f: f.query_rate_per_min)
    print(f"\nHighest DB query rate IP: {top.source_ip}")
    print(f"  query_rate_per_min : {top.query_rate_per_min}")
    print(f"  off_hours_ratio    : {top.off_hours_ratio}")
    print(f"  session_entropy    : {top.session_entropy}")
    print(f"  login_failure_rate : {top.login_failure_rate}")
    print(f"  event_count        : {top.event_count}")
