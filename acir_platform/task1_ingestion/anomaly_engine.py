# =============================================================================
# anomaly_engine.py — PyOD-based anomaly scoring for security logs
#
# Uses an ensemble of:
#   - IForest  (Isolation Forest) — global outlier detection
#   - ECOD     (Empirical Cumulative Distribution-based Outlier Detection)
#   - LOF      (Local Outlier Factor)   — density-based local anomalies
#
# Scores are normalised to [0, 1]. Logs above RISK_THRESHOLD are flagged.
# =============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from datetime import datetime
from pyod.models.iforest import IForest
from pyod.models.ecod import ECOD
from pyod.models.lof import LOF
from sklearn.preprocessing import LabelEncoder
from models import RawLog, ScoredLog
import config
import logging

logger = logging.getLogger(__name__)

# ── Feature engineering ───────────────────────────────────────────────────────

_EVENT_TYPE_ORDER = [
    "login_success", "logout", "file_read", "api_call",
    "db_query", "email_sent", "vpn_connect", "vpn_disconnect",
    "password_change", "mfa_success",
    # attack types — higher index = more suspicious
    "login_failed", "ssh_connect", "port_probe",
    "db_query_burst", "data_transfer",
]
_EVT_ENCODER = {e: i for i, e in enumerate(_EVENT_TYPE_ORDER)}

_SEVERITY_MAP  = {"INFO": 0, "WARNING": 1, "CRITICAL": 2}
_SOURCE_MAP    = {"SIEM": 0, "EDR": 1, "NETWORK": 2}


def _ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP to integer for numeric feature use."""
    try:
        parts = ip.split(".")
        return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                int(parts[2]) << 8  | int(parts[3]))
    except Exception:
        return 0


def _extract_features(logs: list[RawLog]) -> np.ndarray:
    """
    Convert a list of RawLog objects into a numeric feature matrix.
    Shape: (n_logs, n_features)
    """
    rows = []
    for log in logs:
        hour         = log.timestamp.hour
        is_offhours  = int(hour < 8 or hour > 18)
        evt_code     = _EVT_ENCODER.get(log.event_type, len(_EVENT_TYPE_ORDER))
        sev_code     = _SEVERITY_MAP.get(log.severity, 0)
        src_code     = _SOURCE_MAP.get(log.source, 0)
        src_ip_int   = _ip_to_int(log.source_ip) & 0xFF   # last octet only
        payload_len  = len(log.payload)
        has_external = int(log.source_ip.startswith(("10.", "172.", "192.168.")))

        rows.append([
            hour,
            is_offhours,
            evt_code,
            sev_code,
            src_code,
            src_ip_int,
            payload_len,
            has_external,
        ])

    return np.array(rows, dtype=float)


# ── Ensemble model ─────────────────────────────────────────────────────────────

class AnomalyEngine:
    """
    Ensemble anomaly detector: IForest + ECOD + LOF.
    Call .fit() once on a baseline, then .score() on new logs.
    """

    def __init__(self, contamination: float = config.CONTAMINATION):
        self.contamination = contamination
        self._iforest = IForest(contamination=contamination, random_state=42, n_estimators=100)
        self._ecod    = ECOD(contamination=contamination)
        self._lof     = LOF(contamination=contamination, n_neighbors=20)
        self._fitted  = False

    def fit(self, logs: list[RawLog]) -> "AnomalyEngine":
        """Train all three detectors on the provided logs."""
        if len(logs) < 10:
            raise ValueError("Need at least 10 logs to train the anomaly engine.")
        X = _extract_features(logs)
        self._iforest.fit(X)
        self._ecod.fit(X)
        self._lof.fit(X)
        self._fitted = True
        logger.info(f"AnomalyEngine fitted on {len(logs)} logs.")
        return self

    def score(self, logs: list[RawLog]) -> list[ScoredLog]:
        """
        Score each log. Returns ScoredLog with normalised anomaly_score [0,1].
        If the engine has not been fitted yet, it auto-fits on the provided logs
        (cold-start behaviour for live ingestion).
        """
        if not self._fitted:
            logger.warning("AnomalyEngine not fitted — running cold-start fit+score.")
            self.fit(logs)

        X = _extract_features(logs)

        # Raw decision scores (higher = more anomalous for all three)
        s_iforest = self._iforest.decision_function(X)
        s_ecod    = self._ecod.decision_function(X)
        s_lof     = self._lof.decision_function(X)

        # Normalise each to [0, 1]
        def _norm(arr: np.ndarray) -> np.ndarray:
            mn, mx = arr.min(), arr.max()
            if mx == mn:
                return np.zeros_like(arr)
            return (arr - mn) / (mx - mn)

        n_iforest = _norm(s_iforest)
        n_ecod    = _norm(s_ecod)
        n_lof     = _norm(s_lof)

        # Weighted ensemble: IForest 40%, ECOD 40%, LOF 20%
        ensemble = 0.4 * n_iforest + 0.4 * n_ecod + 0.2 * n_lof

        results = []
        for i, log in enumerate(logs):
            score     = float(ensemble[i])
            is_anomaly = score >= config.RISK_THRESHOLD
            results.append(ScoredLog(log=log, anomaly_score=score, is_anomaly=is_anomaly))

        anomaly_count = sum(1 for r in results if r.is_anomaly)
        logger.info(
            f"Scored {len(logs)} logs | "
            f"Anomalies: {anomaly_count} ({anomaly_count/len(logs)*100:.1f}%) | "
            f"Threshold: {config.RISK_THRESHOLD}"
        )
        return results


# ── Convenience: score without managing the engine manually ───────────────────

_default_engine: AnomalyEngine | None = None


def score_logs(logs: list[RawLog]) -> list[ScoredLog]:
    """
    Score a batch of logs using the module-level default engine.
    Auto-trains on first call.
    """
    global _default_engine
    if _default_engine is None:
        _default_engine = AnomalyEngine()
    return _default_engine.score(logs)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from task1_ingestion.log_simulator import simulate_logs

    logs   = simulate_logs(total=300, attack_fraction=0.10)
    engine = AnomalyEngine(contamination=0.1)
    scored = engine.score(logs)

    high = [s for s in scored if s.is_anomaly]
    print(f"Total logs   : {len(scored)}")
    print(f"Anomalies    : {len(high)}")
    print(f"\nTop 5 anomalies:")
    for s in sorted(high, key=lambda x: x.anomaly_score, reverse=True)[:5]:
        print(f"  score={s.anomaly_score:.3f}  type={s.log.event_type}  "
              f"ip={s.log.source_ip}  hour={s.log.timestamp.hour}")
