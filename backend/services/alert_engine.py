"""Local alert decision logic; alerts request analyst review and are not incident declarations."""
from __future__ import annotations
from datetime import datetime, timezone
import uuid
from .risk_engine import classify_risk

ALERT_STATUSES = {"NEW", "INVESTIGATING", "MONITORING", "RESOLVED", "FALSE_POSITIVE"}


def generate_threat_alert(threat: dict, risk_threshold: int = 61, confidence_threshold: int = 35) -> dict | None:
    priority = int(threat.get("priority_score", 0) or 0)
    is_vulnerability = bool(threat.get("is_vulnerability") or threat.get("cve_id") or threat.get("cve_id_optional"))
    risk = int(threat.get("risk_score", priority if is_vulnerability else 0) or 0)
    confidence = int(threat.get("confidence_score", 0) or 0)
    observations = int(threat.get("observed_count", 1) or 1)
    related = int(threat.get("related_indicator_count", 0) or 0)
    reasons = []
    if risk >= risk_threshold and confidence >= confidence_threshold:
        reasons.append("risk and confidence thresholds met")
    if is_vulnerability and (priority >= 80 or (priority >= 65 and str(threat.get("exploitation_status_demo", "")).upper() == "YES")):
        reasons.append("high-priority vulnerability requires patch-review triage")
    if observations >= 5:
        reasons.append("repeated observations")
    if related >= 2:
        reasons.append("correlated indicators present")
    if not reasons:
        return None
    return {
        "alert_id": f"ALT-{uuid.uuid4().hex[:10].upper()}",
        "threat_id": threat.get("threat_id"),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "alert_type": "HIGH_PRIORITY_VULNERABILITY" if is_vulnerability and any("vulnerability" in reason for reason in reasons) else "CORRELATED_INDICATOR" if related >= 2 else "THREAT_REVIEW",
        "severity": classify_risk(risk),
        "risk_score": risk,
        "confidence_score": confidence,
        "description": f"Analyst review recommended: {', '.join(reasons)}. This alert is not a confirmed incident.",
        "status": "NEW",
        "indicator_value": threat.get("indicator_value", ""),
        "observation_count": observations,
        "dedupe_key": f"{threat.get('indicator_type', '')}:{threat.get('indicator_value', '')}:{threat.get('threat_category', '')}".casefold(),
    }


def validate_alert_status(status: str) -> str:
    normalized = (status or "").strip().upper()
    if normalized not in ALERT_STATUSES:
        raise ValueError(f"Status must be one of: {', '.join(sorted(ALERT_STATUSES))}")
    return normalized
