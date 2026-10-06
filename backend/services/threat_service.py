"""Threat record normalization and query helpers."""
from __future__ import annotations
from datetime import datetime, timezone
from .ioc_validator import validate_indicator
from .risk_engine import calculate_confidence_score, calculate_threat_risk, classify_risk

CATEGORIES = {
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS",
    "NETWORK THREATS", "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING",
    "DATA EXPOSURE", "ACCOUNT SECURITY",
}
STATUSES = {"NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"}


def normalize_threat(raw: dict) -> dict:
    """Validate/standardize a threat record without doing network enrichment."""
    category = str(raw.get("threat_category") or raw.get("category") or "").strip().upper()
    if category not in CATEGORIES:
        raise ValueError("Unsupported threat category")
    indicator_value = str(raw.get("indicator_value") or "").strip()
    validation = validate_indicator(indicator_value, raw.get("indicator_type"))
    if not validation["valid"]:
        raise ValueError("Indicator syntax is invalid: " + validation["validation_notes"])
    status = str(raw.get("status", "NEW")).strip().upper()
    if status not in STATUSES:
        raise ValueError("Unsupported threat status")
    reliability = str(raw.get("source_reliability", "C")).upper()
    confidence = int(raw.get("confidence_score", calculate_confidence_score(reliability)))
    if not 0 <= confidence <= 100:
        raise ValueError("confidence_score must be between 0 and 100")
    risk = raw.get("risk_score")
    if risk is None:
        risk = calculate_threat_risk(
            severity=str(raw.get("severity", "MEDIUM")),
            confidence=confidence,
            recency=int(raw.get("recency_score", 50)),
            observation_count=int(raw.get("observed_count", 1)),
            source_reliability=reliability,
            context=int(raw.get("context_score", 50)),
        )
    risk = int(risk)
    if not 0 <= risk <= 100:
        raise ValueError("risk_score must be between 0 and 100")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    first_seen = str(raw.get("first_seen") or now)
    last_seen = str(raw.get("last_seen") or first_seen)
    return {
        "threat_id": str(raw.get("threat_id") or "").strip() or f"THR-{int(datetime.now().timestamp())}",
        "threat_name": str(raw.get("threat_name") or "Unclassified synthetic observation")[:160],
        "threat_category": category,
        "indicator_type": validation["indicator_type"],
        "indicator_value": validation["normalized_value"],
        "source_name": str(raw.get("source_name") or "Unknown Source")[:100],
        "source_reliability": reliability,
        "confidence_score": confidence,
        "severity": classify_risk(risk),
        "risk_score": risk,
        "status": status,
        "timestamp": str(raw.get("timestamp") or now),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "country_or_region_optional": str(raw.get("country_or_region_optional") or "Demo / not geo-enriched"),
        "description": str(raw.get("description") or "Synthetic observation awaiting analyst review.")[:1200],
        "mitre_tactic_optional": raw.get("mitre_tactic_optional"),
        "mitre_technique_optional": raw.get("mitre_technique_optional"),
        "mitre_technique_id_optional": raw.get("mitre_technique_id_optional"),
        "cve_id_optional": raw.get("cve_id_optional"),
        "campaign_id": raw.get("campaign_id"),
        "observed_count": max(1, int(raw.get("observed_count", 1))),
        "synthetic_label": "SYNTHETIC / DEMO ONLY",
    }
