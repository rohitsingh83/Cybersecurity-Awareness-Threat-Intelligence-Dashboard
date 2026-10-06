"""Local-only indicator enrichment. No DNS, WHOIS, HTTP, or reputation calls are made."""
from __future__ import annotations
from .ioc_validator import validate_indicator


def enrich_indicator(
    value: str,
    threats: list[dict],
    alerts: list[dict] | None = None,
    notes: list[dict] | None = None,
    internal_signals: list[dict] | None = None,
    indicator_type: str | None = None,
) -> dict:
    validation = validate_indicator(value, indicator_type)
    if not validation["valid"]:
        return {**validation, "known_in_demo_dataset": False, "threat_count": 0, "related_indicators": [], "related_alerts": [], "analyst_notes": [], "internal_sightings": [], "interpretation": "Invalid syntax; no lookup was performed."}
    needle = validation["normalized_value"].casefold()
    matches = [t for t in threats if str(t.get("indicator_value", "")).casefold() == needle or str(t.get("cve_id_optional", "")).casefold() == needle]
    match_ids = {str(t.get("threat_id")) for t in matches}
    campaigns = {str(t.get("campaign_id")) for t in matches if t.get("campaign_id")}
    related = [t for t in threats if t not in matches and t.get("campaign_id") and str(t.get("campaign_id")) in campaigns]
    alert_rows = [a for a in (alerts or []) if str(a.get("threat_id")) in match_ids or str(a.get("indicator_value", "")).casefold() == needle]
    note_rows = [n for n in (notes or []) if str(n.get("threat_id")) in match_ids]
    signals = [s for s in (internal_signals or []) if str(s.get("indicator_value", "")).casefold() == needle]
    if not matches:
        return {
            **validation,
            "known_in_demo_dataset": False,
            "threat_count": 0,
            "first_seen": None,
            "last_seen": None,
            "categories": [],
            "confidence_score": None,
            "risk_score": None,
            "severity": None,
            "status": None,
            "source_names": [],
            "source_reliability": None,
            "related_alerts": alert_rows,
            "related_indicators": [],
            "mitre_mappings": [],
            "analyst_notes": note_rows,
            "internal_sightings": signals,
            "interpretation": "No exact match in the local synthetic dataset. This is not an external reputation lookup.",
        }
    latest = max(matches, key=lambda t: str(t.get("last_seen", "")))
    risk = max(int(t.get("risk_score", 0)) for t in matches)
    confidence = max(int(t.get("confidence_score", 0)) for t in matches)
    related_indicators = list(dict.fromkeys(str(t.get("indicator_value")) for t in related))
    mappings = []
    for t in matches:
        if t.get("mitre_tactic_optional") or t.get("mitre_technique_optional"):
            mapping = {
                "tactic": t.get("mitre_tactic_optional"),
                "technique": t.get("mitre_technique_optional"),
                "technique_id": t.get("mitre_technique_id_optional"),
                "threat_id": t.get("threat_id"),
            }
            if mapping not in mappings:
                mappings.append(mapping)
    return {
        **validation,
        "known_in_demo_dataset": True,
        "threat_count": len(matches),
        "first_seen": min(str(t.get("first_seen", "")) for t in matches),
        "last_seen": max(str(t.get("last_seen", "")) for t in matches),
        "categories": sorted({str(t.get("threat_category", "")) for t in matches}),
        "confidence_score": confidence,
        "risk_score": risk,
        "severity": latest.get("severity"),
        "status": latest.get("status"),
        "source_names": sorted({str(t.get("source_name", "")) for t in matches}),
        "source_reliability": latest.get("source_reliability"),
        "related_alerts": alert_rows,
        "related_indicators": related_indicators,
        "mitre_mappings": mappings,
        "analyst_notes": note_rows,
        "internal_sightings": signals,
        "interpretation": "Local synthetic-data match only; an indicator match does not establish compromise or attribution.",
    }
