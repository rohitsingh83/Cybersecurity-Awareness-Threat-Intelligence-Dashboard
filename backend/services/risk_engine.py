"""Transparent, illustrative scoring functions. Scores prioritize review; they do not confirm compromise."""
from __future__ import annotations
import math

SEVERITY_POINTS = {"INFORMATIONAL": 10, "LOW": 30, "MEDIUM": 55, "HIGH": 78, "CRITICAL": 96}
RELIABILITY_POINTS = {"A": 100, "B": 80, "C": 60, "D": 35, "UNKNOWN": 35}


def clamp_score(value: float) -> int:
    return max(0, min(100, int(round(value))))


def classify_risk(score: int | float) -> str:
    score = clamp_score(float(score))
    if score <= 20:
        return "INFORMATIONAL"
    if score <= 40:
        return "LOW"
    if score <= 60:
        return "MEDIUM"
    if score <= 80:
        return "HIGH"
    return "CRITICAL"


def classify_cvss(score: float) -> str:
    """Convert a CVSS base score to the commonly used CVSS severity band."""
    value = max(0.0, min(10.0, float(score)))
    if value == 0:
        return "INFORMATIONAL"
    if value < 4.0:
        return "LOW"
    if value < 7.0:
        return "MEDIUM"
    if value < 9.0:
        return "HIGH"
    return "CRITICAL"


def source_reliability_score(level: str | None) -> int:
    return RELIABILITY_POINTS.get((level or "UNKNOWN").strip().upper(), 35)


def _frequency_score(observation_count: int) -> float:
    # Logarithmic scaling avoids allowing a high-volume feed to dominate the score.
    count = max(0, int(observation_count))
    return min(100.0, 100.0 * math.log1p(count) / math.log1p(100))


def calculate_threat_risk(
    severity: str = "MEDIUM",
    confidence: int | float = 50,
    recency: int | float = 50,
    observation_count: int = 1,
    source_reliability: str = "C",
    related_alerts: int = 0,
    context: int | float = 50,
) -> int:
    """Weighted 0–100 score: severity 30%, confidence 25%, recency 15%,
    observations 10%, source reliability 10%, context/correlation 10%.

    The related-alert count contributes a bounded signal to context, not proof.
    """
    severity_points = SEVERITY_POINTS.get((severity or "MEDIUM").upper(), 55)
    context_points = max(0.0, min(100.0, float(context)))
    alert_signal = min(100.0, max(0, int(related_alerts)) * 20.0)
    combined_context = 0.7 * context_points + 0.3 * alert_signal
    score = (
        severity_points * 0.30
        + max(0, min(100, float(confidence))) * 0.25
        + max(0, min(100, float(recency))) * 0.15
        + _frequency_score(observation_count) * 0.10
        + source_reliability_score(source_reliability) * 0.10
        + combined_context * 0.10
    )
    return clamp_score(score)


def calculate_confidence_score(
    source_reliability: str = "C",
    corroboration: int | float = 50,
    freshness: int | float = 50,
    completeness: int | float = 50,
) -> int:
    """Evidence-quality score (separate from risk): source 40%, corroboration 25%, freshness 20%, completeness 15%."""
    return clamp_score(
        source_reliability_score(source_reliability) * 0.40
        + max(0, min(100, float(corroboration))) * 0.25
        + max(0, min(100, float(freshness))) * 0.20
        + max(0, min(100, float(completeness))) * 0.15
    )


def calculate_organizational_risk(
    high_critical_alert_count: int,
    known_exploited_cves_affecting_assets: int,
    awareness_completion_rate: int | float,
) -> dict:
    """Illustrative 0–100 organization-level demo index.

    Component values are normalized to 0–100: 12 high/critical open alerts and
    4 affected known-exploited demo CVEs saturate their components. Awareness
    contributes the completion *gap* (100 - completion rate). These normalization
    constants are teaching defaults, not a calibrated business-risk model.
    """
    alert_pressure = min(100, max(0, int(high_critical_alert_count)) * 12)
    vulnerability_pressure = min(100, max(0, int(known_exploited_cves_affecting_assets)) * 25)
    completion = max(0, min(100, float(awareness_completion_rate)))
    awareness_gap = clamp_score(100 - completion)
    score = clamp_score(alert_pressure * 0.40 + vulnerability_pressure * 0.40 + awareness_gap * 0.20)
    return {
        "score": score,
        "alert_pressure_40_percent": alert_pressure,
        "demo_vulnerability_context_40_percent": vulnerability_pressure,
        "awareness_completion_gap_20_percent": awareness_gap,
    }


def calculate_vulnerability_priority(
    cvss_score: float,
    asset_criticality: int = 50,
    exposure: int = 50,
    known_exploited: bool = False,
    business_context: int = 50,
) -> int:
    """Contextual vulnerability priority; CVSS is only one of five inputs."""
    cvss = max(0.0, min(10.0, float(cvss_score))) * 10
    exploitation = 100 if known_exploited else 20
    score = (
        cvss * 0.30
        + max(0, min(100, asset_criticality)) * 0.25
        + max(0, min(100, exposure)) * 0.15
        + exploitation * 0.20
        + max(0, min(100, business_context)) * 0.10
    )
    return clamp_score(score)
