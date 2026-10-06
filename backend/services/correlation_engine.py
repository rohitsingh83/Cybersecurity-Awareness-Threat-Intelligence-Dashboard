"""Defensive grouping helpers. Correlation is a relationship hypothesis, not attribution."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone


def _parse_time(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def correlate_threats(records: list[dict], window_hours: int = 24) -> list[dict]:
    """Group records using explicit campaign/correlation IDs, or cautious same-category windows.

    Heuristic clusters require at least two distinct indicators and are labelled tentative.
    """
    explicit = defaultdict(list)
    fallback = defaultdict(list)
    for record in records:
        campaign = record.get("campaign_id")
        analyst_group = record.get("analyst_correlation_id") or record.get("correlation_id")
        if campaign:
            explicit[("campaign_id", str(campaign))].append(record)
        elif analyst_group:
            explicit[("analyst_correlation_id", str(analyst_group))].append(record)
        else:
            when = _parse_time(record.get("timestamp") or record.get("first_seen"))
            if when and record.get("threat_category"):
                bucket = int(when.timestamp() // (max(1, window_hours) * 3600))
                fallback[(str(record.get("threat_category")).upper(), bucket)].append(record)

    clusters = []
    for (basis, group_id), members in explicit.items():
        unique = {str(x.get("indicator_value", x.get("threat_id", ""))).casefold() for x in members}
        if len(members) >= 2 and len(unique) >= 2:
            clusters.append(_cluster(members, basis, group_id, "SUPPORTED BY SHARED SYNTHETIC GROUP ID"))
    for (category, bucket), members in fallback.items():
        unique = {str(x.get("indicator_value", x.get("threat_id", ""))).casefold() for x in members}
        if len(members) >= 2 and len(unique) >= 2:
            clusters.append(_cluster(members, "category_and_time_window", f"{category}:{bucket}", "TENTATIVE HEURISTIC; REVIEW BEFORE ACTION"))
    return sorted(clusters, key=lambda x: (x["relationship_basis"], x["cluster_id"]))


def _cluster(members, basis, group_id, evidence):
    return {
        "cluster_id": str(group_id),
        "relationship_basis": basis,
        "evidence_label": evidence,
        "attribution": "NOT ESTABLISHED",
        "threat_count": len(members),
        "indicator_count": len({str(x.get("indicator_value", "")).casefold() for x in members}),
        "threats": members,
    }


def correlate_alerts(events: list[dict], window_minutes: int = 5) -> list[dict]:
    """Deduplicate repeated events per indicator/type in a sliding time window."""
    ordered = sorted(events, key=lambda x: str(x.get("timestamp", "")))
    buckets = defaultdict(list)
    for event in ordered:
        key = (str(event.get("indicator_value", "")).casefold(), str(event.get("alert_type", "IOC_MATCH")))
        buckets[key].append(event)
    output = []
    max_seconds = max(1, int(window_minutes)) * 60
    for (indicator, alert_type), grouped in buckets.items():
        windows = []
        for event in grouped:
            event_time = _parse_time(event.get("timestamp"))
            if event_time is None:
                windows.append([event])
                continue
            if not windows or _parse_time(windows[-1][-1].get("timestamp")) is None:
                windows.append([event])
                continue
            last_time = _parse_time(windows[-1][-1].get("timestamp"))
            if (event_time - last_time).total_seconds() <= max_seconds:
                windows[-1].append(event)
            else:
                windows.append([event])
        for window in windows:
            representative = dict(window[0])
            representative["indicator_value"] = indicator
            representative["alert_type"] = alert_type
            representative["observation_count"] = sum(int(x.get("observation_count", 1)) for x in window)
            representative["correlated_event_count"] = len(window)
            representative["correlation_note"] = "Repeated observations grouped to reduce alert fatigue; investigate the underlying evidence."
            output.append(representative)
    return output
