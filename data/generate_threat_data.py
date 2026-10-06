#!/usr/bin/env python3
"""Generate deterministic, safe, synthetic threat/vulnerability demo data.

All IOCs are reserved documentation/example values. The script performs no network I/O.
Run from the repository root: python data/generate_threat_data.py
"""
from __future__ import annotations
import csv
import hashlib
import ipaddress
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.services.attack_mapper import map_behavior_to_attack
from backend.services.risk_engine import calculate_threat_risk, classify_cvss, classify_risk

DATA = ROOT / "data"
REFERENCE = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
SEED = 20261006
RECORD_COUNT = 2000
SOURCES = [
    ("Internal SOC", "A"),
    ("Security Vendor", "B"),
    ("Public Threat Feed", "C"),
    ("Research Report", "B"),
    ("Community Submission", "D"),
    ("Unknown Source", "D"),
]
STATUSES = ["NEW", "UNDER_REVIEW", "MONITORING", "CLOSED", "FALSE_POSITIVE"]
CATEGORIES = [
    "PHISHING", "MALWARE", "RANSOMWARE", "CREDENTIAL THREATS", "WEB THREATS",
    "NETWORK THREATS", "VULNERABILITY EXPOSURE", "SOCIAL ENGINEERING",
    "DATA EXPOSURE", "ACCOUNT SECURITY",
]
CATEGORY_NAMES = {
    "PHISHING": "Synthetic credential phishing observation",
    "MALWARE": "Synthetic file reputation observation",
    "RANSOMWARE": "Synthetic ransomware-impact awareness signal",
    "CREDENTIAL THREATS": "Synthetic authentication-risk observation",
    "WEB THREATS": "Synthetic web reputation observation",
    "NETWORK THREATS": "Synthetic network indicator observation",
    "VULNERABILITY EXPOSURE": "Synthetic vulnerability awareness record",
    "SOCIAL ENGINEERING": "Synthetic impersonation-awareness signal",
    "DATA EXPOSURE": "Synthetic data-handling observation",
    "ACCOUNT SECURITY": "Synthetic account-protection observation",
}

FIELDNAMES = [
    "threat_id", "timestamp", "threat_name", "threat_category", "indicator_type",
    "indicator_value", "source_name", "source_reliability", "confidence_score", "severity",
    "risk_score", "status", "first_seen", "last_seen", "country_or_region_optional",
    "description", "mitre_tactic_optional", "mitre_technique_optional",
    "mitre_technique_id_optional", "cve_id_optional", "campaign_id", "observed_count",
    "synthetic_label",
]


def stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def demo_hash(number: int) -> str:
    return hashlib.sha256(f"SYNTHETIC-DEMO-ONLY:{number}:{SEED}".encode()).hexdigest()


def sample_indicator(rng: random.Random, kind: str, number: int) -> tuple[str, str]:
    if kind == "IP ADDRESS":
        network = rng.choice([ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"), ipaddress.ip_network("203.0.113.0/24")])
        return str(network.network_address + rng.randint(1, 254)), "IP ADDRESS"
    if kind in {"DOMAIN", "EMAIL/SENDER DOMAIN"}:
        prefix = rng.choice(["portal", "notice", "account", "updates", "security", "mail", "review", "verify", "service", "support"])
        host = f"{prefix}-{number:04d}." + rng.choice(["example.com", "example.org", "example.net", "invalid"])
        if kind == "EMAIL/SENDER DOMAIN":
            return f"notification-{number:04d}@{host}", "EMAIL/SENDER DOMAIN"
        return host, "DOMAIN"
    if kind == "URL":
        return f"https://example.net/demo/{number:04d}?ref=SIM-{number:04d}", "URL"
    if kind == "FILE HASH":
        return demo_hash(number), "FILE HASH"
    if kind == "CVE ID":
        return f"CVE-2099-{10000 + number}", "CVE ID"
    raise ValueError(f"Unsupported synthetic indicator type: {kind}")


def make_record(rng: random.Random, index: int) -> dict:
    category = rng.choice(CATEGORIES)
    source_name, reliability = rng.choice(SOURCES)
    indicator_kind = rng.choices(
        ["IP ADDRESS", "DOMAIN", "URL", "FILE HASH", "EMAIL/SENDER DOMAIN", "CVE ID"],
        weights=[22, 25, 14, 17, 12, 10], k=1,
    )[0]
    indicator_value, indicator_type = sample_indicator(rng, indicator_kind, index)
    age_days = rng.randint(0, 119)
    first = REFERENCE - timedelta(days=age_days, hours=rng.randint(0, 22), minutes=rng.randint(0, 59))
    last = first + timedelta(hours=rng.randint(0, min(72, max(1, age_days * 24 + 1))))
    if last > REFERENCE:
        last = REFERENCE
    timestamp = last
    count = rng.choices([1, 2, 3, 5, 8, 13, 21, 34], weights=[18, 16, 15, 15, 13, 10, 8, 5], k=1)[0]
    confidence = rng.randint(35, 98)
    intrinsic = rng.choice(["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"])
    recency = max(0, min(100, 100 - age_days))
    context = rng.randint(15, 90)
    risk = calculate_threat_risk(intrinsic, confidence, recency, count, reliability, rng.randint(0, 3), context)
    description = _description(category, indicator_type, count)
    mapping = map_behavior_to_attack(category, description)
    cve = indicator_value if indicator_type == "CVE ID" else ""
    return {
        "threat_id": f"THR-2026-{index:06d}",
        "timestamp": stamp(timestamp),
        "threat_name": CATEGORY_NAMES[category],
        "threat_category": category,
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "source_name": source_name,
        "source_reliability": reliability,
        "confidence_score": confidence,
        "severity": classify_risk(risk),
        "risk_score": risk,
        "status": rng.choice(STATUSES),
        "first_seen": stamp(first),
        "last_seen": stamp(last),
        "country_or_region_optional": rng.choice(["Demo / not geo-enriched", "Synthetic lab", "Not provided"]),
        "description": description,
        "mitre_tactic_optional": mapping["tactic"] if mapping else "",
        "mitre_technique_optional": mapping["technique"] if mapping else "",
        "mitre_technique_id_optional": mapping["technique_id"] if mapping else "",
        "cve_id_optional": cve,
        "campaign_id": "",
        "observed_count": count,
        "synthetic_label": "SYNTHETIC / DEMO ONLY",
    }


def _description(category: str, indicator_type: str, count: int) -> str:
    if category == "PHISHING":
        return "Synthetic credential-lure email observation in a classroom dataset; no message was sent and no link was visited."
    if category == "CREDENTIAL THREATS":
        return "Synthetic repeated authentication failures recorded in demo telemetry; no credentials or authentication service were contacted."
    if category == "RANSOMWARE":
        return "Synthetic ransomware impact simulation: simulated mass file-change indicators for awareness only; no executable or file was used."
    if category == "VULNERABILITY EXPOSURE":
        return "Synthetic CVE-format awareness record for prioritization practice; it is not a real vulnerability advisory."
    if category == "MALWARE":
        return "Synthetic file-hash-shaped value for offline reputation workflow practice; no file is present or executed."
    if category == "SOCIAL ENGINEERING":
        return "Synthetic impersonation-awareness observation used to teach independent verification through trusted channels."
    if category == "DATA EXPOSURE":
        return "Synthetic data-handling signal; contains no real personal or organizational data."
    if category == "ACCOUNT SECURITY":
        return "Synthetic account-security awareness observation; no account was accessed or tested."
    if category == "NETWORK THREATS":
        return f"Reserved documentation-range IP observation in synthetic telemetry ({count} demo observations); no packet was sent."
    if indicator_type == "URL":
        return "Fictional example URL string for parser testing only; the application never opens or requests it."
    return "Synthetic local-only indicator observation; reputation and attribution have not been established."


def demo_campaign_records() -> list[dict]:
    first = datetime(2026, 9, 18, 9, 0, tzinfo=timezone.utc)
    common = {
        "threat_name": "Synthetic Credential Phishing Campaign",
        "threat_category": "PHISHING",
        "source_name": "Internal SOC",
        "source_reliability": "A",
        "confidence_score": 85,
        "severity": "HIGH",
        "risk_score": 78,
        "status": "MONITORING",
        "first_seen": stamp(first),
        "last_seen": stamp(first + timedelta(days=2)),
        "country_or_region_optional": "Demo / not geo-enriched",
        "description": "Synthetic credential-lure email observations appear in multiple classroom-only records; this is a simulation, not a confirmed campaign or compromise.",
        "mitre_tactic_optional": "Initial Access",
        "mitre_technique_optional": "Phishing",
        "mitre_technique_id_optional": "T1566",
        "campaign_id": "DEMO-CAMP-001",
        "observed_count": 4,
        "synthetic_label": "SYNTHETIC / DEMO ONLY",
    }
    rows = []
    items = [
        ("THR-2026-001", "DOMAIN", "login-check.invalid", "CVE", ""),
        ("THR-2026-000002", "IP ADDRESS", "198.51.100.25", "2026-09-18T10:00:00Z", ""),
        ("THR-2026-000003", "FILE HASH", demo_hash(1), "2026-09-18T11:00:00Z", ""),
    ]
    for index, item in enumerate(items):
        threat_id, kind, value, time_override, unused = item
        row = dict(common)
        row.update({
            "threat_id": threat_id,
            "timestamp": stamp(first + timedelta(hours=index)),
            "indicator_type": kind,
            "indicator_value": value,
            "cve_id_optional": "",
        })
        if index == 0:
            row["timestamp"] = stamp(first)
            row["description"] = "Synthetic phishing credential-lure email observation. The demo domain is inert and must not be visited."
        rows.append(row)
    return rows


def generate_dataset(count: int = RECORD_COUNT, seed: int = SEED) -> list[dict]:
    if count < 3:
        raise ValueError("At least three records are required for the correlated demo scenario.")
    rng = random.Random(seed)
    records = demo_campaign_records()
    for index in range(4, count + 1):
        records.append(make_record(rng, index))
    return records


def write_threat_dataset(path: Path | None = None, count: int = RECORD_COUNT) -> Path:
    destination = path or DATA / "threat_intelligence_dataset.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = generate_dataset(count)
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)
    return destination


def write_vulnerabilities(path: Path | None = None) -> Path:
    destination = path or DATA / "vulnerabilities.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    headers = ["cve_id", "product_category", "severity", "cvss_score", "published_date", "patch_available", "exploitation_status_demo", "description", "asset_criticality", "exposure_score", "business_context"]
    examples = [
        ("Endpoint OS", 9.4, "YES", 82, 25, 88), ("Web Framework", 8.1, "NO", 95, 95, 92),
        ("Identity Service", 8.8, "YES", 98, 90, 96), ("Browser", 7.5, "YES", 70, 72, 75),
        ("Database", 9.1, "NO", 92, 35, 93), ("VPN Gateway", 8.6, "YES", 96, 100, 94),
        ("Mobile OS", 6.7, "YES", 65, 55, 68), ("Cloud Control Plane", 9.8, "NO", 100, 85, 100),
        ("Developer Tool", 7.2, "NO", 50, 30, 58), ("Email Platform", 8.0, "YES", 88, 80, 90),
        ("Container Runtime", 9.0, "NO", 90, 60, 88), ("Library", 5.9, "NO", 42, 25, 50),
        ("File Service", 8.3, "YES", 78, 68, 82), ("Network Appliance", 7.8, "NO", 88, 82, 86),
        ("Backup Platform", 9.2, "YES", 95, 30, 98), ("Student Portal", 6.4, "NO", 68, 75, 65),
        ("Monitoring Agent", 7.1, "NO", 54, 35, 61), ("Cloud Storage", 8.7, "YES", 90, 88, 94),
        ("Office Suite", 6.2, "NO", 60, 40, 63), ("Authentication Library", 9.3, "NO", 95, 70, 96),
        ("Test Environment", 9.6, "NO", 20, 5, 18), ("Legacy Server", 8.4, "YES", 45, 18, 72),
        ("API Gateway", 7.9, "NO", 92, 94, 86), ("Workstation Utility", 4.8, "YES", 35, 10, 38),
    ]
    with destination.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for idx, (product, cvss, exploited, criticality, exposure, business) in enumerate(examples, start=1):
            writer.writerow({
                "cve_id": f"CVE-2099-{10000 + idx}",
                "product_category": product,
                "severity": classify_cvss(cvss),
                "cvss_score": f"{cvss:.1f}",
                "published_date": (REFERENCE - timedelta(days=idx * 2)).date().isoformat(),
                "patch_available": "YES" if idx % 4 != 0 else "NO",
                "exploitation_status_demo": exploited,
                "description": f"Synthetic {product.lower()} vulnerability-awareness scenario {idx}; fictional, non-actionable classroom data.",
                "asset_criticality": criticality,
                "exposure_score": exposure,
                "business_context": business,
            })
    return destination


def main() -> None:
    threat_file = write_threat_dataset()
    vuln_file = write_vulnerabilities()
    print(f"Generated {RECORD_COUNT:,} synthetic records: {threat_file}")
    print(f"Generated 24 synthetic vulnerability scenarios: {vuln_file}")
    print("All indicators are reserved/example data. No network activity was performed.")


if __name__ == "__main__":
    main()
