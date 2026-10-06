from __future__ import annotations
import csv
import json
from pathlib import Path

import pytest

from backend.db import Database
from backend.services.alert_engine import generate_threat_alert, validate_alert_status
from backend.services.attack_mapper import map_behavior_to_attack
from backend.services.awareness_service import generate_learning_recommendations, load_json, score_quiz
from backend.services.correlation_engine import correlate_alerts, correlate_threats
from backend.services.enrichment_engine import enrich_indicator
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_confidence_score, calculate_organizational_risk, calculate_threat_risk, calculate_vulnerability_priority, classify_cvss, classify_risk, source_reliability_score
from backend.services.threat_service import normalize_threat
from backend.services.vulnerability_service import load_vulnerabilities

ROOT = Path(__file__).resolve().parents[1]


def test_01_valid_ipv4():
    result = validate_indicator("198.51.100.25")
    assert result["valid"] and result["indicator_type"] == "IP ADDRESS"


def test_02_invalid_ipv4():
    assert not validate_indicator("999.1.1.1")["valid"]


def test_03_valid_ipv6():
    result = validate_indicator("2001:db8::25")
    assert result["valid"] and ":" in result["normalized_value"]


def test_04_valid_domain():
    assert validate_indicator("Login-Check.INVALID")["normalized_value"] == "login-check.invalid"


def test_05_invalid_domain():
    assert not validate_indicator("bad..example.com")["valid"]


def test_06_valid_url():
    result = validate_indicator("https://example.net/demo/hello")
    assert result["valid"] and result["indicator_type"] == "URL"
    assert "not opened" in result["validation_notes"] and "contacted" in result["validation_notes"]


def test_07_valid_md5_format():
    assert validate_indicator("a" * 32)["valid"]


def test_08_valid_sha1_format():
    assert validate_indicator("b" * 40)["valid"]


def test_09_valid_sha256_format():
    assert validate_indicator("c" * 64)["valid"]


def test_10_valid_cve_format():
    assert validate_indicator("CVE-2099-10001")["valid"]


def test_11_invalid_cve_format():
    assert not validate_indicator("CVE-26-123")["valid"]


def test_12_threat_creation_normalization():
    result = normalize_threat({"threat_name":"Training observation", "threat_category":"NETWORK THREATS", "indicator_type":"IP ADDRESS", "indicator_value":"203.0.113.9"})
    assert result["indicator_value"] == "203.0.113.9" and result["synthetic_label"] == "SYNTHETIC / DEMO ONLY"


def test_13_risk_calculation_and_classification():
    score = calculate_threat_risk("HIGH", 85, 90, 8, "A", 2, 80)
    assert 0 <= score <= 100 and classify_risk(score) in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert classify_risk(20) == "INFORMATIONAL" and classify_risk(81) == "CRITICAL"


def test_14_confidence_calculation():
    assert calculate_confidence_score("A", 100, 100, 100) == 100
    assert calculate_confidence_score("D", 0, 0, 0) == 14


def test_15_source_reliability():
    assert source_reliability_score("A") > source_reliability_score("C") > source_reliability_score("D")


def test_16_ioc_enrichment_known_demo(client):
    result = client.get("/api/indicators/search", params={"q":"login-check.invalid"}).json()
    assert result["known_in_demo_dataset"] is True
    assert result["risk_score"] == 78 and result["confidence_score"] == 85


def test_17_indicator_search_unknown_is_local_only(client):
    result = client.get("/api/indicators/search", params={"q":"unknown-demo.invalid"}).json()
    assert result["valid"] and result["known_in_demo_dataset"] is False
    assert "external reputation lookup" in result["interpretation"]


def test_18_campaign_correlation():
    records = [
        {"threat_id":"A","indicator_value":"alpha.invalid","campaign_id":"C1","threat_category":"PHISHING"},
        {"threat_id":"B","indicator_value":"198.51.100.2","campaign_id":"C1","threat_category":"PHISHING"},
    ]
    clusters = correlate_threats(records)
    assert len(clusters) == 1 and clusters[0]["attribution"] == "NOT ESTABLISHED"


def test_19_duplicate_observation_correlation():
    events = [
        {"indicator_value":"198.51.100.9","alert_type":"IOC_MATCH","timestamp":"2026-10-01T10:00:00Z","observation_count":1},
        {"indicator_value":"198.51.100.9","alert_type":"IOC_MATCH","timestamp":"2026-10-01T10:04:00Z","observation_count":1},
    ]
    grouped = correlate_alerts(events, window_minutes=5)
    assert len(grouped) == 1 and grouped[0]["observation_count"] == 2


def test_20_alert_generation_on_threshold():
    alert = generate_threat_alert({"threat_id":"T1","risk_score":78,"confidence_score":85,"observed_count":4,"indicator_type":"DOMAIN","indicator_value":"login-check.invalid"})
    assert alert and alert["status"] == "NEW" and "not a confirmed incident" in alert["description"]


def test_21_no_alert_for_low_evidence_record():
    assert generate_threat_alert({"risk_score":20,"confidence_score":10,"observed_count":1,"related_indicator_count":0}) is None


def test_22_alert_status_validation():
    assert validate_alert_status("resolved") == "RESOLVED"
    with pytest.raises(ValueError): validate_alert_status("EXECUTE")


def test_23_attack_mapping_phishing_behavior():
    mapping = map_behavior_to_attack("PHISHING", "Synthetic phishing credential-lure email observation")
    assert mapping and mapping["technique_id"] == "T1566" and mapping["tactic"] == "Initial Access"


def test_24_no_attack_mapping_from_ioc_alone():
    assert map_behavior_to_attack("NETWORK THREATS", "Reserved IP address seen") is None


def test_25_vulnerability_context_priority():
    isolated = calculate_vulnerability_priority(9.6, 20, 5, False, 18)
    exposed = calculate_vulnerability_priority(8.4, 95, 100, True, 95)
    assert exposed > isolated


def test_26_vulnerability_dataset_loads_as_synthetic():
    rows = load_vulnerabilities(ROOT / "data" / "vulnerabilities.csv")
    assert len(rows) == 24 and all(row["is_synthetic"] for row in rows)


def test_27_dashboard_statistics_count_seeded_rows(client):
    stats = client.get("/api/dashboard/stats").json()
    assert stats["total_threat_records"] == 2000 and stats["vulnerabilities_tracked"] == 24


def test_28_severity_filter(client):
    result = client.get("/api/threats", params={"severity":"HIGH","page_size":10}).json()
    assert result["items"] and all(row["severity"] == "HIGH" for row in result["items"])


def test_29_category_filter(client):
    result = client.get("/api/threats", params={"category":"PHISHING","page_size":10}).json()
    assert result["items"] and all(row["threat_category"] == "PHISHING" for row in result["items"])


def test_30_threat_sorting_highest_risk(client):
    result = client.get("/api/threats", params={"sort":"risk","page_size":10}).json()["items"]
    assert result[0]["risk_score"] >= result[-1]["risk_score"]


def test_31_awareness_module_retrieval(client):
    modules = client.get("/api/awareness/modules").json()["items"]
    assert len(modules) == 15 and all(module.get("safe_practices") for module in modules)


def test_32_quiz_scoring_all_correct():
    questions = load_json(ROOT / "awareness" / "quiz_questions.json")
    answers = {q["id"]:q["correct_index"] for q in questions}
    result = score_quiz(questions, answers)
    assert result["overall_score"] == 100 and result["label"] == "Strong Awareness"


def test_33_learning_recommendation_for_weak_area():
    recommendations = generate_learning_recommendations({"PHISHING":40,"PASSWORDS":90})
    phishing = next(item for item in recommendations if item["category"] == "PHISHING")
    assert phishing["priority"] == "FOCUS AREA" and phishing["module_id"] == "phishing-awareness"


def test_34_empty_dataset_enrichment():
    result = enrich_indicator("198.51.100.200", [], [], [])
    assert result["valid"] and not result["known_in_demo_dataset"] and result["threat_count"] == 0


def test_35_database_persistence(tmp_path):
    db = Database(tmp_path / "persist.sqlite3")
    db.initialize()
    record = normalize_threat({"threat_id":"PERSIST-1","threat_name":"Persistence test","threat_category":"NETWORK THREATS","indicator_type":"IP ADDRESS","indicator_value":"203.0.113.8"})
    with db.connect() as connection:
        db._insert_threat(connection, record)
    assert db.get_threat("PERSIST-1")["indicator_value"] == "203.0.113.8"


def test_36_api_health_and_offline_safety(client):
    payload = client.get("/api/health").json()
    assert payload["status"] == "ok" and payload["indicator_network_lookups"] is False


def test_37_api_rejects_invalid_indicator_without_lookup(client):
    payload = client.get("/api/indicators/search", params={"q":"not a domain"}).json()
    assert not payload["valid"] and not payload["known_in_demo_dataset"]


def test_38_api_demo_ip_lookup_includes_related_context(client):
    payload = client.get("/api/indicators/search", params={"q":"198.51.100.25"}).json()
    assert payload["known_in_demo_dataset"] and "login-check.invalid" in payload["related_indicators"]
    assert payload["internal_sightings"]


def test_39_api_risk_filter_validation(client):
    response = client.get("/api/threats", params={"min_risk":90,"max_risk":10})
    assert response.status_code == 422


def test_40_api_note_creation(client):
    response = client.post("/api/threats/THR-2026-001/notes", json={"note":"Reviewed synthetic evidence in the local demo."})
    assert response.status_code == 201 and response.json()["threat_id"] == "THR-2026-001"


def test_41_api_alert_status_update(client):
    items = client.get("/api/alerts", params={"limit":1}).json()["items"]
    assert items
    alert_id = items[0]["alert_id"]
    response = client.put(f"/api/alerts/{alert_id}/status", json={"status":"INVESTIGATING"})
    assert response.status_code == 200 and response.json()["status"] == "INVESTIGATING"
    client.put(f"/api/alerts/{alert_id}/status", json={"status":"NEW"})


def test_42_api_quiz_hides_answers_until_submit(client):
    payload = client.get("/api/quiz").json()
    assert payload["total"] == 30 and "correct_index" not in payload["questions"][0]


def test_43_api_quiz_submission_persists_score(client):
    questions = client.get("/api/quiz").json()["questions"]
    response = client.post("/api/quiz/submit", json={"answers":{q["id"]:0 for q in questions}})
    assert response.status_code == 200 and 0 <= response.json()["overall_score"] <= 100
    assert client.get("/api/awareness/score").json()["latest"] is not None


def test_44_api_vulnerability_rows_are_synthetic(client):
    payload = client.get("/api/vulnerabilities").json()
    assert payload["total"] == 24 and payload["items"][0]["is_synthetic"] is True


def test_45_api_attack_technique_records(client):
    payload = client.get("/api/attack/techniques/T1566/threats").json()
    assert payload["total"] >= 1 and payload["attribution"] == "NOT ESTABLISHED"


def test_46_api_threat_create_validates_and_persists(client):
    payload = {"threat_id":"API-DEMO-01","threat_name":"API-created demo record","threat_category":"NETWORK THREATS","indicator_type":"IP ADDRESS","indicator_value":"203.0.113.77","confidence_score":60,"risk_score":42,"description":"Synthetic API validation test; no packets were sent."}
    response = client.post("/api/threats", json=payload)
    assert response.status_code == 201 and response.json()["threat_id"] == "API-DEMO-01"


def test_47_api_threat_create_rejects_invalid_indicator(client):
    payload = {"threat_name":"Invalid input test","threat_category":"NETWORK THREATS","indicator_type":"IP ADDRESS","indicator_value":"999.999.999.999"}
    response = client.post("/api/threats", json=payload)
    assert response.status_code == 422


def test_48_duplicate_campaign_id_without_distinct_ioc_does_not_cluster():
    records = [{"threat_id":"A","indicator_value":"same.invalid","campaign_id":"C"},{"threat_id":"B","indicator_value":"same.invalid","campaign_id":"C"}]
    assert correlate_threats(records) == []


def test_49_organizational_risk_weighting_uses_completion_gap():
    result = calculate_organizational_risk(2, 1, 80)
    assert result["score"] == 24
    assert result["awareness_completion_gap_20_percent"] == 20
    assert calculate_organizational_risk(0, 0, 100)["score"] == 0


def test_50_high_priority_vulnerability_alert():
    alert = generate_threat_alert({"cve_id":"CVE-2099-10001","is_vulnerability":True,"priority_score":88,"confidence_score":40,"exploitation_status_demo":"YES"})
    assert alert and alert["alert_type"] == "HIGH_PRIORITY_VULNERABILITY"


def test_51_api_date_filter(client):
    response = client.get("/api/threats", params={"from_date":"2026-09-18","to_date":"2026-09-18","page_size":20})
    assert response.status_code == 200
    assert response.json()["items"] and all(row["timestamp"].startswith("2026-09-18") for row in response.json()["items"])
    assert client.get("/api/threats", params={"from_date":"2026-10-01","to_date":"2026-09-01"}).status_code == 422


def test_52_seed_creates_high_priority_vulnerability_alerts(tmp_path):
    db = Database(tmp_path / "seed-alert-test.sqlite3")
    db.initialize()
    result = db.seed(ROOT / "data", ROOT / "awareness")
    alerts = db.list_alerts(limit=500)
    assert result["seeded"] and any(item["alert_type"] == "HIGH_PRIORITY_VULNERABILITY" for item in alerts)


def test_53_cvss_severity_bands():
    assert classify_cvss(8.1) == "HIGH"
    assert classify_cvss(9.4) == "CRITICAL"
    assert classify_cvss(5.9) == "MEDIUM"


def test_54_ipv6_url_is_normalized_with_brackets():
    result = validate_indicator("https://[2001:db8::1]/demo")
    assert result["valid"] and result["normalized_value"] == "https://[2001:db8::1]/demo"
