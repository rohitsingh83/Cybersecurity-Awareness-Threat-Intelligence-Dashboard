"""SQLite storage, initialization, and deterministic demo seeding."""
from __future__ import annotations
import csv
import json
import sqlite3
from pathlib import Path
from typing import Any

from backend.services.alert_engine import generate_threat_alert
from backend.services.awareness_service import load_json
from backend.services.vulnerability_service import load_vulnerabilities

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS threats (
    threat_id TEXT PRIMARY KEY,
    threat_name TEXT NOT NULL,
    threat_category TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK(risk_score BETWEEN 0 AND 100),
    confidence_score INTEGER NOT NULL CHECK(confidence_score BETWEEN 0 AND 100),
    status TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    source_name TEXT NOT NULL,
    source_reliability TEXT NOT NULL,
    country_or_region_optional TEXT,
    mitre_tactic_optional TEXT,
    mitre_technique_optional TEXT,
    mitre_technique_id_optional TEXT,
    cve_id_optional TEXT,
    campaign_id TEXT,
    observed_count INTEGER NOT NULL DEFAULT 1,
    synthetic_label TEXT NOT NULL DEFAULT 'SYNTHETIC / DEMO ONLY'
);
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    indicator_type TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(threat_id, indicator_type, indicator_value)
);
CREATE TABLE IF NOT EXISTS sources (
    source_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL UNIQUE,
    reliability TEXT NOT NULL,
    reliability_label TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attack_mappings (
    mapping_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    tactic TEXT NOT NULL,
    technique TEXT,
    technique_id_optional TEXT,
    UNIQUE(threat_id, tactic, technique_id_optional)
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL UNIQUE,
    product_category TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL NOT NULL,
    published_date TEXT NOT NULL,
    patch_available INTEGER NOT NULL,
    exploitation_status_demo TEXT NOT NULL,
    description TEXT NOT NULL,
    asset_criticality INTEGER NOT NULL,
    exposure_score INTEGER NOT NULL,
    business_context INTEGER NOT NULL,
    priority_score INTEGER NOT NULL,
    synthetic_label TEXT NOT NULL DEFAULT 'SYNTHETIC / DEMO ONLY'
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    threat_id TEXT REFERENCES threats(threat_id) ON DELETE SET NULL,
    timestamp TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    confidence_score INTEGER NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    dedupe_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyst_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT NOT NULL REFERENCES threats(threat_id) ON DELETE CASCADE,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL,
    author_label TEXT NOT NULL DEFAULT 'LOCAL ANALYST'
);
CREATE TABLE IF NOT EXISTS awareness_modules (
    module_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    content_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quiz_results (
    result_id INTEGER PRIMARY KEY AUTOINCREMENT,
    anonymous_user_id_optional TEXT,
    overall_score INTEGER NOT NULL,
    category_scores_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_category ON threats(threat_category);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threat_indicator ON threats(indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_status ON threats(status);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alert_threat ON alerts(threat_id);
CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(indicator_value);
CREATE INDEX IF NOT EXISTS idx_notes_threat ON analyst_notes(threat_id);
CREATE INDEX IF NOT EXISTS idx_quiz_created ON quiz_results(created_at);
"""

RELIABILITY_LABELS = {
    "A": "Highly Reliable", "B": "Usually Reliable", "C": "Fairly Reliable", "D": "Reliability Unknown",
}


def _threat_dict(row: sqlite3.Row | dict) -> dict:
    return dict(row)


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    @staticmethod
    def _insert_threat(connection: sqlite3.Connection, row: dict) -> None:
        fields = [
            "threat_id", "threat_name", "threat_category", "description", "severity", "risk_score",
            "confidence_score", "status", "timestamp", "first_seen", "last_seen", "indicator_type",
            "indicator_value", "source_name", "source_reliability", "country_or_region_optional",
            "mitre_tactic_optional", "mitre_technique_optional", "mitre_technique_id_optional",
            "cve_id_optional", "campaign_id", "observed_count", "synthetic_label",
        ]
        values = [row.get(field, "") for field in fields]
        values[5] = int(values[5] or 0)
        values[6] = int(values[6] or 0)
        values[21] = int(values[21] or 1)
        placeholders = ",".join("?" for _ in fields)
        connection.execute(
            f"INSERT OR IGNORE INTO threats ({','.join(fields)}) VALUES ({placeholders})", values
        )
        connection.execute(
            "INSERT OR IGNORE INTO indicators(threat_id,indicator_type,indicator_value,first_seen,last_seen) VALUES(?,?,?,?,?)",
            (row.get("threat_id"), row.get("indicator_type", ""), row.get("indicator_value", ""), row.get("first_seen", ""), row.get("last_seen", "")),
        )
        level = str(row.get("source_reliability", "D")).upper()
        connection.execute(
            "INSERT OR IGNORE INTO sources(source_name,reliability,reliability_label) VALUES(?,?,?)",
            (row.get("source_name", "Unknown Source"), level, RELIABILITY_LABELS.get(level, "Reliability Unknown")),
        )
        if row.get("mitre_tactic_optional"):
            connection.execute(
                "INSERT OR IGNORE INTO attack_mappings(threat_id,tactic,technique,technique_id_optional) VALUES(?,?,?,?)",
                (row["threat_id"], row["mitre_tactic_optional"], row.get("mitre_technique_optional") or None, row.get("mitre_technique_id_optional") or None),
            )

    def seed(self, data_dir: str | Path, awareness_dir: str | Path) -> dict:
        """Seed a fresh local DB from bundled synthetic CSV/JSON files. Existing data is preserved."""
        data_dir, awareness_dir = Path(data_dir), Path(awareness_dir)
        with self.connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            if count:
                return {"seeded": False, "threats": count}
            threat_path = data_dir / "threat_intelligence_dataset.csv"
            with threat_path.open(newline="", encoding="utf-8") as handle:
                threat_rows = list(csv.DictReader(handle))
            for row in threat_rows:
                self._insert_threat(connection, row)

            vulnerabilities = load_vulnerabilities(data_dir / "vulnerabilities.csv")
            for item in vulnerabilities:
                connection.execute(
                    """INSERT OR IGNORE INTO vulnerabilities
                    (cve_id,product_category,severity,cvss_score,published_date,patch_available,
                    exploitation_status_demo,description,asset_criticality,exposure_score,business_context,priority_score)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (item["cve_id"], item["product_category"], item["severity"], item["cvss_score"], item["published_date"],
                     int(item["patch_available"]), item["exploitation_status_demo"], item["description"], int(item["asset_criticality"]),
                     int(item["exposure_score"]), int(item["business_context"]), int(item["priority_score"])),
                )
            modules = load_json(awareness_dir / "modules.json")
            for module in modules:
                connection.execute(
                    "INSERT OR IGNORE INTO awareness_modules(module_id,title,category,content_json) VALUES(?,?,?,?)",
                    (module["id"], module["title"], module["category"], json.dumps(module, ensure_ascii=False)),
                )

            # A small deterministic review queue demonstrates workflows without creating alert overload.
            eligible = sorted(
                (row for row in threat_rows if int(row["risk_score"]) >= 61 and int(row["confidence_score"]) >= 35),
                key=lambda row: (int(row["risk_score"]), int(row["confidence_score"])), reverse=True,
            )
            chosen = []
            demo = next((row for row in threat_rows if row["threat_id"] == "THR-2026-001"), None)
            if demo:
                chosen.append(demo)
            chosen.extend(row for row in eligible if row not in chosen)
            for row in chosen[:36]:
                alert = generate_threat_alert({**row, "related_indicator_count": 2 if row.get("campaign_id") else 0})
                if alert:
                    connection.execute(
                        """INSERT OR IGNORE INTO alerts(alert_id,threat_id,timestamp,alert_type,severity,risk_score,
                        confidence_score,description,status,indicator_value,observation_count,dedupe_key)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (alert["alert_id"], alert["threat_id"], row["timestamp"], alert["alert_type"], alert["severity"],
                         alert["risk_score"], alert["confidence_score"], alert["description"], "NEW", alert["indicator_value"],
                         alert["observation_count"], alert["dedupe_key"]),
                    )
            # High-priority fictional CVE scenarios also create review alerts; they are not live advisories.
            for item in vulnerabilities:
                alert = generate_threat_alert({
                    "cve_id": item["cve_id"], "is_vulnerability": True,
                    "priority_score": item["priority_score"], "risk_score": item["priority_score"],
                    "confidence_score": 70, "exploitation_status_demo": item["exploitation_status_demo"],
                    "indicator_type": "CVE ID", "indicator_value": item["cve_id"],
                    "threat_category": "VULNERABILITY EXPOSURE", "observed_count": 1,
                })
                if alert and alert["alert_type"] == "HIGH_PRIORITY_VULNERABILITY":
                    connection.execute(
                        """INSERT OR IGNORE INTO alerts(alert_id,threat_id,timestamp,alert_type,severity,risk_score,
                        confidence_score,description,status,indicator_value,observation_count,dedupe_key)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (alert["alert_id"], None, f"{item['published_date']}T00:00:00Z", alert["alert_type"], alert["severity"],
                         alert["risk_score"], alert["confidence_score"],
                         f"Fictional CVE scenario {item['cve_id']} reached the local priority threshold. No real advisory or exploitation is represented.",
                         "NEW", item["cve_id"], 1, f"vulnerability:{item['cve_id']}".casefold()),
                    )
            if demo:
                connection.execute(
                    "INSERT INTO analyst_notes(threat_id,note,created_at,author_label) VALUES(?,?,?,?)",
                    ("THR-2026-001", "Indicator appears in multiple synthetic phishing observations. Review authorized local telemetry; no external domain was visited.", demo["timestamp"], "DEMO ANALYST"),
                )
            return {"seeded": True, "threats": len(threat_rows), "vulnerabilities": len(vulnerabilities), "modules": len(modules)}

    def list_threats(self, filters: dict | None = None) -> dict:
        filters = filters or {}
        conditions, params = [], []
        exact_fields = {"severity": "severity", "category": "threat_category", "indicator_type": "indicator_type", "status": "status"}
        for key, column in exact_fields.items():
            value = filters.get(key)
            if value:
                conditions.append(f"{column} = ?")
                params.append(str(value).upper())
        for key, column, operator in [("min_risk", "risk_score", ">="), ("max_risk", "risk_score", "<="), ("min_confidence", "confidence_score", ">="), ("max_confidence", "confidence_score", "<=")]:
            value = filters.get(key)
            if value not in (None, ""):
                conditions.append(f"{column} {operator} ?")
                params.append(int(value))
        if filters.get("from_date"):
            conditions.append("substr(timestamp,1,10) >= ?")
            params.append(str(filters["from_date"]))
        if filters.get("to_date"):
            conditions.append("substr(timestamp,1,10) <= ?")
            params.append(str(filters["to_date"]))
        if filters.get("q"):
            value = f"%{filters['q'].strip()}%"
            conditions.append("(threat_id LIKE ? OR threat_name LIKE ? OR indicator_value LIKE ? OR description LIKE ? OR cve_id_optional LIKE ?)")
            params.extend([value] * 5)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        sort_columns = {"newest": "timestamp DESC", "oldest": "timestamp ASC", "risk": "risk_score DESC, timestamp DESC", "confidence": "confidence_score DESC, timestamp DESC", "observed": "observed_count DESC, timestamp DESC"}
        order = sort_columns.get(str(filters.get("sort", "newest")), sort_columns["newest"])
        page = max(1, int(filters.get("page", 1)))
        page_size = min(100, max(1, int(filters.get("page_size", 25))))
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM threats" + where, params).fetchone()[0]
            rows = connection.execute("SELECT * FROM threats" + where + f" ORDER BY {order} LIMIT ? OFFSET ?", [*params, page_size, (page - 1) * page_size]).fetchall()
        return {"items": [dict(row) for row in rows], "total": total, "page": page, "page_size": page_size, "pages": max(1, (total + page_size - 1) // page_size)}

    def get_threat(self, threat_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
            if not row:
                return None
            threat = dict(row)
            campaign = threat.get("campaign_id")
            threat["related_indicators"] = []
            if campaign:
                threat["related_indicators"] = [dict(item) for item in connection.execute(
                    "SELECT threat_id,indicator_type,indicator_value,threat_category,risk_score,status FROM threats WHERE campaign_id = ? AND threat_id != ? ORDER BY timestamp",
                    (campaign, threat_id),
                ).fetchall()]
            threat["related_alerts"] = [dict(item) for item in connection.execute("SELECT * FROM alerts WHERE threat_id = ? ORDER BY timestamp DESC", (threat_id,)).fetchall()]
            threat["analyst_notes"] = [dict(item) for item in connection.execute("SELECT * FROM analyst_notes WHERE threat_id = ? ORDER BY created_at DESC", (threat_id,)).fetchall()]
            threat["attack_mappings"] = [dict(item) for item in connection.execute("SELECT tactic,technique,technique_id_optional FROM attack_mappings WHERE threat_id = ?", (threat_id,)).fetchall()]
            threat["timeline"] = [
                {"time": threat["first_seen"], "label": "First observed", "detail": "Synthetic dataset timestamp."},
                {"time": threat["timestamp"], "label": "Latest observation", "detail": f"{threat['observed_count']} synthetic observation(s)."},
                {"time": threat["last_seen"], "label": "Last seen", "detail": f"Current state: {threat['status']} (not a confirmed incident)."},
            ]
            return threat

    def search_indicator(self, normalized_value: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM threats WHERE lower(indicator_value) = lower(?) OR lower(cve_id_optional) = lower(?) ORDER BY risk_score DESC, timestamp DESC LIMIT 100",
                (normalized_value, normalized_value),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_all_threats_for_value(self, value: str) -> list[dict]:
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM threats WHERE lower(indicator_value) = lower(?) OR lower(cve_id_optional) = lower(?)", (value, value)).fetchall()]

    def get_enrichment_context(self, value: str) -> list[dict]:
        """Return exact matches plus records sharing an explicit synthetic campaign ID."""
        with self.connect() as connection:
            rows = connection.execute(
                """SELECT * FROM threats WHERE lower(indicator_value) = lower(?) OR lower(cve_id_optional) = lower(?)
                OR campaign_id IN (SELECT campaign_id FROM threats WHERE (lower(indicator_value) = lower(?) OR lower(cve_id_optional) = lower(?)) AND campaign_id IS NOT NULL)""",
                (value, value, value, value),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_alerts(self, status: str | None = None, severity: str | None = None, limit: int = 100) -> list[dict]:
        conditions, params = [], []
        if status:
            conditions.append("status = ?")
            params.append(status.upper())
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM alerts" + where + " ORDER BY risk_score DESC, timestamp DESC LIMIT ?", [*params, min(500, max(1, int(limit)))]).fetchall()]

    def update_alert_status(self, alert_id: str, status: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            return cursor.rowcount > 0

    def update_threat_status(self, threat_id: str, status: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("UPDATE threats SET status = ? WHERE threat_id = ?", (status, threat_id))
            return cursor.rowcount > 0

    def add_note(self, threat_id: str, note: str, author: str = "LOCAL ANALYST") -> dict | None:
        with self.connect() as connection:
            exists = connection.execute("SELECT 1 FROM threats WHERE threat_id = ?", (threat_id,)).fetchone()
            if not exists:
                return None
            cursor = connection.execute(
                "INSERT INTO analyst_notes(threat_id,note,created_at,author_label) VALUES(?,?,datetime('now'),?)",
                (threat_id, note, author[:80]),
            )
            row = connection.execute("SELECT * FROM analyst_notes WHERE note_id = ?", (cursor.lastrowid,)).fetchone()
            return dict(row)

    def list_vulnerabilities(self, minimum_priority: int = 0, severity: str | None = None) -> list[dict]:
        conditions, params = ["priority_score >= ?"], [int(minimum_priority)]
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        with self.connect() as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM vulnerabilities WHERE " + " AND ".join(conditions) + " ORDER BY priority_score DESC, cvss_score DESC", params).fetchall()]

    def dashboard_stats(self) -> dict:
        with self.connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            critical = connection.execute("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'").fetchone()[0]
            high = connection.execute("SELECT COUNT(*) FROM threats WHERE severity='HIGH'").fetchone()[0]
            active = connection.execute("SELECT COUNT(DISTINCT indicator_value) FROM threats WHERE status NOT IN ('CLOSED','FALSE_POSITIVE')").fetchone()[0]
            open_investigations = connection.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW','INVESTIGATING')").fetchone()[0]
            avg_confidence = connection.execute("SELECT COALESCE(ROUND(AVG(confidence_score)),0) FROM threats").fetchone()[0]
            vuln_count = connection.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            severity = dict(connection.execute("SELECT severity,COUNT(*) FROM threats GROUP BY severity").fetchall())
            categories = dict(connection.execute("SELECT threat_category,COUNT(*) FROM threats GROUP BY threat_category ORDER BY COUNT(*) DESC").fetchall())
            indicator_types = dict(connection.execute("SELECT indicator_type,COUNT(*) FROM threats GROUP BY indicator_type").fetchall())
            statuses = dict(connection.execute("SELECT status,COUNT(*) FROM threats GROUP BY status").fetchall())
            vulnerability_severity = dict(connection.execute("SELECT severity,COUNT(*) FROM vulnerabilities GROUP BY severity").fetchall())
            risk_bins = {label: 0 for label in ["0–20", "21–40", "41–60", "61–80", "81–100"]}
            for row in connection.execute("SELECT risk_score FROM threats"):
                score = int(row[0])
                key = "0–20" if score <= 20 else "21–40" if score <= 40 else "41–60" if score <= 60 else "61–80" if score <= 80 else "81–100"
                risk_bins[key] += 1
            confidence_bins = {label: 0 for label in ["0–20", "21–40", "41–60", "61–80", "81–100"]}
            for row in connection.execute("SELECT confidence_score FROM threats"):
                score = int(row[0])
                key = "0–20" if score <= 20 else "21–40" if score <= 40 else "41–60" if score <= 60 else "61–80" if score <= 80 else "81–100"
                confidence_bins[key] += 1
            top_tactics = [dict(row) for row in connection.execute("SELECT tactic,label,COUNT(*) AS count FROM (SELECT tactic, tactic AS label FROM attack_mappings) GROUP BY tactic ORDER BY count DESC LIMIT 6").fetchall()]
            top_techniques = [dict(row) for row in connection.execute("SELECT technique,technique_id_optional AS technique_id,COUNT(*) AS count FROM attack_mappings WHERE technique IS NOT NULL GROUP BY technique,technique_id_optional ORDER BY count DESC LIMIT 8").fetchall()]
            avg_risk = connection.execute("SELECT COALESCE(ROUND(AVG(risk_score)),0) FROM threats").fetchone()[0]
        return {
            "total_threat_records": total, "critical_threats": critical, "high_threats": high,
            "active_indicators": active, "open_investigations": open_investigations,
            "average_confidence": avg_confidence, "vulnerabilities_tracked": vuln_count,
            "average_risk": avg_risk, "threats_by_severity": severity, "threats_by_category": categories,
            "indicator_type_distribution": indicator_types, "threat_status_distribution": statuses,
            "vulnerabilities_by_severity": vulnerability_severity,
            "risk_distribution": risk_bins, "confidence_distribution": confidence_bins,
            "top_attack_tactics": top_tactics, "top_attack_techniques": top_techniques,
        }

    def dashboard_trends(self, days: int = 30) -> list[dict]:
        days = max(1, min(365, int(days)))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT substr(timestamp,1,10) AS day, COUNT(*) AS observations, ROUND(AVG(risk_score)) AS average_risk FROM threats GROUP BY day ORDER BY day DESC LIMIT ?",
                (days,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]

    def attack_records(self, technique_id: str | None = None, tactic: str | None = None) -> list[dict]:
        sql = "SELECT t.* FROM threats t JOIN attack_mappings a ON a.threat_id=t.threat_id WHERE 1=1"
        params = []
        if technique_id:
            sql += " AND a.technique_id_optional = ?"
            params.append(technique_id)
        if tactic:
            sql += " AND a.tactic = ?"
            params.append(tactic)
        sql += " ORDER BY t.risk_score DESC LIMIT 200"
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, params).fetchall()]

    def list_modules(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT content_json FROM awareness_modules ORDER BY title").fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_quiz_result(self, result: dict, anonymous_user_id: str | None = None) -> dict:
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO quiz_results(anonymous_user_id_optional,overall_score,category_scores_json,created_at,result_json) VALUES(?,?,?,?,?)",
                (anonymous_user_id, result["overall_score"], json.dumps(result["category_scores"]), now, json.dumps(result)),
            )
            return {"result_id": cursor.lastrowid, "created_at": now}

    def quiz_history(self, limit: int = 12) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT overall_score,category_scores_json,created_at FROM quiz_results ORDER BY result_id DESC LIMIT ?", (limit,)).fetchall()
        return [{"overall_score": row[0], "category_scores": json.loads(row[1]), "created_at": row[2]} for row in rows]

    def source_summary(self) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT s.source_name,s.reliability,s.reliability_label,COUNT(t.threat_id) AS record_count FROM sources s LEFT JOIN threats t ON t.source_name=s.source_name GROUP BY s.source_id ORDER BY record_count DESC").fetchall()
        return [dict(row) for row in rows]
