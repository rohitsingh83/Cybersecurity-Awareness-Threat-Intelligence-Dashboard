"""FastAPI app for an offline-first, defensive cybersecurity learning dashboard.

All indicator lookups are local SQLite searches. This application never resolves,
visits, probes, or contacts indicator values or external threat-feed services.
"""
from __future__ import annotations
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import date as Date
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.db import Database
from backend.models.schemas import NoteCreate, QuizSubmission, StatusUpdate, ThreatCreate
from backend.utils.local_data import read_assets, read_awareness_metrics, read_internal_signals
from backend.services.alert_engine import ALERT_STATUSES, validate_alert_status
from backend.services.attack_mapper import map_behavior_to_attack
from backend.services.awareness_service import generate_learning_recommendations, load_json, score_quiz
from backend.services.enrichment_engine import enrich_indicator
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_organizational_risk
from backend.services.threat_service import STATUSES as THREAT_STATUSES, normalize_threat
from backend.services.vulnerability_service import vulnerability_explanation

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
AWARENESS_DIR = PROJECT_ROOT / "awareness"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
QUIZ_PATH = AWARENESS_DIR / "quiz_questions.json"


def _safe_api_key(x_api_key: str | None = Header(default=None)):
    """Protect analyst write endpoints when TI_API_KEY is configured.

    With no key configured, writes are intentionally enabled only for a local demo.
    """
    expected = os.getenv("TI_API_KEY", "").strip()
    if expected and not secrets.compare_digest(expected, x_api_key or ""):
        raise HTTPException(status_code=401, detail="A valid X-API-Key is required for analyst write actions.")
    return True


def create_app(
    db_path: str | Path | None = None,
    data_dir: str | Path | None = None,
    awareness_dir: str | Path | None = None,
    seed: bool = True,
) -> FastAPI:
    data_dir = Path(data_dir or DATA_DIR)
    awareness_dir = Path(awareness_dir or AWARENESS_DIR)
    configured_db = db_path or os.getenv("TI_DB_PATH") or (data_dir / "threat_dashboard.db")
    db_path = Path(configured_db)
    if not db_path.is_absolute():
        db_path = PROJECT_ROOT / db_path
    database = Database(db_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        database.initialize()
        if seed:
            database.seed(data_dir, awareness_dir)
        app.state.database = database
        yield

    app = FastAPI(
        title="Cybersecurity Awareness & Threat Intelligence Dashboard",
        description="Offline-first defensive CTI, IOC review, vulnerability awareness, and security learning. Indicator values are never contacted.",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )
    app.state.database = database
    # Same-origin static UI is the default. CORS is deliberately not opened to arbitrary sites.
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost", "http://127.0.0.1"], allow_credentials=False, allow_methods=["GET", "POST", "PUT"], allow_headers=["Content-Type", "X-API-Key"])

    max_per_minute = max(30, int(os.getenv("TI_RATE_LIMIT_PER_MINUTE", "300")))
    request_buckets: dict[str, deque] = defaultdict(deque)
    limiter_lock = threading.Lock()

    @app.middleware("http")
    async def simple_rate_limit(request, call_next):
        if request.url.path.startswith("/api/"):
            client = request.client.host if request.client else "local"
            now = time.monotonic()
            with limiter_lock:
                bucket = request_buckets[client]
                while bucket and bucket[0] <= now - 60:
                    bucket.popleft()
                if len(bucket) >= max_per_minute:
                    return JSONResponse(status_code=429, content={"detail": "Local demo rate limit reached. Retry shortly."})
                bucket.append(now)
        return await call_next(request)

    def get_db() -> Database:
        return database

    @app.get("/api/health", tags=["system"])
    def health(db: Database = Depends(get_db)):
        return {"status": "ok", "mode": "offline-first synthetic demo", "indicator_network_lookups": False, "database": str(db.path.name)}

    @app.get("/api/threats", tags=["threats"])
    def list_threats(
        severity: Optional[str] = None,
        category: Optional[str] = None,
        indicator_type: Optional[str] = None,
        status: Optional[str] = None,
        min_risk: int = Query(default=0, ge=0, le=100),
        max_risk: int = Query(default=100, ge=0, le=100),
        min_confidence: int = Query(default=0, ge=0, le=100),
        max_confidence: int = Query(default=100, ge=0, le=100),
        q: Optional[str] = Query(default=None, max_length=200),
        from_date: Optional[str] = Query(default=None, max_length=10),
        to_date: Optional[str] = Query(default=None, max_length=10),
        sort: str = Query(default="newest", pattern="^(newest|oldest|risk|confidence|observed)$"),
        page: int = Query(default=1, ge=1),
        page_size: int = Query(default=25, ge=1, le=100),
        db: Database = Depends(get_db),
    ):
        if min_risk > max_risk or min_confidence > max_confidence:
            raise HTTPException(status_code=422, detail="Minimum filter values cannot exceed maximum values.")
        try:
            parsed_from = Date.fromisoformat(from_date) if from_date else None
            parsed_to = Date.fromisoformat(to_date) if to_date else None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Dates must use YYYY-MM-DD format.") from exc
        if parsed_from and parsed_to and parsed_from > parsed_to:
            raise HTTPException(status_code=422, detail="from_date must not be later than to_date.")
        return db.list_threats({
            "severity": severity, "category": category, "indicator_type": indicator_type,
            "status": status, "min_risk": min_risk, "max_risk": max_risk,
            "min_confidence": min_confidence, "max_confidence": max_confidence,
            "from_date": from_date, "to_date": to_date,
            "q": q, "sort": sort, "page": page, "page_size": page_size,
        })

    @app.get("/api/threats/{threat_id}", tags=["threats"])
    def threat_detail(threat_id: str, db: Database = Depends(get_db)):
        result = db.get_threat(threat_id)
        if not result:
            raise HTTPException(status_code=404, detail="Threat record not found in the local demo database.")
        return result

    @app.post("/api/threats", status_code=201, tags=["threats"], dependencies=[Depends(_safe_api_key)])
    def create_threat(payload: ThreatCreate, db: Database = Depends(get_db)):
        raw = payload.model_dump(exclude_none=True)
        try:
            normalized = normalize_threat(raw)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        mapping = map_behavior_to_attack(normalized["threat_category"], normalized["description"])
        if mapping:
            normalized["mitre_tactic_optional"] = mapping["tactic"]
            normalized["mitre_technique_optional"] = mapping["technique"]
            normalized["mitre_technique_id_optional"] = mapping["technique_id"]
        try:
            with db.connect() as connection:
                existing = connection.execute("SELECT 1 FROM threats WHERE threat_id = ?", (normalized["threat_id"],)).fetchone()
                if existing:
                    raise HTTPException(status_code=409, detail="Threat ID already exists.")
                db._insert_threat(connection, normalized)
            return db.get_threat(normalized["threat_id"])
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Could not save threat: {exc}") from exc

    @app.put("/api/threats/{threat_id}", tags=["threats"], dependencies=[Depends(_safe_api_key)])
    def update_threat(threat_id: str, payload: StatusUpdate, db: Database = Depends(get_db)):
        status = payload.status.strip().upper()
        if status not in THREAT_STATUSES:
            raise HTTPException(status_code=422, detail=f"Status must be one of: {', '.join(sorted(THREAT_STATUSES))}")
        if not db.update_threat_status(threat_id, status):
            raise HTTPException(status_code=404, detail="Threat record not found.")
        return db.get_threat(threat_id)

    @app.get("/api/indicators/search", tags=["indicators"])
    def indicator_search(q: str = Query(min_length=1, max_length=2048), db: Database = Depends(get_db)):
        validation = validate_indicator(q)
        if not validation["valid"]:
            return {**validation, "known_in_demo_dataset": False, "threat_count": 0, "matches": [], "interpretation": validation["validation_notes"]}
        normalized = validation["normalized_value"]
        threats = db.get_all_threats_for_value(normalized)
        context_records = db.get_enrichment_context(normalized)
        all_alerts = db.list_alerts(limit=500)
        notes = []
        for threat in threats:
            detail = db.get_threat(threat["threat_id"])
            if detail:
                notes.extend(detail.get("analyst_notes", []))
        enriched = enrich_indicator(
            normalized, context_records, all_alerts, notes,
            internal_signals=read_internal_signals(data_dir), indicator_type=validation["indicator_type"],
        )
        enriched["matches"] = [{
            "threat_id": t["threat_id"], "threat_name": t["threat_name"],
            "category": t["threat_category"], "severity": t["severity"],
            "risk_score": t["risk_score"], "confidence_score": t["confidence_score"],
            "status": t["status"], "first_seen": t["first_seen"], "last_seen": t["last_seen"],
        } for t in threats]
        return enriched

    @app.get("/api/dashboard/stats", tags=["dashboard"])
    def dashboard_stats(db: Database = Depends(get_db)):
        return db.dashboard_stats()

    @app.get("/api/dashboard/trends", tags=["dashboard"])
    def dashboard_trends(days: int = Query(default=30, ge=1, le=365), db: Database = Depends(get_db)):
        return {"days": days, "items": db.dashboard_trends(days)}

    @app.get("/api/alerts", tags=["alerts"])
    def alerts(status: Optional[str] = None, severity: Optional[str] = None, limit: int = Query(default=100, ge=1, le=500), db: Database = Depends(get_db)):
        if status and status.upper() not in ALERT_STATUSES:
            raise HTTPException(status_code=422, detail="Unsupported alert status.")
        return {"items": db.list_alerts(status, severity, limit), "total_returned": len(db.list_alerts(status, severity, limit))}

    @app.put("/api/alerts/{alert_id}/status", tags=["alerts"], dependencies=[Depends(_safe_api_key)])
    def update_alert(alert_id: str, payload: StatusUpdate, db: Database = Depends(get_db)):
        try:
            status = validate_alert_status(payload.status)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not db.update_alert_status(alert_id, status):
            raise HTTPException(status_code=404, detail="Alert not found.")
        rows = [row for row in db.list_alerts(limit=500) if row["alert_id"] == alert_id]
        return rows[0] if rows else {"alert_id": alert_id, "status": status}

    @app.post("/api/threats/{threat_id}/notes", status_code=201, tags=["investigation"], dependencies=[Depends(_safe_api_key)])
    def add_note(threat_id: str, payload: NoteCreate, db: Database = Depends(get_db)):
        text = payload.note.strip()
        if len(text) < 3:
            raise HTTPException(status_code=422, detail="Note must contain at least three non-space characters.")
        note = db.add_note(threat_id, text, payload.author_label.strip() or "LOCAL ANALYST")
        if note is None:
            raise HTTPException(status_code=404, detail="Threat record not found.")
        return note

    @app.get("/api/vulnerabilities", tags=["vulnerabilities"])
    def vulnerabilities(min_priority: int = Query(default=0, ge=0, le=100), severity: Optional[str] = None, db: Database = Depends(get_db)):
        items = db.list_vulnerabilities(min_priority, severity)
        for item in items:
            item["patch_available"] = bool(item["patch_available"])
            item["is_synthetic"] = True
            item["priority_explanation"] = vulnerability_explanation(item)
        return {"items": items, "total": len(items), "synthetic_notice": "All vulnerability rows are fictional classroom scenarios; no real CVE advisory is represented."}

    @app.get("/api/awareness/modules", tags=["awareness"])
    def awareness_modules(db: Database = Depends(get_db)):
        return {"items": db.list_modules(), "total": len(db.list_modules())}

    @app.get("/api/awareness/modules/{module_id}", tags=["awareness"])
    def awareness_module_detail(module_id: str, db: Database = Depends(get_db)):
        item = next((module for module in db.list_modules() if module["id"] == module_id), None)
        if not item:
            raise HTTPException(status_code=404, detail="Awareness module not found.")
        return item

    @app.get("/api/quiz", tags=["awareness"])
    def get_quiz():
        questions = load_json(QUIZ_PATH)
        # Keep answer keys server-side until the learner submits.
        return {"total": len(questions), "questions": [{key: q[key] for key in ("id", "category", "module_id", "question", "options")} for q in questions]}

    @app.post("/api/quiz/submit", tags=["awareness"])
    def submit_quiz(payload: QuizSubmission, db: Database = Depends(get_db)):
        questions = load_json(QUIZ_PATH)
        allowed = {str(q["id"]): len(q["options"]) for q in questions}
        if any(key not in allowed or not 0 <= int(value) < allowed[key] for key, value in payload.answers.items()):
            raise HTTPException(status_code=422, detail="Answer set contains an unknown question or invalid option index.")
        result = score_quiz(questions, payload.answers)
        stored = db.save_quiz_result(result, payload.anonymous_user_id)
        return {**result, **stored}

    @app.get("/api/awareness/score", tags=["awareness"])
    def awareness_score(db: Database = Depends(get_db)):
        history = db.quiz_history()
        return {"latest": history[0] if history else None, "history": history, "notice": "Awareness scores are educational self-reflection, not employee competency judgments."}

    @app.get("/api/attack/tactics", tags=["attack"])
    def attack_tactics(db: Database = Depends(get_db)):
        stats = db.dashboard_stats()
        return {"tactics": stats["top_attack_tactics"], "techniques": stats["top_attack_techniques"], "mapping_notice": "Mappings are included only where synthetic behavior context supports them; an IOC alone is not a technique."}

    @app.get("/api/attack/techniques/{technique_id}/threats", tags=["attack"])
    def attack_technique_records(technique_id: str, db: Database = Depends(get_db)):
        records = db.attack_records(technique_id=technique_id)
        return {"technique_id": technique_id, "items": records, "total": len(records), "attribution": "NOT ESTABLISHED"}

    @app.get("/api/executive/summary", tags=["executive"])
    def executive_summary(db: Database = Depends(get_db)):
        stats = db.dashboard_stats()
        alerts = db.list_alerts(limit=500)
        vulnerabilities = db.list_vulnerabilities()
        history = db.quiz_history()
        high_critical = stats["critical_threats"] + stats["high_threats"]
        high_critical_alerts = sum(1 for item in alerts if item["severity"] in {"HIGH", "CRITICAL"} and item["status"] in {"NEW", "INVESTIGATING", "MONITORING"})
        assets = read_assets(data_dir)
        installed_products = {str(software.get("name", "")).casefold() for asset in assets for software in asset.get("software_list", [])}
        exploited_affected = [item for item in vulnerabilities if item["exploitation_status_demo"] == "YES" and item["product_category"].casefold() in installed_products]
        awareness_metrics = read_awareness_metrics(data_dir)
        latest_score = history[0]["overall_score"] if history else None
        org_components = calculate_organizational_risk(
            high_critical_alerts,
            len(exploited_affected),
            awareness_metrics.get("completion_rate", 0),
        )
        org_risk = org_components["score"]
        top_categories = list(stats["threats_by_category"].items())[:3]
        top_vulnerability_categories = list(dict.fromkeys(item["product_category"] for item in vulnerabilities[:4]))
        focus = []
        if high_critical:
            focus.append("Review high/critical synthetic alerts with an analyst before taking action.")
        if exploited_affected:
            focus.append("Validate synthetic asset inventory matches and patch plans for scenarios marked with demo exploitation evidence.")
        if not history:
            focus.append("Invite learners to complete the self-guided quiz; no awareness result is recorded yet.")
        if not focus:
            focus.append("Maintain routine monitoring, patch review, and short awareness refreshers.")
        return {
            "label": "ILLUSTRATIVE SYNTHETIC DEMO SUMMARY",
            "plain_language_summary": f"The local dataset contains {stats['total_threat_records']:,} fictional observations. {high_critical:,} are currently scored high or critical for review; none is a confirmed incident by score alone.",
            "illustrative_organizational_risk_score": org_risk,
            "score_components": {key: value for key, value in org_components.items() if key != "score"},
            "high_critical_threat_count": high_critical,
            "high_critical_alert_count": high_critical_alerts,
            "known_exploited_demo_cves_affecting_assets": len(exploited_affected),
            "awareness_completion_rate_demo": awareness_metrics.get("completion_rate", 0),
            "awareness_cohort_demo": {key: awareness_metrics.get(key) for key in ("enrolled_learners", "completed_learners", "cohort_label")},
            "open_investigations": stats["open_investigations"],
            "top_threat_categories": [{"category": key, "records": value} for key, value in top_categories],
            "top_vulnerability_categories": top_vulnerability_categories,
            "awareness_latest_score": latest_score,
            "awareness_score_trend": history,
            "top_awareness_weaknesses": history[0]["category_scores"] if history else {},
            "recommended_defensive_priorities": focus,
            "metrics": {"alerts_in_review_queue": len([x for x in alerts if x["status"] in {"NEW", "INVESTIGATING"}]), "synthetic_vulnerability_scenarios": len(vulnerabilities), "awareness_completion_rate_demo": awareness_metrics.get("completion_rate", 0)},
        }

    @app.get("/api/sources", tags=["threat-intelligence"])
    def sources(db: Database = Depends(get_db)):
        return {"items": db.source_summary(), "reliability_note": "Source reliability describes a source's historical quality; item confidence describes evidence for this specific record."}

    @app.get("/api/system/guide", tags=["system"])
    def system_guide():
        return {
            "classification": {
                "observation": "A logged event or report that needs context.",
                "indicator": "An artifact such as an IP, domain, URL, hash, or CVE used for correlation.",
                "alert": "A rule-generated request for analyst review.",
                "threat": "An assessed potential risk with supporting context.",
                "incident": "A confirmed or formally declared security event under organizational process.",
            },
            "safety": ["No indicator is visited or resolved", "Hashes are never used to locate or execute files", "Risk is not confidence", "An IOC match is not proof of compromise", "ATT&CK mapping requires behavior context"],
            "database_design": ["threats → indicators: one or more observed artifacts", "sources → threats: origin and source reliability", "threats → attack_mappings: optional behavior mapping", "threats → alerts/analyst_notes: investigation workflow", "quiz_results → awareness score history", "vulnerabilities: synthetic prioritization scenarios"],
        }

    if FRONTEND_DIR.exists():
        app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
    return app


app = create_app()
