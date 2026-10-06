# Cybersecurity Awareness & Threat Intelligence Dashboard

> **Signal Atlas** is an offline-first defensive cybersecurity learning dashboard. It combines local synthetic threat intelligence, IOC validation, evidence-aware scoring, contextual vulnerability prioritization, analyst workflows, MITRE ATT&CK concepts, and short awareness lessons.

**Repository description:** Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.

**Safety:** all bundled indicators and vulnerability records are synthetic, reserved, or fictional. Indicator values are handled as data. The application does not visit URLs, resolve domains, contact IP addresses, retrieve files by hash, or access external threat feeds.

---

## Overview

Security teams receive technical indicators, vulnerability notices, and human-reported observations from different places. This project demonstrates a small, explainable workflow that normalizes those records, adds local context, computes separate risk and confidence scores, groups explicit demo relationships, and turns selected records into alerts for analyst review. A parallel awareness studio teaches users to pause, verify, protect accounts, and report concerns.

The dashboard uses the fictional **Signal Atlas** interface: an animated SOC-style “signal observatory” with a live-looking local data field, interactive visualizations, an investigation drawer, local IOC search, vulnerability cards, alert triage, ATT&CK lens, awareness modules, a 30-question quiz, and an executive brief. The animations are decorative and run locally; they do not represent live network traffic.

**Standalone GitHub Pages version:** this project also builds a browser-only site into `/docs`. It needs no FastAPI server: GitHub Pages serves the bundled CSV/JSON, while notes, workflow changes, and quiz results are kept in the visitor's browser `localStorage`. Build/publish steps are in [`docs/GITHUB_PAGES_DEPLOYMENT.md`](docs/GITHUB_PAGES_DEPLOYMENT.md). The static site is public and must use synthetic/public-safe content only.

## Problem Statement

Threat feeds and awareness programs can be disconnected. A raw IOC rarely contains enough context to tell a defender what to review, while awareness content is less timely when it is unrelated to current defensive priorities. This student demo joins those workflows while explicitly avoiding the unsafe assumption that an indicator or alert proves compromise.

## Objectives

- Generate at least 2,000 deterministic synthetic threat observations for offline use.
- Validate IP, domain, URL, file-hash-shaped, sender-domain, and CVE-shaped values syntactically.
- Enrich indicators from local SQLite records, synthetic internal signals, and explicit campaign links.
- Keep **risk** (potential concern) separate from **confidence** (evidence quality).
- Provide analyst review statuses, alerts, notes, related indicators, timelines, and conservative ATT&CK mappings.
- Demonstrate context-based vulnerability prioritization and awareness training without real exploit data.
- Provide a documented REST API, automated tests, and portfolio-ready project materials.

## Cybersecurity Relevance

A SOC needs a consistent place to triage observations, distinguish alerts from incidents, and record decisions. IT and vulnerability teams need context to prioritize patch work. Security-awareness teams need short, relevant lessons and safe reporting habits. The project models these intersections for a classroom environment; it is not a production threat feed or a real organizational risk assessment.

## Features

- **Command center:** seven KPI cards; trend, severity, category, indicator type, ATT&CK, risk, confidence, vulnerability severity, and status charts; priority records; alerts.
- **Threat stream:** filters for severity, category, indicator type, status, date range, risk, and confidence; newest/highest-risk/highest-confidence/most-observed sorting; paging; CSV export.
- **IOC lookup:** syntax validation and exact local database search only; category, severity, risk, confidence, time range, source reliability, alerts, notes, ATT&CK context, and related indicators.
- **Investigation drawer:** threat context, timeline, status, related indicators, notes, alerts, source reliability, mapping, and suggested non-destructive review steps.
- **Vulnerability lab:** 24 fictional CVE-shaped examples with CVSS and contextual priority; patch flag; asset criticality; exposure; demo-only exploitation evidence.
- **Alert queue:** NEW / INVESTIGATING / MONITORING / RESOLVED / FALSE_POSITIVE workflow.
- **ATT&CK lens:** technique/tactic counts with click-through to synthetic records. Mappings are made only when behavior context is described.
- **Awareness studio:** 15 bite-sized modules, each with what/why, warning signs, safe practices, what to do next, and one task.
- **Knowledge check:** 30 scenario-based questions, category scores, weakest areas, learning recommendations, and self-reflection notice.
- **Executive brief:** plain-language synthetic summary, illustrative score components, awareness trend, and defensive priorities.
- **REST API:** FastAPI endpoints and OpenAPI docs at `/api/docs`.
- **Privacy by design:** no names required for quiz results; indicators are not contacted; write actions can be protected by an optional local API key.
- **Motion design:** animated network canvas, orbiting signal rings, animated KPI counts, chart draw-in, hover states, and reduced-motion support.

## Architecture

```text
Synthetic CSV / JSON + local demo signals
                 │
                 ▼
       Offline data generation / seed
                 │
                 ▼
 Normalization → syntax validation → local enrichment
                 │                            │
                 ▼                            ├─ demo asset / signal context
       risk + confidence scores               ├─ explicit campaign correlation
                 │                            └─ behavior-backed ATT&CK mapping
                 ▼
        SQLite threat / alert store
           ┌─────┼──────────┐
           ▼     ▼          ▼
       FastAPI  Alert     Awareness + quiz
           └─────┬──────────┘
                 ▼
    Signal Atlas HTML/CSS/JavaScript UI
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for table relationships and system details.

## Technology Stack

- **Backend:** Python 3.10+ (tested in the build workspace with Python 3.13), FastAPI, Pydantic, Uvicorn.
- **Storage:** SQLite; first-run seeding is local and deterministic.
- **Frontend:** semantic HTML, custom CSS, vanilla JavaScript, Canvas charts; no CDN or external font dependency.
- **Testing:** pytest, FastAPI TestClient, httpx.
- **Data:** Python standard library CSV/JSON generation; no API key or network required.

This is a deliberately beginner-friendly single-service implementation. React/PostgreSQL/Redis/Docker are sensible later steps, not prerequisites for running this project.

## Threat Intelligence

### Threat intelligence types

- **Strategic:** leadership-level trends and business impact.
- **Tactical:** adversary behaviors, playbooks, and defensive patterns.
- **Operational:** campaign intent, timing, and activity context.
- **Technical:** machine-readable indicators such as IPs, domains, URLs, hashes, and CVE identifiers.

This demo focuses on technical and tactical concepts plus awareness-oriented intelligence. All example records are synthetic.

### Core concepts

- **Cybersecurity awareness:** habits that help people notice, avoid, and report security risks.
- **Cyber threat intelligence (CTI):** analyzed threat information used to support defensive decisions.
- **IOC:** an artifact that may be associated with suspicious activity. An IOC can be stale, shared, or incomplete; an IOC match is not proof of compromise.
- **IOA:** an observed behavior or activity pattern that may be relevant to a security investigation.
- **Vulnerability:** a weakness that may affect confidentiality, integrity, or availability.
- **CVE:** a standardized identifier for a publicly catalogued vulnerability. The demo's `CVE-2099-…` strings are intentionally fictional and syntactically illustrative.
- **CVSS:** a standardized severity-scoring framework for vulnerability characteristics. CVSS is not a complete organization-specific patch priority.
- **Threat feed:** a collection of threat information distributed for defensive use. The current demo reads bundled local data only.
- **Threat actor:** a conceptual label for a person or group responsible for activity; attribution requires evidence and is not inferred from an IOC.
- **TTP:** tactics, techniques, and procedures—ways of describing behavior and methods at different levels of abstraction.
- **MITRE ATT&CK:** a knowledge base of adversary behaviors. A tactic describes the objective; a technique describes a way to pursue it; a sub-technique adds detail.
- **Threat enrichment:** adding context such as source, first/last seen, related observations, confidence, risk, and behavior mapping.
- **Threat correlation:** grouping observations with shared evidence. Correlation is not attribution or proof of compromise.
- **Threat hunting:** a hypothesis-driven, authorized search across internal telemetry for evidence of relevant behavior.
- **SOC:** Security Operations Center; a team and operating function for monitoring, triage, investigation, response coordination, and continuous improvement.

See [`docs/PROJECT_GUIDE.md`](docs/PROJECT_GUIDE.md) for simple and technical explanations, categories, roles, and workflows.

## IOC Analysis

`validate_indicator(value, indicator_type=None)` returns `valid`, `indicator_type`, `normalized_value`, and `validation_notes`. Supported formats are IPv4, IPv6, domain, HTTP(S) URL, MD5/SHA-1/SHA-256-shaped hexadecimal string, email/sender-domain, and CVE-shaped ID. This is **syntax validation only**; it does not establish reputation or real-world existence.

The lifecycle represented in the UI is:

```text
Observed → Validated → Enriched → Scored → Investigated → Monitored → Expired / Closed
```

The demo performs local exact-value database searches. It does not perform WHOIS, DNS, HTTP, geolocation, reputation, or file lookup.

## Threat Enrichment

Local enrichment includes indicator type, first/last seen, category, source, source reliability, confidence, risk, severity, alert links, notes, explicit campaign-related indicators, internal demo signal sightings, and any supported ATT&CK mapping. Unknown indicators receive a “not found in local demo dataset” result—not an external reputation verdict.

## Risk Scoring

The transparent illustrative score is 0–100:

| Factor | Weight |
|---|---:|
| Intrinsic severity input | 30% |
| Confidence | 25% |
| Recency | 15% |
| Observation frequency (log-scaled) | 10% |
| Source reliability | 10% |
| Context / correlation | 10% |

Classification: **0–20 Informational, 21–40 Low, 41–60 Medium, 61–80 High, 81–100 Critical**. A high score means “prioritize review,” not “confirmed incident.” The seed includes a labeled scenario `THR-2026-001` (`login-check.invalid`, 78 risk, 85 confidence, HIGH, MONITORING), with related documentation-range IP `198.51.100.25` and a fictional hash string.

## Confidence Scoring

Confidence is a separate 0–100 evidence-quality score: source reliability 40%, corroboration 25%, freshness 20%, and completeness 15%. Example: high risk with low confidence means the possible impact may be concerning but evidence is weak. Source reliability describes a source's historical quality; confidence describes the evidence for one record.

## Threat Correlation

The demo groups records by explicit synthetic campaign/correlation IDs and may label category/time heuristics as tentative. Alert correlation groups repeated same-indicator/type events within a five-minute window, retaining the observation count. Grouping reduces alert fatigue but does not prove shared control, actor, or campaign.

## MITRE ATT&CK

The generator uses a small set of established Enterprise ATT&CK entries when behavior context is present: **Initial Access / Phishing (T1566)**, **Credential Access / Brute Force (T1110)** for synthetic repeated-authentication observations, and **Impact / Data Encrypted for Impact (T1486)** for explicitly simulated impact events. The app does not map a bare IP/domain/hash to a technique. Mappings are not attribution.

## Vulnerability Awareness

Twenty-four synthetic `CVE-2099-…` scenario rows illustrate the relationship between CVSS and contextual priority. The priority model weighs CVSS (30%), asset criticality (25%), exposure (15%), demo exploitation evidence (20%), and business context (10%). The entries are fictional and not real vulnerability advisories. Patch availability is displayed separately as a planning field.

## Alert Management

Alerts are generated from risk/confidence thresholds, repeated observations, or related indicators. Alerts are requests for review. An analyst can mark them NEW, INVESTIGATING, MONITORING, RESOLVED, or FALSE_POSITIVE. A **threat** is an assessed potential risk; an **incident** is a confirmed or formally declared event under an organization's process.

## SOC Workflow

```text
Feed / local observation → IOC validation → enrichment → risk + confidence
→ alert queue → Tier 1 triage → correlation → investigation notes
→ escalate / monitor / resolve / false positive → documentation
```

A Tier 1 analyst first checks the record's syntax, source, age, confidence, local context, and authorized internal telemetry; documents evidence; then follows approved escalation policy. The UI does not block indicators, visit URLs, execute files, or take destructive actions.

## Cybersecurity Awareness Center

The 15 modules cover phishing, passwords, MFA/passkeys, social engineering, safe browsing, Wi-Fi, software updates, ransomware awareness, removable media, privacy, mobile, remote work, cloud accounts, incident reporting, and AI-enabled scams. Each includes a definition, relevance, warning signs, safe practices, response guidance, and a tiny task.

## Awareness Quiz

The quiz contains 30 questions across phishing, passwords, MFA, social engineering, safe browsing, ransomware, privacy, Wi-Fi, mobile security, and incident reporting. The API does not send correct answers until submission. Results include overall and category scores, weakest areas, and recommendations. The score is educational self-reflection only—not an employee fitness or competency judgment.

## Executive Dashboard

The executive brief translates the fictional dataset into plain language, high/critical review counts, top categories, vulnerability categories, optional awareness trends, and an illustrative risk index. The demo index uses 40% normalized open high/critical alert pressure, 40% normalized known-exploited fictional CVEs matching the bundled synthetic asset inventory, and 20% synthetic awareness-completion gap. `data/awareness_metrics.json` uses a clearly labeled fictional cohort (32 of 50, 64%) solely to demonstrate the formula. The quiz score trend is separate. The index is labeled demo-only and should never be treated as a real organizational score.

## Installation

### 1. Get the project and enter the folder

```bash
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

### 2. Create and activate a virtual environment

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Generate/refresh safe local data

```bash
python data/generate_threat_data.py
```

This writes 2,000 deterministic synthetic threat records and 24 fictional vulnerability scenarios. It does not use the network.

### 5. Initialize and seed SQLite (optional; first server start does this automatically)

```bash
python -c "from pathlib import Path; from backend.app import app; d=app.state.database; d.initialize(); print(d.seed(Path('data'), Path('awareness')))"
```

### 6. Run the website and API

```bash
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Open **http://127.0.0.1:8000**. The UI is served by FastAPI; no separate frontend server is required. Interactive API docs are at **http://127.0.0.1:8000/api/docs**.

### 7. Optional local write-key protection

Copy `.env.example` to `.env`, set a long local-only `TI_API_KEY`, then run:

```bash
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000 --env-file .env
```

Enter the same key in **System & API**. Do not commit `.env`. This is a demo guard, not enterprise authentication or RBAC.

For the requested 15-step beginner walkthrough (including commands and API verification), see [`docs/LOCAL_RUN.md`](docs/LOCAL_RUN.md).

## Usage

1. Start at **Command center** and inspect the synthetic KPIs and charts.
2. Open **IOC lookup** and search `login-check.invalid` or `198.51.100.25`.
3. Click a result or a threat row to open the investigation drawer.
4. Review the risk and confidence separately, related indicators, status, notes, and any supported ATT&CK context.
5. Use **Vulnerability lab** to compare CVSS with contextual priority.
6. Use **Alert queue** to update workflow state and add a note on a threat.
7. Review **Awareness studio**, then take the 30-question **Knowledge check**.
8. Open **Executive brief** to see a plain-language synthetic summary and the optional quiz trend.
9. Run tests with `python -m pytest -q`.

## API Documentation

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/threats` | Filter, sort, page threat rows |
| GET | `/api/threats/{id}` | Threat detail, related records, alerts, notes, timeline |
| POST | `/api/threats` | Validate and create an observation |
| PUT | `/api/threats/{id}` | Change threat workflow status |
| GET | `/api/indicators/search?q=…` | Syntax validation + exact local lookup |
| GET | `/api/dashboard/stats` | KPI and chart aggregate data |
| GET | `/api/dashboard/trends` | Synthetic event-date series |
| GET | `/api/alerts` | Local alert queue |
| PUT | `/api/alerts/{id}/status` | Update alert status |
| POST | `/api/threats/{id}/notes` | Add a local analyst note |
| GET | `/api/vulnerabilities` | Synthetic vulnerability scenarios |
| GET | `/api/awareness/modules` | Learning modules |
| GET | `/api/quiz` | Quiz without answer keys |
| POST | `/api/quiz/submit` | Score answers, persist anonymous summary |
| GET | `/api/executive/summary` | Management-ready demo summary |
| GET | `/api/attack/tactics` | Supported ATT&CK counts |
| GET | `/api/docs` | Interactive OpenAPI docs |

Request details, validation, auth mode, and status codes: [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md).

## Testing

The suite contains **54 automated tests** covering indicator formats, risk/confidence, source reliability, enrichment, correlation, alert generation, ATT&CK mapping, vulnerabilities, filters/sorting, awareness, quiz scoring, persistence, and API behavior.

```bash
python -m pytest -q
```

The build verification completed with **54 passed**. See [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) for the test IDs, inputs, expected results, and execution results.

## Security & Privacy

- Never visit suspicious URLs, resolve suspicious domains, or contact suspicious IPs from this project.
- Never retrieve or execute files based on hashes.
- Treat descriptions as untrusted text; the interface escapes values before rendering.
- Validate API input and keep write operations local. An optional `TI_API_KEY` protects analyst write routes for a local demo.
- The application includes a basic per-client API request rate limit and does not allow broad CORS origins.
- Keep secrets in environment variables; `.env` is ignored by Git. Use HTTPS and identity/RBAC before any authorized deployment.
- Minimize personal information; quiz results need no name. Analyst notes are local and can still contain sensitive data—do not enter real case details in the demo.
- Threat-intelligence data can itself be sensitive because it may reveal detection rules, investigations, asset exposure, or partner reporting. Production access should be least-privilege and audited.

See [`docs/SECURITY_AND_LIMITATIONS.md`](docs/SECURITY_AND_LIMITATIONS.md).

## Results

- `data/threat_intelligence_dataset.csv`: 2,000 labeled synthetic observations.
- `data/vulnerabilities.csv`: 24 fictional scenarios.
- `data/assets.json` and `data/internal_signals.csv`: synthetic local asset/signal context.
- `data/awareness_metrics.json`: fictional aggregate cohort for the demo executive formula.
- `awareness/modules.json`: 15 learning modules.
- `awareness/quiz_questions.json`: 30 questions.
- SQLite is generated locally at first run and ignored by Git.
- Automated verification: 54 passing tests at build time.

## Limitations

This project is a learning prototype, not production CTI. It has no real feed collector, threat reputation lookup, WHOIS/DNS/HTTP enrichment, endpoint telemetry, enterprise identity, full RBAC, managed secrets, high-availability storage, or validated real organization assets. The risk and confidence models are illustrative. ATT&CK mapping is intentionally limited. Synthetic data demonstrates process, not real threat intelligence.

## Future Improvements

Defensive next steps include authorized STIX/TAXII or MISP feed ingestion; deduplication and indicator expiration; reputable CVE/CISA KEV sources; EPSS-style probability context; asset software inventory; SIEM/SOAR integration; endpoint/email/cloud telemetry; improved confidence calibration; ATT&CK Navigator export; role-based dashboards; audit trails; centralized logging; Docker; CI/CD; PostgreSQL; and privacy/security review. Integrations should be explicitly authorized, rate-limited, and configured not to contact indicators themselves.

## Screenshots

Capture the 37 proof images listed in [`docs/PORTFOLIO.md`](docs/PORTFOLIO.md) and save them under `screenshots/`. Suggested names include `01-command-center.png`, `12-ioc-search-known-demo.png`, `17-attack-mapping.png`, `28-quiz-result-category-scores.png`, and `37-readme-preview.png`.

## Learning Outcomes

- Defensive CTI vocabulary and indicator lifecycle.
- Python data generation, FastAPI, Pydantic validation, SQLite, and REST design.
- IOC syntax validation, enrichment, risk/confidence separation, source reliability, and correlation.
- MITRE ATT&CK behavior mapping with evidence caveats.
- Vulnerability prioritization, SOC triage concepts, awareness learning design, unit/API testing, documentation, and safe GitHub practices.

## Ethical Disclaimer

> “This project is designed exclusively for defensive cybersecurity education, threat-intelligence analysis, and security awareness. It does not execute, deploy, or interact with malicious payloads or unauthorized systems.”

### Author

Student project — replace this line with your preferred name, course, institution, and GitHub/LinkedIn links before publishing.
