# Architecture and data model

## System architecture

```text
┌──────────────────────────────────────────────┐
│ Local synthetic CSV/JSON + demo asset/signals│
└──────────────────────┬───────────────────────┘
                       ▼
           generator / first-run DB seeding
                       ▼
      normalize → syntax validation → classify
                       ▼
        enrichment (local SQLite only)
         ├── internal_signals.csv (fictional)
         ├── explicit campaign IDs
         └── conservative behavior mapping
                       ▼
             risk + confidence engines
                       ▼
     correlation ── alert engine ── SQLite
                       ▼
            FastAPI REST endpoints
                       ▼
  Signal Atlas UI (HTML / CSS / JS / Canvas)
         ├── SOC dashboard / investigation
         ├── vulnerability awareness
         ├── ATT&CK behavior lens
         ├── learning center / quiz
         └── executive summary
```

**Network boundary:** The browser calls relative `/api/...` routes on the same application. IOC search is an exact SQLite lookup. The backend has no requests/HTTP client code, DNS lookups, WHOIS calls, URL openers, or file fetchers. External feeds are future work and are not active.

## Folder guide

```text
Cybersecurity-Awareness-Threat-Intelligence-Dashboard/
├── backend/                  FastAPI service and SQLite repository
│   ├── app.py                REST routes, validation, optional write-key guard, static mount
│   ├── db.py                 schema, indexes, seeding, persistence, queries
│   ├── models/schemas.py     validated Pydantic request models
│   ├── utils/local_data.py   read-only local asset/signal/metric loaders
│   ├── routes/               route package reserved; app factory registers routes in app.py
│   └── services/             validation, risk, enrichment, correlation, alert, awareness logic
├── frontend/                 same-origin dashboard assets
│   ├── index.html            application shell and navigation
│   ├── css/styles.css        responsive animated visual system; reduced-motion support
│   └── js/app.js             API calls, renderers, local charts, delegated interactions
├── data/                     synthetic local-only source data and generator
│   ├── generate_threat_data.py  deterministic safe generator
│   ├── threat_intelligence_dataset.csv  2,000 generated observations
│   ├── vulnerabilities.csv   24 fictional vulnerability scenarios
│   ├── assets.json           synthetic asset context
│   ├── internal_signals.csv synthetic local telemetry sightings
│   └── awareness_metrics.json fictional aggregate completion metric
├── awareness/                reusable lesson and quiz content
├── tests/                    service and API test suite
├── docs/                     project guide, API, test, security, portfolio notes
├── reports/                  course-project report
├── screenshots/              proof-of-work images to capture after running
├── README.md                 GitHub landing page
├── requirements.txt          runtime/test dependencies
├── .env.example              local configuration template
└── .gitignore                excludes local database, secrets, venv, caches
```

## Unified threat record

Each threat observation includes:

- `threat_id`, `timestamp`, `threat_name`, `threat_category`
- `indicator_type`, `indicator_value`
- `source_name`, `source_reliability`
- `confidence_score`, `severity`, `risk_score`
- `status`, `first_seen`, `last_seen`, `country_or_region_optional`
- `description`, `mitre_tactic_optional`, `mitre_technique_optional`, `mitre_technique_id_optional`
- `cve_id_optional`, `campaign_id`, `observed_count`, `synthetic_label`

The record is an observation; it does not contain a `confirmed_incident` assertion.

## SQLite tables and relationships

| Table | Purpose / relationship |
|---|---|
| `threats` | Main assessed observation. `threat_id` primary key. |
| `indicators` | One normalized artifact per observation; FK to `threats`. |
| `sources` | Source name, reliability level, explanatory reliability label. |
| `attack_mappings` | Optional behavior mapping; FK to `threats`, technique ID can be null. |
| `vulnerabilities` | Fictional CVE-shaped scenario, CVSS, asset context, patch flag, priority. |
| `alerts` | Workflow alert derived from a threat; optional threat FK. |
| `analyst_notes` | Investigation notes; FK to `threats`. Keep notes non-sensitive. |
| `awareness_modules` | JSON lesson content by module ID. |
| `quiz_results` | Optional anonymous score + category summary, no name required. |

Indexes support threat category, severity, indicator value, timestamp, status, alert status/threat ID, note threat ID, and quiz date queries.

## Scoring model

### Threat risk

```text
0.30 × severity points
+ 0.25 × confidence
+ 0.15 × recency
+ 0.10 × log-scaled observation frequency
+ 0.10 × source reliability
+ 0.10 × context/correlation
```

Risk classes: 0–20 informational, 21–40 low, 41–60 medium, 61–80 high, 81–100 critical. Weights are classroom defaults and should be calibrated against authorized outcomes before production use.

### Confidence

```text
0.40 × source reliability + 0.25 × corroboration
+ 0.20 × freshness + 0.15 × completeness
```

Reliability and confidence are related but not interchangeable.

### Vulnerability priority

```text
0.30 × CVSS (scaled to 100) + 0.25 × asset criticality
+ 0.15 × exposure + 0.20 × known exploitation evidence
+ 0.10 × business context
```

A contextual score is a triage aid and should be explained to the asset owner.

## Correlation and ATT&CK

- Explicit `campaign_id` / analyst correlation IDs are preferred.
- Same-category/time groups are heuristic and must be labeled tentative.
- Repeated same-indicator alerts inside the configured time window are grouped, keeping an observation count.
- Correlation is not attribution.
- ATT&CK mappings use behavior description only and are omitted when context is insufficient. A raw IOC does not imply a technique.

## API and UI

The API and static UI are hosted by one FastAPI process. Local development uses SQLite, no CDN, and no separate frontend server. `TI_API_KEY` can protect write endpoints in a local demo. This is not a full identity provider or RBAC system; use production authentication and authorization before deployment.
