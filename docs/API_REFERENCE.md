# API reference

Base URL: `http://127.0.0.1:8000`. Interactive OpenAPI docs: `/api/docs`; alternate docs: `/api/redoc`. JSON error bodies use FastAPI's `detail` field. The app applies a simple per-client request limit under `/api/` and returns HTTP 429 when exceeded.

When `TI_API_KEY` is configured, analyst write routes require `X-API-Key: <configured-key>`. With no key configured, write routes are open for local classroom demonstration only. Read routes are unauthenticated in the demo. Production use requires real authentication, RBAC, HTTPS, auditing, and secrets management.

## Common response semantics

- 200: successful read/update.
- 201: record/note created.
- 401: configured analyst key missing/invalid.
- 404: local record not found.
- 409: duplicate threat ID.
- 422: invalid query/body/status or indicator syntax.
- 429: local API rate limit reached.

An invalid indicator search returns an explanatory JSON result rather than making an external lookup. A syntactically valid but unknown value returns `known_in_demo_dataset: false`.

## Endpoints

### `GET /api/health`

Purpose: liveness and safety flag.

Response:

```json
{"status":"ok","mode":"offline-first synthetic demo","indicator_network_lookups":false,"database":"threat_dashboard.db"}
```

### `GET /api/threats`

Query parameters: `severity`, `category`, `indicator_type`, `status`, `min_risk`, `max_risk`, `min_confidence`, `max_confidence`, `from_date`, `to_date` (YYYY-MM-DD), `q`, `sort`, `page`, `page_size`.

`sort`: `newest | oldest | risk | confidence | observed`. Page size is capped at 100. Example: `/api/threats?category=PHISHING&min_risk=60&sort=risk&page=1&page_size=25`.

Response: `{items:[...], total, page, page_size, pages}`. Filters are parameterized; sort keys are allow-listed. Invalid range pairs return 422.

### `GET /api/threats/{id}`

Purpose: investigation detail. Returns main observation, campaign-related indicators, linked alerts, analyst notes, optional ATT&CK mappings, and a simple first/latest/last-seen timeline. 404 if not found.

### `POST /api/threats`

Purpose: create a local normalized observation. Requires analyst key when configured.

Request fields: `threat_name`, `threat_category`, `indicator_type`, `indicator_value`; optional `threat_id`, `source_name`, `source_reliability`, `confidence_score`, `risk_score`, `status`, timestamps, description, `campaign_id`, `observed_count`.

Validation: supported category/status, indicator syntax, 0–100 scores, length limits. The API does not contact the submitted indicator. Response: 201 and saved record; 409 for duplicate ID; 422 for invalid input.

### `PUT /api/threats/{id}`

Request: `{"status":"MONITORING"}`. Allowed statuses: `NEW`, `UNDER_REVIEW`, `MONITORING`, `CLOSED`, `FALSE_POSITIVE`. Requires analyst key when configured. 404 if record is missing; 422 for an unsupported status.

### `GET /api/indicators/search?q=…`

Purpose: syntax validation and exact local lookup. Supported types: IPv4/IPv6, domain, URL, hash format, sender-domain, CVE ID. No DNS/HTTP/WHOIS/geo/reputation request occurs.

Response fields include `valid`, `indicator_type`, `normalized_value`, `validation_notes`, `known_in_demo_dataset`, `threat_count`, `categories`, `risk_score`, `confidence_score`, `severity`, `first_seen`, `last_seen`, `related_indicators`, `related_alerts`, `internal_sightings`, and `matches`. Unknown-but-valid values have null scores and no local match.

### `GET /api/dashboard/stats`

Purpose: aggregate dashboard KPIs and chart data: severity, categories, indicator types, statuses, risk bands, confidence bands, vulnerability severities, ATT&CK tactics/techniques, averages, and queue counts.

### `GET /api/dashboard/trends?days=30`

Returns grouped synthetic observation dates and count/average risk for up to 365 days. `days` must be 1–365.

### `GET /api/alerts?status=NEW&severity=HIGH&limit=100`

Purpose: alert queue. Optional filters; maximum limit is 500. Returns `{items:[...], total_returned}`.

### `PUT /api/alerts/{id}/status`

Request: `{"status":"INVESTIGATING"}`. Allowed values: `NEW`, `INVESTIGATING`, `MONITORING`, `RESOLVED`, `FALSE_POSITIVE`. Requires analyst key when configured. Invalid status returns 422; missing alert returns 404.

### `POST /api/threats/{id}/notes`

Request: `{"note":"Reviewed the synthetic evidence in the local demo.","author_label":"LOCAL ANALYST"}`. Note length: 3–1000 characters; author label capped at 80. Requires analyst key when configured. Do not enter real sensitive case details.

### `GET /api/vulnerabilities?min_priority=0&severity=CRITICAL`

Returns fictional `CVE-2099-…` classroom rows with CVSS, patch flag, asset criticality, exposure, demo-only exploitation status, contextual priority, and a plain-language scoring explanation. This route does not query CVE/NVD/KEV services.

### `GET /api/awareness/modules`

Returns 15 local module objects: definition, relevance, warning signs, safe practices, incident guidance, and quick task. `/api/awareness/modules/{module_id}` fetches one module; 404 if unknown.

### `GET /api/quiz`

Returns 30 question IDs, categories, prompts, and options. Correct answers are intentionally withheld until submission.

### `POST /api/quiz/submit`

Request:

```json
{"answers":{"Q01":2,"Q02":1},"anonymous_user_id":"optional-demo-token"}
```

Only quiz question IDs and option indices are accepted. The optional identifier should be random and non-identifying. Response includes overall score, category scores, weakest areas, recommendations, explanations, and result ID. Result is stored locally without requiring a name. The score is self-reflection only.

### `GET /api/awareness/score`

Returns the latest quiz result summary and a bounded local trend. Empty history returns `latest: null`.

### `GET /api/attack/tactics`

Returns supported synthetic tactics and techniques. Mapping notice explains that behavior evidence is needed.

### `GET /api/attack/techniques/{technique_id}/threats`

Returns synthetic observations linked to a technique ID, with `attribution: NOT ESTABLISHED`.

### `GET /api/executive/summary`

Returns a plain-language synthetic summary, top categories, fictional vulnerability focus, optional awareness trend, recommended defensive priorities, and an illustrative 0–100 demo risk index. Never use that score for real organizational decisions.

### `GET /api/sources`

Returns local synthetic source names, A–D reliability level/label, and record count. Reliability of a source does not guarantee any single item is correct.

### `GET /api/system/guide`

Returns record distinctions, safety rails, and a database relationship summary.

## Authentication and authorization notes

The optional API key is a local demonstration guard. It is not user authentication, role-based authorization, key rotation, or a safe public deployment model. In an authorized production environment, use a real identity provider, least-privilege RBAC, per-role access, audit logs, HTTPS, secret storage, and a threat-model review. Read access may also reveal sensitive threat intelligence and should not automatically be public.
