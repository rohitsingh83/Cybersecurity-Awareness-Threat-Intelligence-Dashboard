# Security, privacy, false positives, and limitations

## Safety design

- **No indicator contact:** the application does not perform HTTP requests, DNS resolution, WHOIS, port scanning, geolocation lookup, webhook delivery, or reputation lookup. IOC search is a local exact-value SQLite query.
- **No file execution:** hash-shaped values are plain text. There is no file download, open, scan, or execution function.
- **Reserved examples:** IPs use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`); domains use `example.com`, `example.org`, `example.net`, and `.invalid`; URL strings are fictional/reserved examples; hashes are generated synthetic strings; CVE-shaped examples use a fictional future year.
- **No attack surface demonstration:** this project does not exploit vulnerabilities, scan external systems, create phishing pages, or include payloads.
- **Input validation:** Pydantic constraints, syntactic IOC validation, enum/status checks, query bounds, and parameterized SQL protect data entry paths.
- **XSS posture:** frontend content is escaped before interpolation; text is not treated as trusted HTML. Keep this discipline when adding UI fields.
- **Rate limiting:** simple in-memory per-client request limiting is provided for the local demo. It is not a production distributed rate limiter.
- **CORS:** no broad wildcard origin. Default UI uses same-origin routing.
- **Optional write key:** set `TI_API_KEY` to require `X-API-Key` on analyst write routes. The no-key mode is convenient only for localhost classroom use.
- **Secrets:** `.env` and local database files are ignored by Git. Keep real credentials and private feed keys out of source control.
- **Transport:** localhost demo traffic is local. If deployed in an authorized environment, use HTTPS, secure cookies/token handling, and a reverse proxy configured for the preview/deployment host.
- **Privacy:** quiz results store a numeric score/category summary. A name is not required. Do not add personal or employee performance data without an approved privacy purpose, retention policy, and access review.
- **Analyst notes:** notes may expose investigation context, internal detections, or personally identifiable information. Demo notes are local and fictional; production notes need encryption/access controls/auditing.

## Why threat intelligence can require access controls

Threat-intelligence data can reveal an organization's detection coverage, suspected assets, investigative hypotheses, partner reporting, internal telemetry, response plans, and vulnerabilities. Sharing raw data outside authorized audiences may expose defensive posture or private information. Use least privilege, tenant separation, retention limits, audit logging, and safe sharing rules.

## Distinctions and limits

- **Observation:** logged or reported event.
- **Indicator:** artifact to validate/search/correlate.
- **Alert:** generated request for analyst review.
- **Threat:** assessed potential concern.
- **Incident:** confirmed or formally declared event under organizational policy.

Risk is not confidence. A high-risk, low-confidence item may merit careful validation, not automatic blocking. A high-confidence assessment can still be benign or irrelevant to a particular organization.

## False positives and intelligence limitations

- An IP address may be shared by many users or services.
- A domain can change ownership, expire, or host benign and malicious content at different times.
- Cloud/CDN infrastructure can be multi-tenant.
- Indicators can go stale, be mistyped, be decontextualized, or be reused in public examples.
- Feeds can disagree, and source reliability does not guarantee each item is correct.
- Correlation can happen coincidentally; it does not prove actor attribution or compromise.
- A CVE record does not prove a particular asset is affected; version, configuration, mitigation, exposure, and ownership matter.
- ATT&CK is a behavior knowledge base, not a label generator for raw indicators.
- Synthetic records test software workflow only and are not intelligence about a real campaign.

Threat intelligence should support, not replace, human decisions and authorized internal telemetry.

## Production hardening checklist (future work)

1. Identity provider, MFA for analysts, and RBAC (viewer, analyst, admin, awareness manager).
2. HTTPS, secure headers, CSRF protection where cookie auth is used, and robust session management.
3. Central secret management; key rotation; never commit API keys.
4. Per-user and per-tenant rate limits; request-size limits; structured validation.
5. Audit trail for access, note changes, status changes, exports, and admin actions.
6. Backups, restore testing, database migrations, retention/expiration policy, and encryption at rest.
7. Feed allowlists, signed source handling, provenance tracking, deduplication, and source-specific TLP/licensing checks.
8. Sandboxed offline parsing of feed files; no automatic indicator dereferencing.
9. Privacy impact review, data minimization, retention limits, and access reviews.
10. Security review and CI checks before any integration or deployment.
