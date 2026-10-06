# Resume, LinkedIn, and portfolio proof

## Resume bullets

- Built an offline-first **FastAPI + SQLite** defensive threat-intelligence dashboard with 2,000 deterministic synthetic records, IOC syntax validation, local enrichment, risk/confidence scoring, correlation, alert triage, and a 54-test automated suite.
- Designed a SOC-style analyst workflow with source-reliability context, conservative MITRE ATT&CK mapping, vulnerability-priority scoring, status tracking, timelines, and notes—while clearly separating an observation, indicator, alert, threat assessment, and incident.
- Created a responsive animated awareness center with 15 micro-learning modules and a 30-question quiz that computes category scores and learning recommendations without requiring a named user or external data feed.

Adjust the verbs and metrics to match what you actually ran and can explain. Avoid claiming live feed integrations or production deployment.

## Two-line project description

Signal Atlas is a defensive cybersecurity learning dashboard that combines synthetic cyber threat intelligence, local IOC analysis, risk/confidence scoring, vulnerability prioritization, ATT&CK context, and SOC-style triage. It pairs technical signals with short awareness lessons and a 30-question quiz, using offline data and no indicator callbacks.

## LinkedIn project description

**Cybersecurity Awareness & Threat Intelligence Dashboard — Signal Atlas**

I built an offline-first defensive cybersecurity dashboard to practice how threat intelligence becomes useful to analysts and users. The application generates 2,000 synthetic threat observations and 24 fictional vulnerability scenarios, validates IP/domain/URL/hash/CVE-shaped values, enriches indicators from a local SQLite dataset, calculates distinct risk and evidence-confidence scores, groups explicit synthetic relationships, and surfaces a SOC-style review queue. It includes conservative MITRE ATT&CK mapping only when the synthetic description contains behavior context.

The human-defense side contains 15 short awareness modules and a 30-question scenario quiz, with category scoring and personalized refreshers. The executive view summarizes the fictional dataset in plain language. The complete project includes FastAPI REST endpoints, a responsive animated HTML/CSS/JavaScript interface, API documentation, and 54 automated tests.

**Safety by design:** all included data is synthetic or reserved; the project does not visit suspicious URLs, contact IPs, resolve domains, execute files, exploit vulnerabilities, or attack external systems. An IOC match or high risk score is not represented as a confirmed compromise.

## Technical skills demonstrated

Python · FastAPI · Pydantic · SQLite · REST API design · defensive CTI concepts · IOC validation · data normalization · local enrichment · risk scoring · confidence scoring · source reliability · threat correlation · alert fatigue reduction · MITRE ATT&CK concepts · vulnerability prioritization · SOC workflow · security awareness · quiz analytics · privacy minimization · testing with pytest · Git/GitHub · technical documentation.

## GitHub description

“Defensive cybersecurity dashboard combining threat intelligence, IOC analysis, risk and confidence scoring, ATT&CK mapping, vulnerability awareness, SOC workflows, and interactive cybersecurity awareness training.”

## Topics

`cybersecurity`, `threat-intelligence`, `cti`, `soc`, `ioc`, `mitre-attack`, `security-awareness`, `python`, `fastapi`, `vulnerability-management`, `incident-response`, `security-analytics`, `defensive-security`.

## Screenshot proof checklist

Use [`SCREENSHOT_CHECKLIST.md`](SCREENSHOT_CHECKLIST.md) for the 37 suggested filenames and capture requirements. Capture genuine local behavior; don't include real sensitive data.

## Future scope

Authorized STIX/TAXII; SIEM/SOAR and ticketing integration; approved CVE/KEV/EPSS-style context; asset inventory correlation; indicator expiration; more calibrated confidence; ATT&CK Navigator export; email/endpoint/cloud telemetry from owned environments; identity/RBAC; audit logs; Docker; CI/CD; PostgreSQL; centralized logging; executive trends; privacy review. All integrations must stay defensive, authorized, and opt-in.
