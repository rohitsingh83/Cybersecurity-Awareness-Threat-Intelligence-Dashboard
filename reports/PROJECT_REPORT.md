# Project Report

## Abstract

This project presents Signal Atlas, a defensive, offline-first Cybersecurity Awareness & Threat Intelligence Dashboard. The prototype generates 2,000 synthetic threat observations and fictional vulnerability scenarios, validates indicator syntax, enriches records with local context, computes separate risk and confidence scores, correlates explicitly related observations, and supports alert triage. A parallel awareness center provides short modules, a 30-question quiz, category scores, and learning recommendations. The system is designed to teach a student how to reason about threat information while avoiding active interaction with suspicious indicators. It is not a production intelligence service and does not represent real threats.

## Introduction

Modern defenders need to interpret external threat context alongside internal telemetry, patch needs, and user reports. A raw indicator may be incomplete or stale; a score cannot replace evidence; an awareness lesson is most useful when it produces an actionable habit. The project models a small end-to-end pipeline and an educational experience in a single web application.

## Problem Statement

Threat information may be distributed across feeds, dashboards, reports, and awareness systems. Students also need a safe environment to learn how data normalization, validation, contextual prioritization, analyst workflows, and awareness content fit together. The project addresses this learning gap with deterministic local data and transparent behavior.

## Objectives

1. Generate a safe dataset of at least 2,000 synthetic records.
2. Validate supported indicator formats without checking maliciousness.
3. Enrich exact matches using local synthetic context only.
4. calculate independent risk and confidence scores.
5. Demonstrate source reliability, correlation, alerts, and analyst notes.
6. Map behavior to MITRE ATT&CK only when evidence context is present.
7. Teach vulnerability prioritization beyond CVSS.
8. Deliver 15 awareness modules and an interactive 30-question quiz.
9. Provide a clear executive summary, documented REST API, and automated tests.

## Cybersecurity Awareness

Cybersecurity awareness develops safe habits: recognizing phishing, protecting passwords, using MFA, verifying unusual requests, browsing carefully, maintaining updates, protecting data, and reporting incidents. The project treats learning scores as self-reflection rather than employee judgments.

## Cyber Threat Intelligence

CTI is analyzed threat information used to support defensive decisions. It includes technical indicators, behavior, source context, vulnerabilities, timelines, and confidence. The prototype implements offline technical and tactical concepts; it makes no claim to current or real threat intelligence.

## Threat Intelligence Types

- Strategic: high-level trends and business implications.
- Tactical: behavior and defensive patterns.
- Operational: campaign timing, intent, and context.
- Technical: machine-readable IOCs and vulnerability identifiers.

The implementation focuses on technical and tactical intelligence with awareness-oriented output.

## IOC and IOA Concepts

An IOC is an artifact that may be associated with suspicious activity. An IOA describes a behavior pattern or activity. Both need context. An IOC match does not prove compromise; an IOA is not necessarily malicious without surrounding evidence. The application makes this limitation visible throughout the interface.

## Threat Intelligence Lifecycle

```text
Observe → Validate → Enrich → Score → Correlate → Investigate → Monitor → Close / Learn
```

Data is generated locally, normalized into one schema, syntax-checked, enriched from SQLite, and then shown to users or analysts. No indicator is resolved, visited, or contacted.

## Proposed System

The system consists of a Python data generator, service modules, SQLite persistence, a FastAPI API, and a responsive HTML/CSS/JavaScript dashboard. Separate services handle validation, scoring, source reliability, ATT&CK mapping, vulnerability priority, enrichment, alert logic, correlation, and quiz scoring.

## Architecture

```text
Synthetic CSV/JSON + local sample signals
             ↓
       Seed / normalize
             ↓
 IOC syntax validation → local enrichment
             ↓                    ↓
 Risk + confidence       internal demo context
             ↓                    ↓
 correlation → alert engine → SQLite
             ↓                    ↓
              FastAPI REST API
                    ↓
          SOC and awareness UI
```

## Synthetic Dataset

`data/threat_intelligence_dataset.csv` contains 2,000 rows and the requested fields, including category, type, source, reliability, risk, confidence, status, timestamps, optional ATT&CK/CVE mapping, correlation key, observation count, and `SYNTHETIC / DEMO ONLY` label. IPs use documentation ranges. Domains use reserved example domains and `.invalid`. URLs are fictional. Hashes are random-looking deterministic SHA-256-shaped strings. CVE-shaped identifiers use fictional future-year values. The generator uses a fixed seed and performs no network I/O.

The highlighted demo record `THR-2026-001` uses `login-check.invalid`, is HIGH with risk 78 and confidence 85, and is MONITORING. It is linked with reserved documentation IP `198.51.100.25` and a synthetic hash by an explicit demo campaign key.

## IOC Validation

`validate_indicator()` accepts IPv4, IPv6, domain, URL, MD5/SHA-1/SHA-256-shaped digest, sender domain, and CVE-shaped syntax. It returns validity, canonical type/value, and notes. Validation establishes syntax only—not reputation, ownership, maliciousness, or vulnerability existence.

## Threat Enrichment

The enrichment engine uses local records, alerts, analyst notes, internal synthetic sightings, and explicit campaign IDs. It returns first/last seen, category, source, scores, severity, related indicators, mappings, and an interpretation. Unknown indicators are reported as not found locally.

## Risk Scoring

Risk is a 0–100 potential-concern score: severity 30%, confidence 25%, recency 15%, logarithmic observation frequency 10%, source reliability 10%, and context/correlation 10%. Classification is informational 0–20, low 21–40, medium 41–60, high 61–80, critical 81–100. The score prioritizes review; it does not prove compromise.

## Confidence Scoring

Confidence is a separate evidence-quality score: source reliability 40%, corroboration 25%, freshness 20%, completeness 15%. A high-risk, low-confidence record should be validated. A high-confidence score does not establish relevance to every organization.

## Source Reliability

Synthetic sources include Internal SOC, Security Vendor, Public Threat Feed, Research Report, Community Submission, and Unknown Source. Reliability levels A–D mean Highly Reliable, Usually Reliable, Fairly Reliable, and Reliability Unknown. Source reliability is a historical/general estimate; confidence is specific to one item.

## Threat Correlation

The system groups records with explicit campaign IDs and labels heuristic category/time correlations as tentative. Repeated same-indicator events inside a short window can be combined into one alert with an observation count. Correlation reduces noise but does not prove attribution or compromise.

## MITRE ATT&CK

ATT&CK describes tactics, techniques, and sub-techniques. A tactic represents an objective; a technique represents a method. This project maps only behavior-described synthetic records to limited, established technique IDs such as T1566, T1110, and T1486. A raw indicator alone is not mapped. The UI supports tactic/technique frequency and click-through to associated rows.

## Vulnerability Awareness

The vulnerability module contains 24 fictional CVE-shaped rows with product category, CVSS, patch flag, demo-only exploitation status, published date, asset context, and description. The priority model combines CVSS, asset criticality, exposure, exploitation evidence, and business context. CVSS alone is not a patch plan. No exploitation steps are provided.

## Alert Management

Alerts are generated from configured risk/confidence thresholds, repeated observations, or related indicator context. The alert lifecycle is NEW, INVESTIGATING, MONITORING, RESOLVED, or FALSE_POSITIVE. Alerts ask for review; incidents are declared through organizational processes, not by this score.

## SOC Workflow

```text
Threat feed / observation → IOC validation → enrichment → risk + confidence
→ alert → analyst triage → correlation → investigation → escalation/monitor/resolve
→ note and documentation
```

A Tier 1 analyst should verify source, syntax, recency, confidence, local context, and authorized internal telemetry; document knowns/unknowns; and follow escalation policy. The project does not initiate blocking or destructive response actions.

## Awareness Center

Fifteen modules include phishing, password security, MFA/passkeys, social engineering, safe browsing, Wi-Fi, updates, ransomware awareness, USB safety, data privacy, mobile, remote work, cloud security, incident reporting, and AI-enabled scam awareness. Each provides what, why, warning signs, safe practices, response guidance, and a quick task.

## Quiz System

Thirty scenario questions cover ten topic groups. Correct answers are withheld in the quiz GET response. Submission computes overall score, category scores, weakest areas, explanations, and recommendations, then stores a local score summary with no required identity. The result is educational self-reflection, not employee fitness or competency.

## Executive Dashboard

The executive view communicates the fictional threat landscape, high/critical review volume, synthetic vulnerability focus, optional awareness-score history, and an illustrative organization-risk index. The index uses a 40/40/20 weighting for normalized open high/critical alert pressure, known-exploited fictional CVEs matching the synthetic asset list, and a synthetic awareness-completion gap. A 32/50 (64%) fictional aggregate cohort is provided only to demonstrate the formula; actual quiz score history is separate. Each metric is labeled synthetic/demo and is not a claim about an actual organization.

## Testing

Fifty-four automated tests cover format validation, risk, confidence, reliability, enrichment, correlation, duplicate events, alert generation/status, ATT&CK, vulnerability prioritization, database persistence, dashboard filtering/sorting, modules, quiz, recommendations, API behavior, and validation errors. Build verification: `pytest -q` → **54 passed**. Full test scenario table: `docs/TEST_PLAN.md`.

## Security

The implementation uses reserved/example data, no external connections, Pydantic validation, parameterized SQL, escaped UI values, a same-origin API/UI, a basic per-client rate limit, optional write-key guard, and a Git-ignored local DB/secrets template. Production use requires real auth/RBAC, HTTPS, auditing, managed secrets, access reviews, robust rate limiting, and privacy governance. See `docs/SECURITY_AND_LIMITATIONS.md`.

## Results

The application starts locally, seeds 2,000 synthetic records and 24 fictional vulnerability scenarios, exposes documented REST routes, and supports interactive dashboard workflows. The built-in example is searchable and linked to related synthetic observations. Automated tests pass in the build environment.

## Limitations

There are no live feed integrations, live reputation calls, asset agents, SIEM/EDR/email connectors, real CVEs, production auth, real organizational assets, or calibration against real outcomes. Scoring weights are illustrative. Synthetic data is not threat intelligence. Correlation is not proof.

## Future Scope

Authorized feed ingestion, STIX/TAXII, MISP interoperability, asset inventory context, approved CVE/KEV and EPSS-style signals, indicator expiration, stronger deduplication, calibrated confidence, SIEM/SOAR integration, ATT&CK Navigator, email/endpoint/cloud signals, RBAC, audit trails, Docker, CI/CD, PostgreSQL, centralized logging, and executive analytics.

## Conclusion

Signal Atlas demonstrates a safe, modular path from synthetic threat data through validation, enrichment, scoring, correlation, SOC review, and awareness learning. Its most important design principle is evidence discipline: a syntactically valid IOC is not necessarily malicious, a high risk score is not confidence, an alert is not an incident, and correlation is not attribution.
