# Project Guide — Concepts, workflow, and industry context

## 1. Short project explanation

### Simple explanation

Think of the dashboard as a careful librarian for security clues. It reads fictional clues (an IP-shaped value, a domain, a hash, or a vulnerability record), checks that the value is formatted correctly, finds matching context in a local demo archive, and ranks which items deserve a human's attention. It also teaches users how to spot suspicious requests and report them safely.

A clue is not a verdict. A suspicious-looking indicator might be stale, shared, benign, or missing context. An **observation** is data; an **indicator** is an artifact; an **alert** is a generated request for review; a **threat** is an assessed potential risk; an **incident** is a confirmed or formally declared event under an organization's policy.

### Technical explanation

The project ingests a bundled deterministic CSV/JSON dataset; normalizes and validates indicator values; enriches exact matches using local SQLite records and synthetic internal-signal examples; calculates a 0–100 threat-risk score separately from a 0–100 evidence-confidence score; conservatively maps behavior to a small number of ATT&CK concepts; stores threat, indicator, source, mapping, vulnerability, alert, analyst-note, awareness, and quiz-result records; and serves a same-origin FastAPI API and HTML/CSS/JavaScript dashboard.

## 2. Glossary

- **Cybersecurity awareness:** knowledge and habits that help people recognize, avoid, and report risk. Examples include phishing awareness, password managers, MFA, safe browsing, secure Wi-Fi, software updates, data privacy, attachment caution, and incident reporting.
- **Cyber threat intelligence (CTI):** collected and analyzed information about threats, behaviors, vulnerabilities, and context used to make defensive decisions.
- **IOC (Indicator of Compromise):** an artifact potentially associated with suspicious activity, such as an IP, domain, URL, hash, or sender domain. A match is not proof of compromise.
- **IOA (Indicator of Attack / Activity):** a behavior pattern or event sequence that may indicate suspicious activity. Terminology differs between vendors; it still requires context.
- **Vulnerability:** a weakness that could affect a system's security properties.
- **CVE:** a standardized public identifier format for a vulnerability record. The project uses `CVE-2099-…` shapes as fictional examples; syntax validation does not check existence.
- **CVSS:** a standardized severity score for vulnerability characteristics. It is useful input, not the only patch-priority factor.
- **Threat feed:** a collection of threat information distributed for defenders. This project reads local synthetic files; external feeds are future work only.
- **Threat actor:** a label for a person or group behind activity. Attribution is difficult and should not be inferred from one indicator.
- **TTP:** tactic, technique, and procedure; descriptions of adversary objectives and behavior at different levels of specificity.
- **MITRE ATT&CK:** a knowledge base describing adversary behaviors. A tactic describes why/what objective; a technique describes how; a sub-technique is more specific.
- **Threat enrichment:** adding useful context around a raw indicator, for example first/last seen, source reliability, confidence, related observations, local sightings, or justified behavior mappings.
- **Threat correlation:** grouping observations that share an explicit key or useful context. Correlation indicates a relationship to investigate, not attribution.
- **Threat hunting:** an authorized, hypothesis-driven search through an organization's internal telemetry for evidence that may not have produced an alert.
- **SOC:** Security Operations Center; people, processes, and technology for monitoring, triage, investigation, response coordination, and learning.

## 3. Cybersecurity awareness vs threat intelligence

| Cybersecurity awareness | Threat intelligence |
|---|---|
| Human-focused: recognize and avoid risks. | Technical/operational: collect and analyze threat context. |
| Examples: phishing, password reuse, MFA, safe browsing, social engineering, updates, Wi-Fi, privacy, suspicious attachments, reporting. | Examples: IOC, CVE, source quality, timing, behavior, confidence, risk, and correlation. |
| Outcome: safer decisions and faster reporting. | Outcome: better prioritization and defensive investigation. |

The project combines **human defense + technical threat intelligence**. A phishing-heavy synthetic feed can point users toward a phishing refresher, while analysts still decide whether any internal sighting merits investigation. Awareness scores remain educational; they do not rank employee fitness.

## 4. End-to-end workflow

```text
Threat data / synthetic feed
  ↓ data collection (local CSV/JSON only)
Normalization
  ↓ syntax validation (not maliciousness validation)
IOC extraction / classification
  ↓ category, source, timestamps, status
Enrichment
  ↓ local SQLite context + synthetic internal signals
Risk + confidence scoring
  ↓ separate scales and explainable factors
MITRE ATT&CK mapping where behavior evidence justifies it
  ↓ optional, conservative mapping
Threat database → correlation → alert queue
  ↓ human triage and notes
SOC dashboard → awareness module → analyst / user
```

The seed pipeline loads the synthetic CSV into SQLite; it does not download data. The UI's IOC lookup calls `/api/indicators/search`, which executes local queries only.

## 5. IOC lifecycle and record language

```text
Observed → Validated → Enriched → Scored → Investigated → Monitored → Expired/Closed
```

- **Observation:** a recorded event/report, not necessarily suspicious.
- **Indicator:** a value that can be searched or correlated.
- **Alert:** a rule output requesting human review.
- **Threat:** an assessment of potential risk given current evidence.
- **Incident:** a confirmed or formally declared event under organizational policy.

The app must not promote an observation to a confirmed incident solely because an IOC matched or risk is high.

## 6. Threat-intelligence types

- **Strategic:** broad trends and business impact for executives; e.g. “credential abuse is increasing in our sector,” if supported by reliable evidence.
- **Tactical:** reusable behavior and defensive patterns; e.g. a behavior mapped to an ATT&CK technique and corresponding detection/awareness focus.
- **Operational:** campaign timing, intent, and context; e.g. a well-supported campaign note for a sector.
- **Technical:** machine-readable artifacts such as domains, IPs, URLs, hashes, and CVE IDs.

This student project focuses on **technical + tactical + awareness-oriented** intelligence. Strategic/operational records are discussed, not asserted as live facts.

## 7. Industry relevance and roles

A SOC, bank, cloud provider, IT enterprise, government office, e-commerce company, healthcare organization, university, MSSP, or cybersecurity consultancy may combine indicators, vulnerabilities, telemetry, alert workflows, and user education. A real organization must use authorized data and policies; this student dataset is not live intelligence.

| Role | How this project demonstrates relevant concepts |
|---|---|
| SOC Analyst | queue review, risk/confidence separation, status changes, notes, timeline, false-positive handling |
| Cybersecurity Analyst | indicator validation, filtering, reporting, defensive controls, interpretation |
| Threat Intelligence Analyst | source reliability, enrichment, categorization, correlation, caveats |
| Incident Response Analyst | triage/documentation concepts and high-level lifecycle awareness |
| Security Engineer | API/data architecture, validation, storage, safe defaults, input handling |
| Vulnerability Analyst | CVSS vs contextual priority, asset criticality, exposure, patch awareness |
| Security Awareness Specialist | modules, quizzes, personalized learning recommendations, respectful scoring |
| Threat Hunter | explains hypothesis-led authorized searches; does not perform external hunting |

The project demonstrates Python, REST API design, SQLite, input validation, data analysis, defensive threat intelligence, MITRE ATT&CK concepts, vulnerability management, human-centered awareness, test writing, documentation, and ethical boundaries.

## 8. Threat categories and defensive habits

| Category | Description / common signal | Potential impact | Defensive controls and awareness |
|---|---|---|---|
| Phishing | Unexpected message, urgent request, sender/domain mismatch | Credential disclosure or unsafe action | Email filtering, MFA, independent verification, reporting |
| Malware | Untrusted file reputation signal or endpoint alert | Device/service disruption or data exposure | Managed endpoint protection, trusted software sources, patching, report unusual behavior |
| Ransomware | High-level ransomware-impact awareness signal | File availability, downtime, extortion risk | Tested backups, MFA, least privilege, patching, monitoring, practiced response |
| Credential threats | Repeated auth failures or suspicious sign-in alert | Account takeover risk | MFA/passkeys, unique passwords, rate limits, session review, user reporting |
| Social engineering | Urgency, authority, secrecy, unusual payment/data request | Fraud or disclosure | Separate-channel verification and approval controls |
| Network threats | Reserved example IP or authorized internal alert | Possible unwanted communication if validated by defenders | Network telemetry, segmentation, change control; never contact a suspicious IP from this demo |
| Web threats | URL/domain report or browser warning | Account/data exposure | Safe browsing, trusted bookmarks, gateway controls, no automatic URL visits |
| Data exposure | Misrouted file or oversharing signal | Privacy or business harm | Data minimization, recipient/permission checks, reporting |
| Account takeover risk | Unfamiliar sessions or recovery changes | Unauthorized account use | MFA, passkeys, session review, account recovery policy |
| Vulnerability exposure | CVE-shaped awareness record | Weakness may remain unpatched | Asset inventory, patch process, exposure/context-based prioritization |

## 9. Risk, confidence, and source reliability

### Risk

Risk is an illustrative measure of potential concern. Implemented weights: severity 30%, confidence 25%, recency 15%, log-scaled observation count 10%, source reliability 10%, context/correlation 10%. A high risk is not a compromise verdict.

### Confidence

Confidence estimates evidence quality: source reliability 40%, corroboration 25%, freshness 20%, completeness 15%. Examples:

- **Risk 90 / confidence 25:** potentially serious, but evidence quality is weak; validate before action.
- **Risk 70 / confidence 95:** strong evidence for a meaningful-risk assessment; still investigate using authorized context.

### Source reliability

Synthetic source types: Internal SOC, Security Vendor, Public Threat Feed, Research Report, Community Submission, Unknown Source. Levels: A—Highly Reliable; B—Usually Reliable; C—Fairly Reliable; D—Reliability Unknown. Reliability is a general source-quality estimate; confidence applies to one specific intelligence item.

### Illustrative organization-risk index

The executive demo combines three normalized 0–100 components: open high/critical alert pressure (40%), known-exploited fictional CVEs that match the synthetic asset inventory (40%), and an awareness-completion gap (20%). The bundled `data/awareness_metrics.json` has a clearly synthetic cohort of 32 completions among 50 fictional learners (64%). The normalizers (12 alerts and 4 matching CVEs saturate their components) are teaching assumptions, not a calibrated business-risk formula. Actual quiz score history is displayed separately. No real organization or employee data is represented.

## 10. ATT&CK and evidence

The project uses validated high-level mappings only when the description includes relevant synthetic behavior. Current mappings include Initial Access / Phishing (T1566), Credential Access / Brute Force (T1110), and Impact / Data Encrypted for Impact (T1486). A raw IOC has no behavior by itself. No technique IDs are guessed from an indicator alone; click a technique in the ATT&CK lens to view associated synthetic records.

## 11. CVE, CVSS, patches, and zero-days

- A **patch** is a vendor-provided correction or mitigation; verify applicability and change control.
- An **exploit** conceptually takes advantage of a vulnerability. This guide provides no exploitation instructions.
- A **zero-day** is a vulnerability that is unknown to or not yet fixed by the responsible vendor at the relevant time; definitions can vary by context.
- **CVSS alone** is not enough for a patch queue. Consider CVSS + asset criticality + exposure + known exploitation evidence + business context.

For example, an isolated disposable test asset with a high base score may be lower priority than a somewhat lower-scored issue on an exposed, business-critical system. The demo calculates the contextual score and labels all data synthetic.

## 12. SOC and incident-response awareness

Tier 1 concept workflow: review the alert metadata; validate syntax; confirm source and timestamps; inspect enrichment and correlation; check authorized internal sightings; record what is known and unknown; classify as investigate/escalate/monitor/resolve/false positive under policy; document the rationale. Do not visit an IOC or probe an external service.

High-level incident-response lifecycle (frameworks differ in labels):

1. **Preparation** — roles, contacts, backups, plans, training.
2. **Detection / identification** — assess signals and determine scope with authorized telemetry.
3. **Containment** — coordinated actions under approved procedures.
4. **Eradication** — remove the confirmed cause using trusted response processes.
5. **Recovery** — restore and validate services safely.
6. **Lessons learned** — document improvements to controls, communication, and training.

Educational checklist: know the reporting channel; record time/device/observations; protect credentials; preserve context; notify authorized staff promptly; follow their guidance; do not attempt destructive remediation or personal investigation.

## 13. Student implementation choices

The easiest complete student stack is FastAPI + SQLite + HTML/CSS/vanilla JS. A beginner can run one command and avoid a separate frontend build step. The same API can later support React/PostgreSQL. The project generator is deterministic and safe to rerun; reset the ignored SQLite database only if you want a fresh local state.
