# Interview preparation — exactly 10 questions and answers

## 1. “Explain your project.”

**Answer:** I built Signal Atlas, an offline-first Cybersecurity Awareness & Threat Intelligence Dashboard. It uses 2,000 deterministic synthetic threat observations and fictional vulnerability scenarios. The technical workflow validates indicator syntax, enriches exact matches from local SQLite data, calculates separate risk and confidence scores, groups explicitly related records, and presents alerts for analyst review. I added conservative MITRE ATT&CK mapping where the synthetic description contains behavior context, plus a vulnerability-priority view. On the human-defense side, there are 15 awareness modules, a 30-question quiz, category scores, learning recommendations, and an executive summary. The app does not contact indicators or external systems, and an IOC match is never treated as automatic proof of compromise.

## 2. What is cyber threat intelligence, and what part did you implement?

**Answer:** Cyber threat intelligence is analyzed information about threats and behaviors that helps defenders make decisions. It is more than a raw list: source quality, time, confidence, relevance, and context matter. My project primarily demonstrates technical and tactical CTI using synthetic IPs, domains, URL strings, hash-shaped values, and CVE-shaped examples, then adds local enrichment and a review workflow. It does not claim to be a live feed platform.

## 3. What is an IOC? Does a match prove compromise?

**Answer:** An IOC is an artifact that may be associated with suspicious activity, such as an IP address, domain, URL, file hash, or sender domain. No, a match does not prove compromise. Indicators can be stale, shared, benign in another context, or incorrectly reported. In my application, an exact local match adds evidence to review; it does not create an incident declaration or automatically take action.

## 4. What is the difference between your risk score and confidence score?

**Answer:** Risk estimates how concerning an item may be, using severity, confidence, recency, observation frequency, source reliability, and context. Confidence estimates how strong the supporting evidence is, using reliability, corroboration, freshness, and completeness. They are separate on purpose. A 90-risk, 25-confidence item could have high potential impact but weak evidence, so I would validate it before acting. Neither score proves compromise.

## 5. What is threat enrichment in your project?

**Answer:** Enrichment adds context to a raw value. For a known synthetic indicator, my local engine can show type, categories, source and reliability, first and last seen, risk, confidence, alert links, analyst notes, internal demo sightings, related indicators with an explicit campaign key, and any supported behavior mapping. It is all local data; there are no DNS, WHOIS, HTTP, or reputation calls.

## 6. How did you use MITRE ATT&CK without overclaiming?

**Answer:** ATT&CK describes adversary behaviors through tactics, techniques, and sub-techniques. A tactic is an objective; a technique is a way to pursue it. I only map when the synthetic record describes behavior, such as a phishing/lure observation that supports Initial Access / Phishing, T1566. A bare IP or domain gets no technique mapping. I also label attribution as not established because ATT&CK mapping does not identify an actor.

## 7. How do you prioritize vulnerabilities beyond CVSS?

**Answer:** CVSS is an important severity input but not an organization-specific patch order. The demo score combines CVSS, asset criticality, exposure, synthetic known-exploitation context, and business context. That lets an exposed critical service rank above an isolated disposable test asset even if the latter has a higher base score. In a real environment, I would validate product/version, owner, mitigation, approved threat evidence, and change windows.

## 8. What is threat correlation, and how do you reduce alert fatigue?

**Answer:** Correlation groups observations that share evidence, like a synthetic campaign ID, or groups repeated same-indicator observations in a short time window. The alert correlation helper produces one grouped record with an observation count rather than one analyst alert per repeated event. The group is still a hypothesis; it does not prove attribution or compromise. Explicit shared keys are stronger than category/time heuristics.

## 9. Describe the SOC analyst workflow this dashboard supports.

**Answer:** An analyst can review the alert queue, validate syntax, check source reliability and timestamps, compare risk with confidence, inspect local enrichment and related records, check only justified ATT&CK context, then document a decision and update status to investigating, monitoring, resolved, or false positive. In a real SOC, the analyst would correlate with authorized internal telemetry and follow the organization's escalation procedure. My demo does not block indicators or contact external systems.

## 10. What are the project's limitations, and what would you improve next?

**Answer:** The data is synthetic, the scoring weights are illustrative, and the app has no real feed integration, production identity provider, full RBAC, live asset inventory, or SIEM connection. Indicators and sources can be stale or wrong, and correlation does not prove attribution. I would first add authenticated role-based access, audit logging, feed provenance and expiration, better confidence calibration, and a controlled asset inventory. Then I would consider authorized STIX/TAXII, CVE/KEV context, and SIEM integration with privacy and network-safety review.
