# Automated test plan and execution result

**Execution recorded during project build:** `pytest -q` → **54 passed**. The API fixture initializes a temporary SQLite database from the deterministic synthetic files. All tests use reserved/example inputs and do not make network requests.

| ID | Scenario / input | Expected result | Actual result |
|---|---|---|---|
| T01 | Valid IPv4 `198.51.100.25` | Valid IP address syntax | PASS |
| T02 | Invalid IPv4 `999.1.1.1` | Rejected syntactically | PASS |
| T03 | Valid IPv6 `2001:db8::25` | Valid IPv6 syntax | PASS |
| T04 | Domain `Login-Check.INVALID` | Lowercase normalized domain | PASS |
| T05 | Domain `bad..example.com` | Rejected syntax | PASS |
| T06 | URL `https://example.net/demo/hello` | Valid URL syntax; not opened/contacted | PASS |
| T07 | 32-character hex value | Valid MD5-shaped format | PASS |
| T08 | 40-character hex value | Valid SHA-1-shaped format | PASS |
| T09 | 64-character hex value | Valid SHA-256-shaped format | PASS |
| T10 | `CVE-2099-10001` | Valid CVE-shaped syntax; no existence claim | PASS |
| T11 | `CVE-26-123` | Rejected CVE syntax | PASS |
| T12 | Normalize synthetic network observation | Canonical record and demo label | PASS |
| T13 | Calculate risk and classification boundaries | 0–100; 20 informational, 81 critical | PASS |
| T14 | Confidence extremes | A/complete evidence = 100; D/none = 14 | PASS |
| T15 | Source reliability A/C/D | Reliability scores order correctly | PASS |
| T16 | Enrich `login-check.invalid` | Known; risk 78; confidence 85 | PASS |
| T17 | Search `unknown-demo.invalid` | Valid syntax, no local match, no external lookup | PASS |
| T18 | Two distinct indicators / shared campaign ID | One cluster, attribution not established | PASS |
| T19 | Same indicator twice within five minutes | One correlated alert, count 2 | PASS |
| T20 | High-risk/high-confidence synthetic threat | Analyst-review alert generated | PASS |
| T21 | Low-risk/low-confidence single observation | No alert by configured rules | PASS |
| T22 | Alert status `resolved` / `EXECUTE` | Normalize valid status; reject invalid | PASS |
| T23 | Phishing behavior description | Map to Initial Access / T1566 | PASS |
| T24 | Bare reserved IP observation | No ATT&CK behavior mapping | PASS |
| T25 | Exposed critical asset vs isolated test asset | Contextual priority ranks exposed case higher | PASS |
| T26 | Read vulnerability CSV | 24 records; all marked synthetic | PASS |
| T27 | Dashboard stats | 2,000 threats and 24 vulnerability scenarios | PASS |
| T28 | Severity filter HIGH | All returned rows are HIGH | PASS |
| T29 | Category filter PHISHING | All returned rows are PHISHING | PASS |
| T30 | Sort by highest risk | Scores are non-increasing | PASS |
| T31 | Awareness module retrieval | 15 modules with safe-practice content | PASS |
| T32 | Quiz all correct answers | Score 100 and Strong Awareness | PASS |
| T33 | Low phishing category score | Focus recommendation points to phishing module | PASS |
| T34 | Enrich valid indicator against empty list | Valid syntax, not locally known | PASS |
| T35 | Insert/read SQLite threat | Record persists in temporary database | PASS |
| T36 | `/api/health` | OK and network lookups explicitly false | PASS |
| T37 | Invalid indicator lookup | Invalid response; no local match | PASS |
| T38 | Demo IP `198.51.100.25` | Related campaign context and internal sample sighting | PASS |
| T39 | min risk greater than max risk | HTTP 422 | PASS |
| T40 | Add analyst note to demo threat | HTTP 201 and threat ID returned | PASS |
| T41 | Update alert status | HTTP 200; status can be restored | PASS |
| T42 | Request quiz | 30 questions; answer key withheld | PASS |
| T43 | Submit quiz | Score returned and summary persists | PASS |
| T44 | Vulnerability API | 24 rows and synthetic flag | PASS |
| T45 | ATT&CK technique click-through endpoint | T1566 records returned; no attribution | PASS |
| T46 | Create a valid API threat | HTTP 201 and row persists | PASS |
| T47 | Create invalid IP observation | HTTP 422 | PASS |
| T48 | Same campaign but same single IOC repeated | No multi-indicator cluster | PASS |
| T49 | Organizational risk weighting with two alerts, one affected CVE, and 80% demo completion | Weighted 40/40/20 score = 24; awareness gap = 20 | PASS |
| T50 | High-priority fictional CVE with demo exploitation evidence | Vulnerability review alert generated | PASS |
| T51 | API date range for 2026-09-18; reversed range | Matching timestamps returned; reversed range returns 422 | PASS |
| T52 | Fresh database seed | High-priority fictional vulnerability review alerts are created | PASS |
| T53 | CVSS 8.1 / 9.4 / 5.9 | HIGH / CRITICAL / MEDIUM severity bands | PASS |
| T54 | IPv6 literal inside HTTPS URL | Valid syntax; normalized with IPv6 brackets | PASS |

## Run tests

```bash
python -m pytest -q
```

The project includes API, scoring, data, enrichment, filtering, correlation, awareness, and persistence checks. It does not yet include load testing, browser automation, authorization-role tests, or production security assurance. Those are future work.
