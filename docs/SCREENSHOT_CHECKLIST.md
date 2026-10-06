# Portfolio screenshot checklist

Capture screenshots after running the local site. Use browser zoom around 90–100%, keep text readable, and ensure every view shows the synthetic/demo notice. Never include real organizational telemetry or credentials.

| # | Suggested filename | Capture |
|---:|---|---|
| 01 | `01-project-folder-structure.png` | Root folders and key files in an editor/file explorer |
| 02 | `02-system-architecture.png` | Architecture diagram from `docs/ARCHITECTURE.md` or README |
| 03 | `03-synthetic-threat-dataset.png` | First rows of CSV showing reserved/example values + demo label |
| 04 | `04-command-center-overview.png` | Hero, KPIs, local synthetic status |
| 05 | `05-total-threat-records.png` | KPI row with 2,000 records |
| 06 | `06-severity-constellation.png` | Severity distribution visual |
| 07 | `07-threat-category-chart.png` | Threat category chart |
| 08 | `08-ioc-type-distribution.png` | Indicator type chart |
| 09 | `09-threat-timeline.png` | Activity chart and date axis |
| 10 | `10-risk-score-distribution.png` | Risk bands chart |
| 11 | `11-confidence-score-distribution.png` | Confidence bands chart |
| 12 | `12-ioc-search-known-demo.png` | Search `login-check.invalid`; local-only banner visible |
| 13 | `13-ioc-result-and-enrichment.png` | Risk 78, confidence 85, HIGH/MONITORING |
| 14 | `14-threat-investigation-drawer.png` | Click `THR-2026-001` from table |
| 15 | `15-risk-vs-confidence.png` | Both score cards and interpretive notice |
| 16 | `16-related-synthetic-indicators.png` | Shared demo campaign indicators |
| 17 | `17-attack-mapping.png` | ATT&CK lens with T1566 behavior mapping |
| 18 | `18-cve-vulnerability-lab.png` | Fictional 2099 scenario notice and contextual priority cards |
| 19 | `19-alert-queue.png` | Alert workflow status choices |
| 20 | `20-alert-investigation-status.png` | Update a demo alert status; no incident claim |
| 21 | `21-analyst-notes.png` | Sample note in threat detail drawer |
| 22 | `22-awareness-studio.png` | Awareness module grid |
| 23 | `23-phishing-awareness-module.png` | Expanded phishing module |
| 24 | `24-password-mfa-module.png` | Password/MFA learning content |
| 25 | `25-ransomware-awareness.png` | High-level defensive module |
| 26 | `26-knowledge-check-quiz.png` | Quiz questions and progress indicator |
| 27 | `27-quiz-score-result.png` | Score label and educational notice |
| 28 | `28-quiz-category-scores.png` | Category scores and recommendations |
| 29 | `29-learning-recommendations.png` | Personalized focus suggestions |
| 30 | `30-executive-brief.png` | Plain-language management view |
| 31 | `31-executive-risk-components.png` | Illustrative score and component labels |
| 32 | `32-automated-tests.png` | Terminal output `54 passed` |
| 33 | `33-api-health-response.png` | `GET /api/health` JSON response |
| 34 | `34-sqlite-database-schema.png` | SQLite viewer or schema output; no real user data |
| 35 | `35-github-commit-history.png` | Genuine commit history after your incremental work |
| 36 | `36-github-repository.png` | Repository landing page with topics/README |
| 37 | `37-readme-preview.png` | README top/feature/ethical disclaimer sections |

Keep images in `screenshots/`; do not invent screenshots or imply an integration is functional if it is only future work.
