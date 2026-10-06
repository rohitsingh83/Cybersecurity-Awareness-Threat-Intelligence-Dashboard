# Local run — 15 beginner-friendly steps

This project uses only bundled synthetic data by default. It does not require API keys, a feed, or a separate frontend server. Commands below assume a terminal in the project root.

## Step 1 — Create or enter the project folder

If you downloaded/extracted this repository, enter it:

```bash
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

If creating a new empty working folder first:

```bash
mkdir -p Cybersecurity-Awareness-Threat-Intelligence-Dashboard
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

Copy/extract the project files into this folder before continuing. Once published to GitHub, a clone can instead be created with:

```bash
git clone https://github.com/<YOUR-USERNAME>/Cybersecurity-Awareness-Threat-Intelligence-Dashboard.git
cd Cybersecurity-Awareness-Threat-Intelligence-Dashboard
```

## Step 2 — Create a Python virtual environment

macOS/Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

## Step 3 — Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Step 4 — Generate local demo data

```bash
python data/generate_threat_data.py
```

Expected output: 2,000 synthetic threat rows and 24 fictional vulnerability scenarios. This generator uses a deterministic seed and performs no network I/O.

## Step 5 — Initialize the database

The first server start initializes/seeds SQLite automatically. To initialize it explicitly before starting the server:

```bash
python -c "from pathlib import Path; from backend.app import app; d=app.state.database; d.initialize(); print(d.seed(Path('data'), Path('awareness')))"
```

The local database path is `data/threat_dashboard.db`; it is ignored by Git.

## Step 6 — Start the backend

```bash
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

Keep this terminal open. The API and website are served by the same FastAPI app.

## Step 7 — Start the frontend

No second command is required. FastAPI serves `frontend/index.html`, CSS, and JavaScript from the same origin. There is no npm build step or external CDN dependency.

## Step 8 — Open the dashboard

Open this address in your browser:

```text
http://127.0.0.1:8000
```

The API reference is at `http://127.0.0.1:8000/api/docs`.

## Step 9 — Search a synthetic IOC

In the site, select **IOC lookup** and search `login-check.invalid`. This is a database lookup only. Alternatively, call the local API (the request is to localhost; the indicator itself is not visited):

```bash
curl "http://127.0.0.1:8000/api/indicators/search?q=login-check.invalid"
```

Expected: known in demo `YES`, risk `78`, severity `HIGH`, confidence `85`, status `MONITORING`.

## Step 10 — Open threat details

Select the `THR-2026-001` row in the threat stream or command-center table. The investigation drawer shows scores, notes, source, timeline, related indicators, and recommended review actions. It does not label the record an incident.

Direct API read:

```bash
curl "http://127.0.0.1:8000/api/threats/THR-2026-001"
```

## Step 11 — Review ATT&CK context

Choose **ATT&CK lens**, then select technique `T1566` (Phishing). The technique page lists synthetic records whose descriptions contain matching behavior context. A standalone indicator is not assigned a technique.

## Step 12 — Review vulnerabilities

Choose **Vulnerability lab**. Inspect fictional `CVE-2099-…` scenarios. Compare CVSS, asset criticality, exposure, demo exploitation flag, patch availability, and contextual priority.

## Step 13 — Open Awareness Studio

Choose **Awareness studio**. Select any module card—Phishing, Passwords/MFA, Ransomware, Privacy, or others—to expand the lesson, warning signs, defensive practices, and quick task.

## Step 14 — Complete the quiz

Select **Knowledge check**, answer the 30 questions, and submit. Unanswered questions count as incorrect. The result shows category scores, focus areas, and module recommendations. The quiz does not require a real name.

## Step 15 — Review score and executive view

The quiz result is stored locally. Choose **Executive brief** to see the optional score trend and fictional completion-cohort metric. Both are explicitly demo-only and are not employee performance judgments or real organization measurements.

## Run tests

In a second terminal with the virtual environment activated:

```bash
python -m pytest -q
```

Expected build result: **54 passed**. For optional write-key protection, follow the instructions in `README.md` and the **System & API** panel.
