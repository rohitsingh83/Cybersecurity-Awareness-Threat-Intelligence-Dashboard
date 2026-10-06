# Publish Signal Atlas independently with GitHub Pages

This repository now has two ways to run the project:

1. **FastAPI + SQLite demo:** the full local backend, API, and persistent database.
2. **GitHub Pages static site:** a browser-only build with no Python server, database server, Node build, or third-party API. It reads the bundled CSV/JSON dataset and stores notes, review statuses, and quiz results in that browser's `localStorage`.

The static version does not expose a backend API. Its JavaScript adapter implements the dashboard's data operations in the browser. It makes same-site requests only for the repository's static CSV/JSON files; it never contacts indicator values. Browser-local changes do not synchronize across devices or users.

## Build or refresh the Pages folder

From the repository root:

```bash
python scripts/build_github_pages.py
```

This generates/refreshes:

```text
docs/index.html
docs/assets/styles.css
docs/assets/app.js
docs/assets/static-adapter.js
docs/data/threat_intelligence_dataset.csv
docs/data/vulnerabilities.csv
docs/data/assets.json
docs/data/internal_signals.csv
docs/data/awareness_metrics.json
docs/data/modules.json
docs/data/quiz_questions.json
```

Commit these generated files to GitHub:

```bash
git add docs/index.html docs/assets docs/data docs/GITHUB_PAGES_DEPLOYMENT.md
git commit -m "Add standalone GitHub Pages dashboard"
git push
```

## Enable GitHub Pages

1. Push the repository to GitHub.
2. Open repository **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**.
4. Select branch **`main`** and folder **`/docs`**.
5. Save. Wait for GitHub's Pages deployment to finish.
6. Open the URL shown by GitHub. A project site normally looks like `https://<username>.github.io/<repository-name>/`; a special `<username>.github.io` repository may publish at the host root.

The site uses relative paths, so it supports both root and repository-subpath hosting. The generated landing page is `docs/index.html`.

## Test a local Pages build

`file://` browser restrictions can prevent loading bundled CSV/JSON files. Use a simple local static server instead—this is only for previewing the static site and does not run the FastAPI backend:

```bash
python scripts/build_github_pages.py
python -m http.server 8080 --directory docs
```

Open `http://127.0.0.1:8080/`. Stop it with Ctrl+C. No suspicious indicator is contacted; the server only serves files from `docs/`.

## What works in the static site

- Dashboard charts and KPIs from the included 2,000-row synthetic CSV.
- Threat filtering, date ranges, sorting, pagination, and CSV export.
- Exact IOC validation and dataset search without DNS/HTTP/reputation queries.
- Threat details, alert status changes, investigation notes, and local threat additions.
- Vulnerability prioritization, ATT&CK exploration, awareness modules, quiz scoring, recommendations, and executive summary.
- The same visual design and animations as the FastAPI version.

## Static-site storage and limitations

- Notes, status changes, quiz results, and added records are kept in the current browser profile's `localStorage`.
- Clearing browser storage or switching device/browser resets those local changes. The System & API page includes a reset control.
- There is no server-side login, role-based access control, shared database, API key, API endpoint, or multi-user collaboration in GitHub Pages mode. Do not enter real incident notes, personal information, credentials, or private indicators.
- The Pages copy of the data is static. To update baseline data, regenerate data in the project root, rerun the build script, commit, and push.
- Keep every record synthetic or otherwise approved for public disclosure. GitHub Pages content is public.

## Deployment safety reminder

The public static site is designed for defensive learning and synthetic data only. It does not visit URLs, resolve domains, contact IPs, retrieve files by hash, execute files, exploit vulnerabilities, or scan systems. Never publish confidential threat intelligence or analyst notes to a public repository.
