#!/usr/bin/env python3
"""Build the no-backend GitHub Pages version into /docs.

Run from the repository root:
    python scripts/build_github_pages.py
The generated site uses the bundled local dataset plus browser localStorage.
"""
from __future__ import annotations
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs"
ASSETS = SITE / "assets"
SITE_DATA = SITE / "data"


def copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    SITE_DATA.mkdir(parents=True, exist_ok=True)

    html = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    html = html.replace('<html lang="en">', '<html lang="en" data-static-mode="true" data-base="./">')
    html = html.replace('href="/css/styles.css"', 'href="./assets/styles.css"')
    html = html.replace('<script src="/js/app.js" defer></script>', '<script src="./assets/static-adapter.js" defer></script>\n  <script src="./assets/app.js" defer></script>')
    (SITE / "index.html").write_text(html, encoding="utf-8")

    copy_file(ROOT / "frontend" / "css" / "styles.css", ASSETS / "styles.css")
    copy_file(ROOT / "frontend" / "js" / "app.js", ASSETS / "app.js")
    copy_file(ROOT / "frontend" / "js" / "static-adapter.js", ASSETS / "static-adapter.js")

    files = {
        ROOT / "data" / "threat_intelligence_dataset.csv": SITE_DATA / "threat_intelligence_dataset.csv",
        ROOT / "data" / "vulnerabilities.csv": SITE_DATA / "vulnerabilities.csv",
        ROOT / "data" / "assets.json": SITE_DATA / "assets.json",
        ROOT / "data" / "internal_signals.csv": SITE_DATA / "internal_signals.csv",
        ROOT / "data" / "awareness_metrics.json": SITE_DATA / "awareness_metrics.json",
        ROOT / "awareness" / "modules.json": SITE_DATA / "modules.json",
        ROOT / "awareness" / "quiz_questions.json": SITE_DATA / "quiz_questions.json",
    }
    for source, destination in files.items():
        copy_file(source, destination)

    print(f"GitHub Pages site built at: {SITE}")
    print(f"Static data files copied: {len(files)}")
    print("Publish the repository's /docs folder using GitHub Pages settings.")
    print("All edits in the static site are browser-local; there is no API server.")


if __name__ == "__main__":
    main()
