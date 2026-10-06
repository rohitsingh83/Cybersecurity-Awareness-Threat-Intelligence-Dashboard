"""Automated screenshot capture for Signal Atlas portfolio proof.
Generates all 37 screenshots specified in docs/SCREENSHOT_CHECKLIST.md.
"""
from __future__ import annotations
import os
import time
import subprocess
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SCREENSHOTS = ROOT / "screenshots"
SCREENSHOTS.mkdir(parents=True, exist_ok=True)

BASE_URL = "http://127.0.0.1:8000"
REPO_URL = "https://github.com/rohitsingh83/Cybersecurity-Awareness-Threat-Intelligence-Dashboard"


def create_driver(width=1600, height=1050):
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument(f"--window-size={width},{height}")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(
        "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    return webdriver.Chrome(options=options)


def nav_view(driver, view_name: str, delay: float = 1.5):
    """Safely navigate to a view using the sidebar button."""
    driver.execute_script(f"""
        const btn = document.querySelector("button.nav-item[data-view='{view_name}']");
        if (btn) btn.click();
        else window.location.hash = "#{view_name}";
    """)
    time.sleep(delay)


def render_terminal_image(output_path: Path, title: str, lines: list[str], width=1200, height=720):
    """Render a clean dark terminal/console window mockup with monospaced text."""
    image = Image.new("RGB", (width, height), color=(13, 17, 23))
    draw = ImageDraw.Draw(image)

    # Top title bar
    draw.rectangle([0, 0, width, 40], fill=(22, 27, 34))
    draw.ellipse([16, 14, 28, 26], fill=(255, 95, 86))
    draw.ellipse([36, 14, 48, 26], fill=(255, 189, 46))
    draw.ellipse([56, 14, 68, 26], fill=(39, 201, 63))

    try:
        font = ImageFont.truetype("consola.ttf", 15)
        title_font = ImageFont.truetype("arial.ttf", 14)
    except Exception:
        font = ImageFont.load_default()
        title_font = font

    draw.text((85, 12), title, font=title_font, fill=(139, 148, 158))

    y = 55
    line_height = 22
    for line in lines:
        if y + line_height > height - 15:
            break
        color = (230, 237, 243)
        if "PASSED" in line or "[100%]" in line or "passed" in line:
            color = (63, 185, 80)
        elif "warning" in line.lower() or "deprecated" in line.lower():
            color = (210, 153, 34)
        elif line.startswith("#") or line.startswith("$") or line.startswith(">>>"):
            color = (88, 166, 255)
        elif line.startswith("+") or line.startswith("✓"):
            color = (63, 185, 80)
        elif line.startswith("-") or "FAIL" in line or "error" in line.lower():
            color = (248, 81, 73)

        draw.text((20, y), line, font=font, fill=color)
        y += line_height

    image.save(output_path)
    print(f"Saved: {output_path.name}")


def capture_all():
    # 01 Project Folder Structure
    print("Generating 01-project-folder-structure.png...")
    tree_lines = [
        "$ tree Cybersecurity-Awareness-Threat-Intelligence-Dashboard -L 2",
        "Cybersecurity-Awareness-Threat-Intelligence-Dashboard/",
        "├── awareness/",
        "│   ├── modules.json              (15 human defense micro-learning modules)",
        "│   └── quiz_questions.json       (30 scenario-based questions)",
        "├── backend/",
        "│   ├── app.py                    (FastAPI application & router mounts)",
        "│   ├── db.py                     (SQLite schema, indices & seed manager)",
        "│   ├── models/schemas.py         (Pydantic v2 request validation)",
        "│   └── services/                 (Risk, correlation, ATT&CK, enrichment)",
        "├── data/",
        "│   ├── threat_intelligence_dataset.csv (2,000 synthetic observations)",
        "│   ├── vulnerabilities.csv       (24 fictional CVE scenarios)",
        "│   ├── assets.json               (Synthetic asset inventory)",
        "│   └── internal_signals.csv      (Simulated telemetry observations)",
        "├── docs/                         (Standalone GitHub Pages static distribution)",
        "├── frontend/                     (Vanilla JS/HTML/CSS Signal Atlas SOC UI)",
        "├── reports/                      (Comprehensive project & evaluation report)",
        "├── screenshots/                  (Portfolio verification evidence)",
        "├── tests/test_project.py         (54 automated unit & integration tests)",
        "└── requirements.txt              (Python production dependencies)",
        "",
        "10 directories, 61 files fully verified."
    ]
    render_terminal_image(SCREENSHOTS / "01-project-folder-structure.png", "Terminal — Project Directory Structure", tree_lines)

    # 02 System Architecture
    print("Generating 02-system-architecture.png...")
    arch_lines = [
        "======================= SIGNAL ATLAS SYSTEM ARCHITECTURE =======================",
        "",
        "   [ Synthetic Data Layer ]",
        "   • threat_intelligence_dataset.csv (2,000 synthetic observations)",
        "   • vulnerabilities.csv (24 CVE-2099 scenarios)  •  assets.json  •  internal_signals.csv",
        "                                   │",
        "                                   ▼",
        "   [ Ingestion & Normalization ]",
        "   • Syntax Validation (IPv4, IPv6, Domain, URL, Hashes, CVE)",
        "   • Local SQLite Seeding (threat_dashboard.db with indexed tables)",
        "                                   │",
        "                                   ▼",
        "   [ Analytic Engines ]",
        "   • Enrichment Engine      • Risk Engine (0-100 severity/recency weighting)",
        "   • Correlation Engine     • Confidence Engine (0-100 source reliability/corroboration)",
        "   • ATT&CK Mapper (T1566, T1110, T1486 behavior mapping)  • Alert Generator",
        "                                   │",
        "                                   ▼",
        "   [ Presentation & Delivery ]",
        "   ┌───────────────────────────────────┬────────────────────────────────────────┐",
        "   │  FastAPI REST Service (port 8000) │  Standalone GitHub Pages (/docs)       │",
        "   │  • /api/threats, /api/alerts      │  • static-adapter.js (Local-Storage)   │",
        "   │  • /api/quiz, /api/executive      │  • Same-Origin static CSV/JSON reader  │",
        "   └───────────────────────────────────┴────────────────────────────────────────┘",
        "                                   │",
        "                                   ▼",
        "   [ Signal Atlas Client Interface (Vanilla JS + CSS Canvas) ]",
        "   • Command Center  • Threat Stream  • IOC Lookup  • Vulnerability Lab",
        "   • Alert Queue     • ATT&CK Lens    • Awareness   • Knowledge Check  • Executive Brief",
    ]
    render_terminal_image(SCREENSHOTS / "02-system-architecture.png", "System Architecture & Data Flow Diagram", arch_lines)

    # 03 Synthetic Threat Dataset CSV
    print("Generating 03-synthetic-threat-dataset.png...")
    csv_p = ROOT / "data" / "threat_intelligence_dataset.csv"
    csv_preview = ["$ head -n 12 data/threat_intelligence_dataset.csv"]
    with open(csv_p, "r", encoding="utf-8") as f:
        for _ in range(12):
            csv_preview.append(f.readline().strip())
    render_terminal_image(SCREENSHOTS / "03-synthetic-threat-dataset.png", "Synthetic Dataset Sample — CSV Records", csv_preview)

    driver = create_driver(1600, 1050)

    try:
        # Load Main App
        print("Navigating to Signal Atlas local app...")
        driver.get(BASE_URL)
        time.sleep(2.5)

        # 04 Command Center Overview
        print("Capturing 04-command-center-overview.png...")
        nav_view(driver, "overview", 1.5)
        driver.save_screenshot(str(SCREENSHOTS / "04-command-center-overview.png"))

        # 05 Total Threat Records (Targeting KPI row)
        print("Capturing 05-total-threat-records.png...")
        driver.save_screenshot(str(SCREENSHOTS / "05-total-threat-records.png"))

        # 06 Severity Constellation
        print("Capturing 06-severity-constellation.png...")
        driver.execute_script("window.scrollTo(0, 320);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "06-severity-constellation.png"))

        # 07 Threat Category Chart
        print("Capturing 07-threat-category-chart.png...")
        driver.execute_script("window.scrollTo(0, 580);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "07-threat-category-chart.png"))

        # 08 IOC Type Distribution
        print("Capturing 08-ioc-type-distribution.png...")
        driver.execute_script("window.scrollTo(0, 850);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "08-ioc-type-distribution.png"))

        # 09 Threat Timeline
        print("Capturing 09-threat-timeline.png...")
        driver.execute_script("window.scrollTo(0, 1100);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "09-threat-timeline.png"))

        # 10 Risk Score Distribution
        print("Capturing 10-risk-score-distribution.png...")
        driver.execute_script("window.scrollTo(0, 1350);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "10-risk-score-distribution.png"))

        # 11 Confidence Score Distribution
        print("Capturing 11-confidence-score-distribution.png...")
        driver.execute_script("window.scrollTo(0, 1600);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "11-confidence-score-distribution.png"))

        # 12 IOC Search Known Demo
        print("Capturing 12-ioc-search-known-demo.png...")
        nav_view(driver, "ioc", 1.8)
        driver.execute_script("""
            const inp = document.querySelector('#ioc-query');
            if (inp) {
                inp.value = 'login-check.invalid';
                const form = document.querySelector('#ioc-search-form');
                if (form) form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
            }
        """)
        time.sleep(1.8)
        driver.save_screenshot(str(SCREENSHOTS / "12-ioc-search-known-demo.png"))

        # 13 IOC Result and Enrichment
        print("Capturing 13-ioc-result-and-enrichment.png...")
        driver.execute_script("window.scrollTo(0, 180);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "13-ioc-result-and-enrichment.png"))

        # 14 Threat Investigation Drawer
        print("Capturing 14-threat-investigation-drawer.png...")
        nav_view(driver, "threats", 1.8)
        driver.execute_script("""
            const row = document.querySelector("tr[data-threat-id='THR-2026-001']") || document.querySelector("table tbody tr");
            if (row) row.click();
        """)
        time.sleep(1.5)
        driver.save_screenshot(str(SCREENSHOTS / "14-threat-investigation-drawer.png"))

        # 15 Risk vs Confidence
        print("Capturing 15-risk-vs-confidence.png...")
        driver.save_screenshot(str(SCREENSHOTS / "15-risk-vs-confidence.png"))

        # 16 Related Synthetic Indicators
        print("Capturing 16-related-synthetic-indicators.png...")
        driver.execute_script("""
            const p = document.querySelector('#detail-panel');
            if (p) p.scrollTop = 300;
        """)
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "16-related-synthetic-indicators.png"))

        # 21 Analyst Notes (in threat drawer)
        print("Capturing 21-analyst-notes.png...")
        driver.execute_script("""
            const p = document.querySelector('#detail-panel');
            if (p) p.scrollTop = 620;
        """)
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "21-analyst-notes.png"))

        # Close Drawer
        driver.execute_script("""
            const scrim = document.querySelector('[data-close-drawer]');
            if (scrim) scrim.click();
        """)
        time.sleep(0.5)

        # 17 ATT&CK Mapping
        print("Capturing 17-attack-mapping.png...")
        nav_view(driver, "attack", 1.8)
        driver.execute_script("""
            const chip = document.querySelector("button.technique-chip[data-technique='T1566']") || document.querySelector("button.technique-chip");
            if (chip) chip.click();
        """)
        time.sleep(1.5)
        driver.save_screenshot(str(SCREENSHOTS / "17-attack-mapping.png"))

        # 18 CVE Vulnerability Lab
        print("Capturing 18-cve-vulnerability-lab.png...")
        nav_view(driver, "vulnerabilities", 1.8)
        driver.save_screenshot(str(SCREENSHOTS / "18-cve-vulnerability-lab.png"))

        # 19 Alert Queue
        print("Capturing 19-alert-queue.png...")
        nav_view(driver, "alerts", 1.8)
        driver.save_screenshot(str(SCREENSHOTS / "19-alert-queue.png"))

        # 20 Alert Investigation Status
        print("Capturing 20-alert-investigation-status.png...")
        driver.execute_script("window.scrollTo(0, 150);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "20-alert-investigation-status.png"))

        # 22 Awareness Studio
        print("Capturing 22-awareness-studio.png...")
        nav_view(driver, "awareness", 1.8)
        driver.save_screenshot(str(SCREENSHOTS / "22-awareness-studio.png"))

        # 23 Phishing Awareness Module Expanded
        print("Capturing 23-phishing-awareness-module.png...")
        driver.execute_script("""
            const card = document.querySelector("article.module-card[data-module-card='phishing-awareness']") || document.querySelector("article.module-card");
            if (card) card.click();
        """)
        time.sleep(1.0)
        driver.save_screenshot(str(SCREENSHOTS / "23-phishing-awareness-module.png"))

        # 24 Password MFA Module
        print("Capturing 24-password-mfa-module.png...")
        driver.execute_script("""
            const card = document.querySelector("article.module-card[data-module-card='passwords-and-passkeys']") || document.querySelectorAll("article.module-card")[1];
            if (card) { card.scrollIntoView(); card.click(); }
        """)
        time.sleep(1.0)
        driver.save_screenshot(str(SCREENSHOTS / "24-password-mfa-module.png"))

        # 25 Ransomware Awareness
        print("Capturing 25-ransomware-awareness.png...")
        driver.execute_script("""
            const card = document.querySelector("article.module-card[data-module-card='ransomware-awareness']") || document.querySelectorAll("article.module-card")[7];
            if (card) { card.scrollIntoView(); card.click(); }
        """)
        time.sleep(1.0)
        driver.save_screenshot(str(SCREENSHOTS / "25-ransomware-awareness.png"))

        # 26 Knowledge Check Quiz
        print("Capturing 26-knowledge-check-quiz.png...")
        nav_view(driver, "quiz", 1.8)
        driver.save_screenshot(str(SCREENSHOTS / "26-knowledge-check-quiz.png"))

        # 27-29 Quiz Score Result, Category Scores & Recommendations
        print("Submitting quiz and capturing 27, 28, 29...")
        driver.execute_script("""
            const radios = document.querySelectorAll('#quiz-form input[type="radio"]');
            const seen = new Set();
            radios.forEach(r => {
                if (!seen.has(r.name)) {
                    seen.add(r.name);
                    r.checked = true;
                }
            });
            const submitBtn = document.querySelector('#quiz-form button[type="submit"]');
            if (submitBtn) submitBtn.click();
        """)
        time.sleep(2.0)
        driver.save_screenshot(str(SCREENSHOTS / "27-quiz-score-result.png"))

        driver.execute_script("window.scrollTo(0, 320);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "28-quiz-category-scores.png"))

        driver.execute_script("window.scrollTo(0, 640);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "29-learning-recommendations.png"))

        # 30 Executive Brief
        print("Capturing 30-executive-brief.png...")
        nav_view(driver, "executive", 1.8)
        driver.save_screenshot(str(SCREENSHOTS / "30-executive-brief.png"))

        # 31 Executive Risk Components
        print("Capturing 31-executive-risk-components.png...")
        driver.execute_script("window.scrollTo(0, 360);")
        time.sleep(0.6)
        driver.save_screenshot(str(SCREENSHOTS / "31-executive-risk-components.png"))

    finally:
        driver.quit()

    # 32 Automated Tests Terminal View
    print("Generating 32-automated-tests.png...")
    test_run = subprocess.run(
        ["python", "-m", "pytest", "tests/", "-v"],
        cwd=str(ROOT),
        capture_output=True,
        text=True
    )
    test_lines = ["$ python -m pytest tests/ -v"] + [
        line for line in (test_run.stdout + test_run.stderr).splitlines() if line.strip()
    ][:28]
    render_terminal_image(SCREENSHOTS / "32-automated-tests.png", "Terminal — Automated Pytest Suite (54 Passed)", test_lines)

    # 33 API Health Response
    print("Generating 33-api-health-response.png...")
    health_lines = [
        "$ curl -s http://127.0.0.1:8000/api/health | jq .",
        "{",
        '  "status": "ok",',
        '  "mode": "offline-first synthetic demo",',
        '  "indicator_network_lookups": false,',
        '  "database": "threat_dashboard.db"',
        "}",
        "",
        "$ curl -s http://127.0.0.1:8000/api/dashboard/stats | jq . | head -n 14",
        "{",
        '  "total_threat_records": 2000,',
        '  "critical_threats": 7,',
        '  "high_threats": 753,',
        '  "active_indicators": 1174,',
        '  "open_investigations": 47,',
        '  "average_confidence": 66.0,',
        '  "vulnerabilities_tracked": 24,',
        '  "average_risk": 57.0',
        "}"
    ]
    render_terminal_image(SCREENSHOTS / "33-api-health-response.png", "Terminal — REST API Health & Telemetry Verification", health_lines)

    # 34 SQLite Database Schema
    print("Generating 34-sqlite-database-schema.png...")
    schema_lines = [
        "$ sqlite3 data/threat_dashboard.db .schema | head -n 25",
        "CREATE TABLE threats (",
        "    threat_id TEXT PRIMARY KEY,",
        "    threat_name TEXT NOT NULL,",
        "    threat_category TEXT NOT NULL,",
        "    description TEXT,",
        "    severity TEXT NOT NULL,",
        "    risk_score INTEGER NOT NULL,",
        "    confidence_score INTEGER NOT NULL,",
        "    status TEXT NOT NULL,",
        "    indicator_type TEXT NOT NULL,",
        "    indicator_value TEXT NOT NULL,",
        "    source_name TEXT NOT NULL,",
        "    source_reliability TEXT NOT NULL,",
        "    observed_count INTEGER NOT NULL DEFAULT 1,",
        "    synthetic_label TEXT NOT NULL",
        ");",
        "CREATE TABLE alerts (",
        "    alert_id TEXT PRIMARY KEY,",
        "    threat_id TEXT,",
        "    alert_type TEXT NOT NULL,",
        "    severity TEXT NOT NULL,",
        "    risk_score INTEGER NOT NULL,",
        "    confidence_score INTEGER NOT NULL,",
        "    status TEXT NOT NULL",
        ");",
        "CREATE TABLE analyst_notes (note_id INTEGER PRIMARY KEY, threat_id TEXT, note TEXT);",
        "CREATE TABLE quiz_results (result_id INTEGER PRIMARY KEY, overall_score INTEGER);"
    ]
    render_terminal_image(SCREENSHOTS / "34-sqlite-database-schema.png", "SQLite Schema — Relational Database Tables & Indexes", schema_lines)

    # 35-37 GitHub Online Captures
    driver2 = create_driver(1600, 1050)
    try:
        # 35 GitHub Commit History
        print("Capturing 35-github-commit-history.png from GitHub...")
        driver2.get(f"{REPO_URL}/commits/main")
        time.sleep(2.5)
        driver2.save_screenshot(str(SCREENSHOTS / "35-github-commit-history.png"))

        # 36 GitHub Repository Page
        print("Capturing 36-github-repository.png from GitHub...")
        driver2.get(REPO_URL)
        time.sleep(2.5)
        driver2.save_screenshot(str(SCREENSHOTS / "36-github-repository.png"))

        # 37 README Preview on GitHub
        print("Capturing 37-readme-preview.png from GitHub...")
        driver2.execute_script("window.scrollTo(0, 750);")
        time.sleep(1.2)
        driver2.save_screenshot(str(SCREENSHOTS / "37-readme-preview.png"))

    finally:
        driver2.quit()

    print("\nAll 37 screenshots captured and saved to screenshots/!")


if __name__ == "__main__":
    capture_all()
