"""Read bundled synthetic local context. The helpers are read-only and never access the network."""
from __future__ import annotations
import csv
import json
from pathlib import Path


def read_internal_signals(data_dir: str | Path) -> list[dict]:
    path = Path(data_dir) / "internal_signals.csv"
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def read_assets(data_dir: str | Path) -> list[dict]:
    path = Path(data_dir) / "assets.json"
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_awareness_metrics(data_dir: str | Path) -> dict:
    path = Path(data_dir) / "awareness_metrics.json"
    if not path.exists():
        return {"enrolled_learners": 0, "completed_learners": 0, "completion_rate": 0, "cohort_label": "NO COHORT DATA"}
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)
