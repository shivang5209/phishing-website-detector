from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .config import DATA_DIR
from .inference import AnalysisResult

ACTIVITY_PATH = DATA_DIR / "recent_activity.json"
MAX_ACTIVITY_ITEMS = 25


def load_recent_activity(limit: int = 10) -> List[Dict]:
    items = _read_activity()
    return items[:limit]


def record_single_analysis(result: AnalysisResult) -> None:
    entry = {
        "type": "single_analysis",
        "timestamp": _now_iso(),
        "title": result.normalized_url,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "meta": {
            "top_signal": result.suspicious_signals[0] if result.suspicious_signals else "",
        },
    }
    _append_entry(entry)


def record_batch_run(filename: str, summary: Dict) -> None:
    entry = {
        "type": "batch_analysis",
        "timestamp": _now_iso(),
        "title": filename,
        "verdict": f"{summary['phishing_count']} phishing / {summary['legitimate_count']} legitimate",
        "risk_score": "",
        "meta": {
            "rows": summary["total_rows"],
            "errors": summary["error_count"],
        },
    }
    _append_entry(entry)


def _append_entry(entry: Dict) -> None:
    items = _read_activity()
    items.insert(0, entry)
    _write_activity(items[:MAX_ACTIVITY_ITEMS])


def _read_activity() -> List[Dict]:
    if not ACTIVITY_PATH.exists():
        return []
    try:
        with ACTIVITY_PATH.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def _write_activity(items: List[Dict]) -> None:
    ACTIVITY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ACTIVITY_PATH.open("w", encoding="utf-8") as handle:
        json.dump(items, handle, indent=2)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
