from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from .activity import load_recent_activity
from .config import DATA_DIR, DEFAULT_ARTIFACT_PATH
from .training import default_plot_dir, default_report_path, default_summary_path


def load_training_report(report_path: Path | None = None) -> Dict:
    target = Path(report_path or default_report_path(DEFAULT_ARTIFACT_PATH))
    if not target.exists():
        raise FileNotFoundError(f"Training report not found at {target}")
    with target.open("r", encoding="utf-8") as handle:
        report = json.load(handle)
    return report


def build_training_report_view(report: Dict) -> Dict:
    model_rows: List[Dict] = []
    plot_files = report.get("plot_files", {})
    for model_name, metrics in report.get("metrics", {}).items():
        model_rows.append(
            {
                "name": model_name,
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "roc_auc": metrics["roc_auc"],
                "is_selected": model_name == report.get("model_name"),
                "confusion_matrix_asset": _asset_relative_path(plot_files.get(model_name, {}).get("confusion_matrix")),
                "roc_curve_asset": _asset_relative_path(plot_files.get(model_name, {}).get("roc_curve")),
            }
        )
    return {
        "selected_model": report.get("model_name"),
        "dataset_mode": report.get("dataset_mode"),
        "threshold": report.get("threshold"),
        "training_rows": report.get("training_rows"),
        "test_rows": report.get("test_rows"),
        "feature_count": report.get("feature_count"),
        "data_paths": report.get("data_paths", []),
        "model_rows": model_rows,
    }


def build_dashboard_view() -> Dict:
    artifact_exists = DEFAULT_ARTIFACT_PATH.exists()
    report_path = default_report_path(DEFAULT_ARTIFACT_PATH)
    summary_path = default_summary_path(DEFAULT_ARTIFACT_PATH)
    plot_dir = default_plot_dir(DEFAULT_ARTIFACT_PATH)

    selected_model = "Unavailable"
    dataset_mode = "Unavailable"
    training_rows = None
    test_rows = None
    feature_count = None
    report_available = report_path.exists()
    summary_available = summary_path.exists()
    plot_count = 0
    training_error = None

    if plot_dir.exists():
        plot_count = len(list(plot_dir.glob("*.png")))

    if report_available:
        try:
            report = load_training_report(report_path)
            selected_model = report.get("model_name") or selected_model
            dataset_mode = report.get("dataset_mode") or dataset_mode
            training_rows = report.get("training_rows")
            test_rows = report.get("test_rows")
            feature_count = report.get("feature_count")
        except Exception as exc:
            training_error = f"Could not parse training report: {exc}"

    status_items = [
        {
            "label": "Model Artifact",
            "value": "Ready" if artifact_exists else "Missing",
            "tone": "good" if artifact_exists else "bad",
        },
        {
            "label": "Training Report",
            "value": "Ready" if report_available else "Missing",
            "tone": "good" if report_available else "bad",
        },
        {
            "label": "Summary Report",
            "value": "Ready" if summary_available else "Missing",
            "tone": "good" if summary_available else "bad",
        },
        {
            "label": "Evaluation Plots",
            "value": str(plot_count),
            "tone": "good" if plot_count else "warn",
        },
    ]

    quick_links = [
        {"label": "Analyzer", "href": "/"},
        {"label": "Training Report", "href": "/training-report"},
        {"label": "Analysis Detail", "href": "/analysis-detail?url=https://example.com/login"},
        {"label": "Batch Analysis", "href": "/batch-analysis"},
        {"label": "Settings", "href": "/settings"},
    ]

    return {
        "selected_model": selected_model,
        "dataset_mode": dataset_mode,
        "training_rows": training_rows,
        "test_rows": test_rows,
        "feature_count": feature_count,
        "status_items": status_items,
        "quick_links": quick_links,
        "training_error": training_error,
        "recent_activity": load_recent_activity(),
    }


def resolve_data_asset(asset_path: str) -> Path:
    candidate = (DATA_DIR / asset_path).resolve()
    data_root = DATA_DIR.resolve()
    if data_root not in candidate.parents and candidate != data_root:
        raise ValueError("Asset path is outside the data directory.")
    if not candidate.exists():
        raise FileNotFoundError(candidate)
    return candidate


def _asset_relative_path(raw_path: str | None) -> str | None:
    if not raw_path:
        return None
    path = Path(raw_path)
    try:
        return str(path.relative_to(DATA_DIR)).replace("\\", "/")
    except ValueError:
        return str(path.name)
