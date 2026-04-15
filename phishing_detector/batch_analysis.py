from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Dict, List

from .inference import analyze_url

URL_COLUMN_CANDIDATES = ("url", "URL", "Url", "link", "Link", "domain", "Domain", "website", "Website", "uri", "URI")


@dataclass
class BatchAnalysisResult:
    filename: str
    rows: List[Dict]


def analyze_batch_csv(file_bytes: bytes, filename: str = "batch_urls.csv") -> BatchAnalysisResult:
    if not file_bytes:
        raise ValueError("Upload a CSV file with at least one URL column.")
    text = file_bytes.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("The uploaded CSV does not contain a header row.")

    url_column = _resolve_url_column(reader.fieldnames)
    rows: List[Dict] = []
    for index, row in enumerate(reader, start=1):
        raw_url = (row.get(url_column) or "").strip()
        if not raw_url:
            rows.append(
                {
                    "row_number": index,
                    "input_url": "",
                    "normalized_url": "",
                    "verdict": "Error",
                    "risk_score": "",
                    "probability": "",
                    "warnings": "",
                    "top_signal": "Missing URL value.",
                }
            )
            continue
        try:
            result = analyze_url(raw_url)
            rows.append(
                {
                    "row_number": index,
                    "input_url": raw_url,
                    "normalized_url": result.normalized_url,
                    "verdict": result.verdict,
                    "risk_score": result.risk_score,
                    "probability": f"{result.probability:.4f}",
                    "warnings": " | ".join(result.warnings),
                    "top_signal": result.suspicious_signals[0] if result.suspicious_signals else "",
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "row_number": index,
                    "input_url": raw_url,
                    "normalized_url": "",
                    "verdict": "Error",
                    "risk_score": "",
                    "probability": "",
                    "warnings": "",
                    "top_signal": str(exc),
                }
            )
    if not rows:
        raise ValueError("The uploaded CSV does not contain any data rows.")
    return BatchAnalysisResult(filename=filename, rows=rows)


def batch_result_to_csv(batch_result: BatchAnalysisResult) -> str:
    buffer = io.StringIO()
    fieldnames = ["row_number", "input_url", "normalized_url", "verdict", "risk_score", "probability", "warnings", "top_signal"]
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(batch_result.rows)
    return buffer.getvalue()


def build_batch_summary(batch_result: BatchAnalysisResult) -> Dict:
    phishing_count = sum(1 for row in batch_result.rows if row["verdict"] == "Phishing")
    legitimate_count = sum(1 for row in batch_result.rows if row["verdict"] == "Legitimate")
    error_count = sum(1 for row in batch_result.rows if row["verdict"] == "Error")
    return {
        "filename": batch_result.filename,
        "total_rows": len(batch_result.rows),
        "phishing_count": phishing_count,
        "legitimate_count": legitimate_count,
        "error_count": error_count,
        "rows": batch_result.rows,
    }


def _resolve_url_column(fieldnames: List[str]) -> str:
    normalized = {name.strip().lower(): name for name in fieldnames}
    for candidate in URL_COLUMN_CANDIDATES:
        match = normalized.get(candidate.lower())
        if match is not None:
            return match
    raise ValueError(
        "Could not find a URL column in the uploaded CSV. Supported columns include: "
        + ", ".join(URL_COLUMN_CANDIDATES)
    )
