from __future__ import annotations

import json
from typing import Dict

from .inference import AnalysisResult


def build_analysis_report_payload(result: AnalysisResult) -> Dict:
    return {
        "normalized_url": result.normalized_url,
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "probability": result.probability,
        "suspicious_signals": result.suspicious_signals,
        "reassuring_signals": result.reassuring_signals,
        "warnings": result.warnings,
        "feature_sections": result.feature_sections,
        "features": result.features,
    }


def build_analysis_markdown(result: AnalysisResult) -> str:
    lines = [
        "# URL Analysis Report",
        "",
        f"- URL: `{result.normalized_url}`",
        f"- Verdict: `{result.verdict}`",
        f"- Risk score: `{result.risk_score}/100`",
        f"- Model probability: `{result.probability * 100:.1f}%`",
        "",
        "## Suspicious Signals",
        "",
    ]
    if result.suspicious_signals:
        for item in result.suspicious_signals:
            lines.append(f"- {item}")
    else:
        lines.append("- No strong phishing indicators were triggered by the current checks.")

    lines.extend(["", "## Reassuring Signals", ""])
    if result.reassuring_signals:
        for item in result.reassuring_signals:
            lines.append(f"- {item}")
    else:
        lines.append("- No strong reassuring signals were identified.")

    lines.extend(["", "## Warnings", ""])
    if result.warnings:
        for item in result.warnings:
            lines.append(f"- {item}")
    else:
        lines.append("- No runtime warnings were raised.")

    for section in result.feature_sections:
        lines.extend(["", f"## {section['title']}", ""])
        for row in section["rows"]:
            lines.append(f"- {row['label']}: {row['value']}")

    return "\n".join(lines) + "\n"


def build_analysis_json(result: AnalysisResult) -> str:
    return json.dumps(build_analysis_report_payload(result), indent=2)
