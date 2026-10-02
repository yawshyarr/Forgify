"""Identity-card evaluation records and metrics.

This module intentionally does not tune detector thresholds.  It records one
fixed operating point and preserves the evidence needed to inspect errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable


AUTHENTIC_CASES = (
    "original photograph", "JPEG-resaved original", "resized original",
    "cropped original", "slightly rotated original", "different lighting",
    "compressed image", "scanned/reprinted ID",
)
MANIPULATED_CASES = (
    "changed name", "changed student ID", "changed registration number",
    "replaced photograph", "changed date", "replaced QR", "replaced barcode",
    "copy-move", "whiteout/cover-up", "multiple simultaneous changes",
)


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    category: str
    ground_truth: bool
    evidence_path: str
    reference_path: str | None = None


def _report_record(case: EvaluationCase, report: dict[str, Any], threshold: int) -> dict[str, Any]:
    score = int(report.get("verdict", {}).get("riskScore", 0))
    predicted = score >= threshold
    layers = report.get("layers", [])
    family_scores = {
        item.get("family", "unknown"): item.get("score", 0)
        for item in report.get("fusion", {}).get("familyEvidence", [])
    }
    return {
        "caseId": case.case_id, "category": case.category, "groundTruth": case.ground_truth,
        "detectorScores": {layer.get("layer", "unknown"): layer.get("score", 0) for layer in layers},
        "familyScores": family_scores, "finalScore": score,
        "suspiciousRegions": report.get("unifiedRegions", report.get("regions", [])),
        "predictedManipulated": predicted,
        "error": "false-positive" if predicted and not case.ground_truth else "false-negative" if not predicted and case.ground_truth else None,
        "referenceAligned": (report.get("referenceComparison") or {}).get("aligned") if case.reference_path else None,
    }


def evaluate_cases(cases: Iterable[EvaluationCase], analyze: Callable[[EvaluationCase], dict[str, Any]], threshold: int = 50) -> dict[str, Any]:
    """Run cases through the real analyzer and calculate an auditable report."""
    records = [_report_record(case, analyze(case), threshold) for case in cases]
    tp = sum(r["groundTruth"] and r["predictedManipulated"] for r in records)
    tn = sum(not r["groundTruth"] and not r["predictedManipulated"] for r in records)
    fp = sum(not r["groundTruth"] and r["predictedManipulated"] for r in records)
    fn = sum(r["groundTruth"] and not r["predictedManipulated"] for r in records)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "operatingPoint": {"riskThreshold": threshold, "note": "fixed before evaluation; no threshold optimization"},
        "cases": records, "counts": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "metrics": {"precision": round(precision, 4), "recall": round(recall, 4),
                    "F1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
                    "falsePositiveRate": round(fp / (fp + tn), 4) if fp + tn else 0.0,
                    "falseNegativeRate": round(fn / (fn + tp), 4) if fn + tp else 0.0},
    }


def pair_regression(original_report: dict[str, Any], manipulated_report: dict[str, Any]) -> dict[str, Any]:
    """Assert only ordering/evidence properties, never filenames or score values."""
    original_score = original_report.get("verdict", {}).get("riskScore", 0)
    manipulated_score = manipulated_report.get("verdict", {}).get("riskScore", 0)
    original_reference = original_report.get("referenceComparison") or {}
    manipulated_reference = manipulated_report.get("referenceComparison") or {}
    return {
        "manipulatedStronger": manipulated_score > original_score,
        "scoreDelta": manipulated_score - original_score,
        "originalAligned": bool(original_reference.get("aligned")),
        "manipulatedAligned": bool(manipulated_reference.get("aligned")),
        "manipulatedEvidence": len(manipulated_report.get("unifiedRegions", [])),
        "hasIndependentEvidence": len([x for x in manipulated_report.get("fusion", {}).get("familyEvidence", []) if x.get("score", 0) > 0]) >= 2,
    }


__all__ = ["AUTHENTIC_CASES", "MANIPULATED_CASES", "EvaluationCase", "evaluate_cases", "pair_regression"]
