"""Pilot evaluation of the unchanged Forgify worker on identity-card cases."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageDraw
from fastapi.testclient import TestClient

from app.main import app


THRESHOLD = 45  # existing verdict boundary: suspicious and above
VERSION = "forgify-identity-evaluation-v1"


def _diagnostic_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Extract auditable evidence fields without changing worker behavior."""
    comparison = report.get("referenceComparison") or {}
    changed = comparison.get("changedRegions") or []
    stable = [item for item in changed if item.get("stable") is True or item.get("stableAcrossQualities") is True]
    field_differences = comparison.get("fieldDifferences") or []
    layers = {item.get("layer"): item for item in report.get("layers", [])}
    families = {item.get("family"): item for item in (report.get("fusion") or {}).get("familyEvidence", [])}
    ml = report.get("mlClassification") or layers.get("ml-classifier", {}).get("mlClassification") or {}
    return {
        "agreement": (report.get("fusion") or {}).get("agreement"),
        "referenceComparisonScore": comparison.get("structuralDifference"),
        "referenceAlignmentConfidence": comparison.get("alignmentConfidence"),
        "changedRegionCount": len(changed),
        "stableChangedRegionCount": len(stable),
        "fieldMismatchCount": len(field_differences),
        "pixelElaScore": layers.get("pixel", {}).get("score"),
        "semanticFamilyScore": families.get("semantic", {}).get("score"),
        "structuralReferenceFamilyScore": families.get("structural/reference", {}).get("score"),
        "encodedDataFamilyScore": families.get("encoded-data", {}).get("score"),
        "mlStatus": ml.get("status") or ml.get("calibrationStatus") or ml.get("summary"),
        "topFindings": [
            {"code": item.get("code"), "severity": item.get("severity"), "title": item.get("title")}
            for item in sorted(report.get("findings", []), key=lambda x: float(x.get("confidence", 0)), reverse=True)[:5]
        ],
        "topSuspiciousRegions": [
            {"regionType": item.get("regionType"), "score": item.get("score"), "confidence": item.get("confidence")}
            for item in sorted(report.get("unifiedRegions", report.get("regions", [])), key=lambda x: float(x.get("confidence", x.get("score", 0))), reverse=True)[:5]
        ],
        "directFieldMismatch": bool(field_differences) or any(
            item.get("type") in {"OCR_FIELD_MISMATCH", "REF-FIELD"} for item in report.get("identityFindings", [])
        ),
    }


def _failure_cause(case: dict[str, Any], diagnostics: dict[str, Any], reference: bool) -> str | None:
    """Conservative, evidence-backed labels for misclassified pilot cases."""
    if case["predictedStatus"] == case["expectedStatus"]:
        return None
    if case["expectedStatus"] == "manipulated":
        if not reference:
            return "reference-free: no trusted value available for a definitive field comparison"
        if case.get("expectedField") and not diagnostics["directFieldMismatch"]:
            return "synthetic OCR/label compatibility: expected field was not extracted or compared"
        if diagnostics["referenceAlignmentConfidence"] is not None and diagnostics["referenceAlignmentConfidence"] < 0.8:
            return "alignment confidence too low for reliable reference evidence"
        return "reference evidence did not contribute enough to cross the existing verdict boundary"
    if reference and diagnostics["changedRegionCount"] and not diagnostics["stableChangedRegionCount"] and not diagnostics["directFieldMismatch"]:
        return "benign reference difference promoted without stable local corroboration"
    return "non-reference forensic signal crossed the existing verdict boundary"


def binary_metrics(labels: list[bool], predictions: list[bool]) -> dict[str, Any]:
    tp = sum(a and b for a, b in zip(labels, predictions)); tn = sum(not a and not b for a, b in zip(labels, predictions))
    fp = sum(not a and b for a, b in zip(labels, predictions)); fn = sum(a and not b for a, b in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"confusionMatrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn}, "precision": precision,
            "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "fnr": fn / (fn + tp) if fn + tp else 0.0}


def auc(labels: list[bool], scores: list[float]) -> float | None:
    positives = [s for y, s in zip(labels, scores) if y]; negatives = [s for y, s in zip(labels, scores) if not y]
    if not positives or not negatives: return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in positives for n in negatives)
    return wins / (len(positives) * len(negatives))


def mask_from_regions(regions: list[dict], size: tuple[int, int]) -> np.ndarray:
    mask = Image.new("1", size, 0); draw = ImageDraw.Draw(mask)
    w, h = size
    for region in regions or []:
        box = region.get("bbox", region)
        try:
            x, y = int(float(box["x"]) * w), int(float(box["y"]) * h)
            x2, y2 = int((float(box["x"]) + float(box["width"])) * w), int((float(box["y"]) + float(box["height"])) * h)
            if x2 > x and y2 > y: draw.rectangle((max(0, x), max(0, y), min(w, x2), min(h, y2)), fill=1)
        except (KeyError, TypeError, ValueError):
            continue
    return np.asarray(mask, dtype=bool)


def overlap_metrics(predicted: np.ndarray, truth: np.ndarray) -> tuple[float, float]:
    intersection = int(np.logical_and(predicted, truth).sum()); union = int(np.logical_or(predicted, truth).sum())
    pred_area, truth_area = int(predicted.sum()), int(truth.sum())
    iou = intersection / union if union else 1.0
    dice = 2 * intersection / (pred_area + truth_area) if pred_area + truth_area else 1.0
    return iou, dice


def _load_mask(root: Path, case: dict, size: tuple[int, int]) -> np.ndarray:
    path = case.get("mask_path")
    if not path: return np.zeros((size[1], size[0]), dtype=bool)
    return np.asarray(Image.open(root / path).convert("L")) > 127


def _field_match(report: dict, expected: str | None) -> dict[str, Any] | None:
    if not expected: return None
    for item in report.get("identityFindings", []):
        if item.get("fieldType") == expected and item.get("type") in {"OCR_FIELD_MISMATCH", "REF-FIELD"}:
            return {"fieldDetected": True, "matchingFinding": item.get("type"), "comparisonState": item.get("comparisonState")}
    for item in (report.get("referenceComparison") or {}).get("fieldDifferences", []):
        if item.get("field") == expected:
            return {"fieldDetected": True, "matchingFinding": "REF-FIELD", "comparisonState": "MISMATCH"}
    return {"fieldDetected": False, "matchingFinding": None}


def _localization_sources(report: dict, reference: bool) -> tuple[list[dict], dict[str, Any]]:
    """Select existing report evidence; never create detector regions."""
    unified = report.get("unifiedRegions", [])
    raw = report.get("regions", [])
    sources = ["unifiedRegions"] if unified else ["regions"]
    selected = list(unified or raw)
    comparison = report.get("referenceComparison") or {}
    reference_regions = comparison.get("changedRegions", [])
    identity_regions = []
    for finding in report.get("identityFindings", []):
        if finding.get("type") in {"OCR_FIELD_MISMATCH", "REF-FIELD"} and isinstance(finding.get("bbox"), dict):
            identity_regions.append({"bbox": finding["bbox"], "regionType": finding.get("fieldType", "unknown"), "score": finding.get("confidence", 0.0)})
    if reference:
        if reference_regions:
            # Prefer the direct reference-localization stream over the merged
            # executive region, which may intentionally be broad after overlap
            # aggregation. This measures the existing reference evidence itself.
            selected = list(reference_regions); sources = ["referenceComparison.changedRegions"]
        if identity_regions:
            selected.extend(identity_regions); sources.append("identityFindings.bbox")
    return selected, {"sources": sources, "unifiedCount": len(unified), "rawCount": len(raw), "referenceChangedCount": len(reference_regions), "identityMismatchCount": len(identity_regions)}


def _run_case(client: TestClient, root: Path, case: dict, reference: bool) -> dict[str, Any]:
    evidence = root / case["evidenceImage"]; ref = root / case["referenceImage"]
    files = {"file": (evidence.name, evidence.read_bytes(), "image/png")}
    if reference: files["reference"] = (ref.name, ref.read_bytes(), "image/png")
    try:
        response = client.post("/analyze", files=files)
        report = response.json()
        if response.status_code != 200 or not report.get("ok"):
            return {"caseId": case["caseId"], "error": f"HTTP {response.status_code}", "expectedStatus": case["expectedDocumentStatus"]}
        size = Image.open(evidence).size; truth = _load_mask(root, case, size)
        predicted_regions, localization = _localization_sources(report, reference)
        predicted = mask_from_regions(predicted_regions, size)
        iou, dice = overlap_metrics(predicted, truth)
        risk = int(report.get("verdict", {}).get("riskScore", 0)); verdict = report.get("verdict", {}).get("label", "unknown")
        expected = case["expectedDocumentStatus"] == "manipulated"
        field = _field_match(report, (case.get("fieldsChanged") or [None])[0])
        diagnostics = _diagnostic_summary(report)
        result = {"caseId": case["caseId"], "manipulation": case["manipulation"], "expectedStatus": case["expectedDocumentStatus"], "predictedStatus": "manipulated" if risk >= THRESHOLD else "genuine", "riskScore": risk, "confidence": report.get("verdict", {}).get("confidence"), "verdict": verdict, "threshold": THRESHOLD, "expectedField": (case.get("fieldsChanged") or [None])[0], "fieldResult": field, "groundTruthRegion": case.get("region"), "referenceComparison": report.get("referenceComparison"), "predictedRegions": predicted_regions, "localizationSources": localization, "groundTruthMask": case.get("mask_path"), "iou": iou, "dice": dice, "diagnostics": diagnostics, "error": None, "_label": expected}
        result["failureCause"] = _failure_cause(result, diagnostics, reference)
        return result
    except Exception as exc:
        return {"caseId": case["caseId"], "expectedStatus": case.get("expectedDocumentStatus"), "error": f"{type(exc).__name__}: {exc}"}


def evaluate(manifest_path: Path, output_dir: Path, mode: str) -> dict[str, Any]:
    # Existing manifests store paths relative to documents/dataset, while the
    # manifest itself lives in documents/dataset/pilot.
    root = manifest_path.parent.parent if manifest_path.parent.name == "pilot" else manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); cases = manifest.get("samples", [])
    with TestClient(app) as client: results = [_run_case(client, root, case, mode == "reference_assisted") for case in cases]
    valid = [r for r in results if "_label" in r]
    labels = [r["_label"] for r in valid]; predictions = [r["predictedStatus"] == "manipulated" for r in valid]; scores = [r["riskScore"] for r in valid]
    metrics = binary_metrics(labels, predictions); metrics["rocAuc"] = auc(labels, scores); metrics["rocAucCaseCount"] = len(valid) if metrics["rocAuc"] is not None else 0
    manipulated = [r for r in valid if r["_label"]]
    metrics["meanIoU"] = float(np.mean([r["iou"] for r in manipulated])) if manipulated else 0.0
    metrics["meanDice"] = float(np.mean([r["dice"] for r in manipulated])) if manipulated else 0.0
    groups: dict[str, list[dict]] = defaultdict(list)
    for item in valid: groups["benign_transformations" if item["expectedStatus"] == "genuine" and item["manipulation"] != "none" else item["manipulation"]].append(item)
    by_type = {}
    for name, group in groups.items():
        if len({x["_label"] for x in group}) < 2: by_type[name] = {"status": "insufficient_cases", "caseCount": len(group)}; continue
        sub = binary_metrics([x["_label"] for x in group], [x["predictedStatus"] == "manipulated" for x in group]); sub["caseCount"] = len(group); by_type[name] = sub
    for item in results: item.pop("_label", None)
    errors = [item for item in valid if item.get("failureCause")]
    output = {"evaluationVersion": VERSION, "dataset": manifest.get("dataset"), "mode": mode, "caseCount": len(results), "metrics": metrics, "confusionMatrix": metrics["confusionMatrix"], "byManipulation": by_type, "failureAnalysis": {"falsePositives": [item for item in errors if item["expectedStatus"] == "genuine"], "falseNegatives": [item for item in errors if item["expectedStatus"] == "manipulated"]}, "cases": results, "notes": ["Pilot synthetic identity-card evaluation; not a real-world accuracy claim.", f"Existing application verdict threshold used: risk >= {THRESHOLD}; no threshold optimization performed.", "IoU/Dice use normalized report boxes converted to evidence-image pixels; reference-assisted mode consumes referenceComparison.changedRegions directly.", "Failure causes are audit labels derived from report evidence; they do not change verdicts or detector behavior."]}
    output_dir.mkdir(parents=True, exist_ok=True); (output_dir / f"{mode}.json").write_text(json.dumps(output, indent=2, default=float) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--manifest", type=Path, default=Path("documents/dataset/pilot/manifest.json")); parser.add_argument("--output", type=Path, default=Path("documents/dataset/pilot/results")); parser.add_argument("--mode", choices=("reference_free", "reference_assisted", "both"), default="both")
    args = parser.parse_args(); modes = ("reference_free", "reference_assisted") if args.mode == "both" else (args.mode,)
    for mode in modes:
        result = evaluate(args.manifest, args.output, mode); print(f"{mode}: {result['caseCount']} cases, risk metrics={result['metrics']}")
    return 0


if __name__ == "__main__": raise SystemExit(main())
