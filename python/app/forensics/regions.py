"""Evidence-aware suspicious-region aggregation.

Detector regions are deliberately kept as raw layer output for auditability.
This module creates the executive-facing view: overlapping observations are
clustered into one physical region and their reasons are retained together.
"""

from __future__ import annotations

from typing import Any


def _box(value: dict[str, Any]) -> dict[str, float]:
    return {key: float(value.get(key, 0.0)) for key in ("x", "y", "width", "height")}


def _iou(a: dict[str, Any], b: dict[str, Any]) -> float:
    ax0, ay0 = float(a.get("x", 0)), float(a.get("y", 0))
    ax1, ay1 = ax0 + float(a.get("width", 0)), ay0 + float(a.get("height", 0))
    bx0, by0 = float(b.get("x", 0)), float(b.get("y", 0))
    bx1, by1 = bx0 + float(b.get("width", 0)), by0 + float(b.get("height", 0))
    overlap = max(0.0, min(ax1, bx1) - max(ax0, bx0)) * max(0.0, min(ay1, by1) - max(ay0, by0))
    union = max(0.0, ax1 - ax0) * max(0.0, ay1 - ay0) + max(0.0, bx1 - bx0) * max(0.0, by1 - by0) - overlap
    return overlap / union if union else 0.0


def _overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Allow small detector box drift without merging merely adjacent fields."""
    if _iou(a, b) >= 0.18:
        return True
    cx = float(a.get("x", 0)) + float(a.get("width", 0)) / 2
    cy = float(a.get("y", 0)) + float(a.get("height", 0)) / 2
    return (float(b.get("x", 0)) <= cx <= float(b.get("x", 0)) + float(b.get("width", 0))
            and float(b.get("y", 0)) <= cy <= float(b.get("y", 0)) + float(b.get("height", 0)))


def _type_for(candidate: dict[str, Any], identity_fields: list[dict[str, Any]]) -> str:
    label = f"{candidate.get('label', '')} {candidate.get('technique', '')} {candidate.get('notes', '')}".lower()
    for field in identity_fields:
        if _iou(candidate, field.get("bbox", {})) >= 0.12:
            mapping = {
                "name": "name", "student_id": "student ID", "registration_number": "registration number",
                "prn": "PRN", "roll_number": "roll number", "date_of_birth": "date",
                "department": "course", "course": "course", "academic_year": "course", "validity": "date",
                "institution_name": "logo",
            }
            return mapping.get(str(field.get("fieldType")), str(field.get("fieldType")))
    rules = (("portrait", "portrait"), ("photo", "portrait"), ("face", "portrait"),
             ("qr", "QR"), ("barcode", "barcode"), ("signature", "signature"),
             ("logo", "logo"), ("background", "background"), ("date", "date"),
             ("course", "course"), ("name", "name"), ("student id", "student ID"),
             ("registration", "registration number"))
    return next((kind for token, kind in rules if token in label), "unknown")


def _candidate_from_field(field: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    matching = [f for f in findings if f.get("fieldType") == field.get("fieldType")]
    finding = matching[0] if matching else None
    return {
        "layer": "identity-ocr", "label": f"Identity field: {field.get('fieldType')}",
        "score": float(finding.get("confidence", 0.0)) if finding else 0.0,
        "confidence": float(finding.get("confidence", field.get("confidence", 0.0))) if finding else float(field.get("confidence", 0.0)),
        **field.get("bbox", {}), "technique": "identity OCR", "notes": "; ".join(finding.get("evidence", [])) if finding else f"OCR field: {field.get('text', '')}",
    }


def aggregate_regions(raw_regions: list[dict[str, Any]], identity_fields: list[dict[str, Any]] | None = None,
                      identity_findings: list[dict[str, Any]] | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return merged regions and one explainable finding per merged cluster."""
    identity_fields = identity_fields or []
    candidates = list(raw_regions) + [_candidate_from_field(f, identity_findings or []) for f in identity_fields]
    clusters: list[list[dict[str, Any]]] = []
    for candidate in candidates:
        if not candidate.get("width", 0) or not candidate.get("height", 0):
            continue
        matching = [cluster for cluster in clusters if any(_overlap(candidate, item) for item in cluster)]
        if not matching:
            clusters.append([candidate])
        else:
            base = matching[0]
            base.append(candidate)
            for other in matching[1:]:
                base.extend(other)
                clusters.remove(other)

    merged: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for index, cluster in enumerate(clusters, 1):
        x0 = min(float(c.get("x", 0)) for c in cluster); y0 = min(float(c.get("y", 0)) for c in cluster)
        x1 = max(float(c.get("x", 0)) + float(c.get("width", 0)) for c in cluster)
        y1 = max(float(c.get("y", 0)) + float(c.get("height", 0)) for c in cluster)
        detectors = list(dict.fromkeys(str(c.get("detector", c.get("layer", "unknown"))) for c in cluster))
        scores = {str(c.get("detector", c.get("layer", "unknown"))): round(max(float(x.get("score", 0)) for x in cluster if str(x.get("detector", x.get("layer", "unknown"))) == str(c.get("detector", c.get("layer", "unknown")))), 3) for c in cluster}
        types = [_type_for(c, identity_fields) for c in cluster]
        known_types = [t for t in types if t != "unknown"]
        region_type = max(known_types or types, key=lambda t: types.count(t))
        evidence = []
        for c in cluster:
            note = str(c.get("notes", "")).strip()
            item = f"{c.get('detector', c.get('layer', 'detector'))}: {c.get('label', 'anomaly')} (score {float(c.get('score', 0)):.2f})"
            evidence.append(f"{item}; {note}" if note else item)
        max_conf = max(float(c.get("confidence", 0)) for c in cluster)
        confidence = min(0.98, max_conf + min(0.18, 0.06 * (len(detectors) - 1)))
        region = {"id": f"UR-{index:02d}", "bbox": {"x": round(x0, 4), "y": round(y0, 4), "width": round(x1-x0, 4), "height": round(y1-y0, 4)},
                  "regionType": region_type, "detectors": detectors, "scores": scores, "confidence": round(confidence, 3),
                  "evidence": evidence, "whySuspicious": "Corroborated local evidence: " + "; ".join(detectors)}
        merged.append(region)
        findings.append({"id": f"URF-{index:02d}", "regionId": region["id"], "regionType": region_type,
                         "bbox": region["bbox"], "confidence": region["confidence"], "evidence": evidence,
                         "description": region["whySuspicious"]})
    return merged, findings


__all__ = ["aggregate_regions"]
