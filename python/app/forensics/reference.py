"""Reference-based comparison helpers for paired exhibits.

The comparison is intentionally evidence-oriented: it reports aligned pixel and
text differences, but does not turn a difference into a forgery claim by itself.
"""

from __future__ import annotations

import difflib
import base64
import hashlib
from typing import Any

import numpy as np

from . import modules

try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None


def _order_quad(points):
    points = np.asarray(points, dtype=np.float32)
    total = points.sum(axis=1)
    diff = np.diff(points, axis=1).ravel()
    return np.array([points[np.argmin(total)], points[np.argmin(diff)], points[np.argmax(total)], points[np.argmax(diff)]], dtype=np.float32)


def _document_quad(image):
    """Find a plausible card/document quadrilateral from the outer edge."""
    if cv2 is None or image is None:
        return None
    gray = modules.to_gray(image)
    edges = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 40, 140)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    area_limit = gray.shape[0] * gray.shape[1] * 0.35
    for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:20]:
        area = cv2.contourArea(contour)
        if area < area_limit:
            continue
        approx = cv2.approxPolyDP(contour, 0.03 * cv2.arcLength(contour, True), True)
        if len(approx) == 4 and cv2.isContourConvex(approx):
            return _order_quad(approx.reshape(4, 2))
    return None


def _perspective_normalize(image, quad, size=(1200, 800)):
    if quad is None or cv2 is None:
        return image
    width, height = size
    dst = np.array([[0, 0], [width - 1, 0], [width - 1, height - 1], [0, height - 1]], dtype=np.float32)
    matrix = cv2.getPerspectiveTransform(quad, dst)
    return cv2.warpPerspective(image, matrix, (width, height), borderMode=cv2.BORDER_REPLICATE)


def _align(reference, target):
    """Perspective-normalize, then align reference into target coordinates."""
    if cv2 is None or reference is None or target is None:
        return None, "Raster alignment unavailable.", 0.0
    target_gray = modules.to_gray(target)
    ref_gray = modules.to_gray(reference)
    if target_gray is None or ref_gray is None:
        return None, "Raster alignment unavailable.", 0.0
    target_quad = _document_quad(target)
    reference_quad = _document_quad(reference)
    canonical_size = (1200, 800)
    target_norm = _perspective_normalize(target, target_quad, canonical_size)
    ref_norm = _perspective_normalize(reference, reference_quad, canonical_size)
    target_gray = modules.to_gray(target_norm)
    ref_gray = modules.to_gray(ref_norm)
    ref = cv2.resize(ref_norm, (target_norm.shape[1], target_norm.shape[0]), interpolation=cv2.INTER_AREA)
    ref_gray = cv2.resize(ref_gray, (target_norm.shape[1], target_norm.shape[0]), interpolation=cv2.INTER_AREA)
    target_gray = cv2.resize(target_gray, (target_norm.shape[1], target_norm.shape[0]), interpolation=cv2.INTER_AREA)
    warp = np.eye(2, 3, dtype=np.float32)
    try:
        criteria = (cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 80, 1e-5)
        score, warp = cv2.findTransformECC(target_gray.astype(np.float32) / 255.0, ref_gray.astype(np.float32) / 255.0, warp, cv2.MOTION_AFFINE, criteria)
        aligned = cv2.warpAffine(ref, warp, (target.shape[1], target.shape[0]), flags=cv2.INTER_LINEAR + cv2.WARP_INVERSE_MAP, borderMode=cv2.BORDER_REFLECT)
        # The returned image is always canonical so all subsequent boxes use
        # stable coordinates independent of source crop/rotation.
        aligned = cv2.warpAffine(ref, warp, (target_norm.shape[1], target_norm.shape[0]), flags=cv2.INTER_LINEAR + cv2.WARP_INVERSE_MAP, borderMode=cv2.BORDER_REFLECT)
        return aligned, f"Perspective normalization={'yes' if target_quad is not None and reference_quad is not None else 'fallback'}; affine ECC {float(score):.3f}; canonical size 1200×800.", float(np.clip(score, 0.0, 1.0))
    except Exception:
        return ref_norm, "Perspective normalization completed; ECC did not converge, so proportional canonical alignment was used.", 0.35


def _word_text(words: list[dict]) -> str:
    return " ".join(str(w.get("text", "")).strip().lower() for w in words if str(w.get("text", "")).strip())


_ID_LABELS = ("name", "gender", "date", "birth", "branch", "course", "valid", "reg", "registration")


def _identity_fields(words: list[dict], shape) -> dict[str, str]:
    """Extract conservative label/value spans from an ID-card OCR pass."""
    h, w = shape[:2]
    usable = [x for x in words if str(x.get("text", "")).strip() and float(x.get("conf", -1)) >= 25]
    fields: dict[str, str] = {}
    for label in _ID_LABELS:
        hits = [x for x in usable if str(x["text"]).strip().lower().rstrip(":.") == label]
        if not hits:
            continue
        anchor = min(hits, key=lambda x: (x["top"], x["left"]))
        same_line = [x for x in usable if x["left"] > anchor["left"] + anchor["width"] and abs(x["top"] - anchor["top"]) < max(12, anchor["height"] * .75)]
        same_line.sort(key=lambda x: x["left"])
        value_tokens = []
        for item in same_line[:8]:
            token = str(item["text"]).strip()
            if value_tokens and token.lower().rstrip(":.") in _ID_LABELS:
                break
            value_tokens.append(token)
        value = " ".join(value_tokens).strip(" :")
        if value:
            fields[label] = value
    return fields


def _text_differences(primary_words: list[dict], reference_words: list[dict], primary_shape, reference_shape) -> tuple[list[dict], list[str]]:
    """Find changed OCR tokens using normalized word coordinates."""
    ph, pw = primary_shape[:2]
    rh, rw = reference_shape[:2]
    ref_by_y = sorted(reference_words, key=lambda x: ((x["top"] + x["height"] / 2) / max(1, rh), (x["left"] + x["width"] / 2) / max(1, rw)))
    diffs: list[dict] = []
    notes: list[str] = []
    for word in primary_words:
        text = str(word.get("text", "")).strip()
        if not text or float(word.get("conf", -1)) < 20:
            continue
        nx = (word["left"] + word["width"] / 2) / max(1, pw)
        ny = (word["top"] + word["height"] / 2) / max(1, ph)
        candidates = [r for r in ref_by_y if abs((r["top"] + r["height"] / 2) / max(1, rh) - ny) < 0.045 and abs((r["left"] + r["width"] / 2) / max(1, rw) - nx) < 0.16]
        if not candidates:
            continue
        match = min(candidates, key=lambda r: abs((r["left"] + r["width"] / 2) / max(1, rw) - nx) + abs((r["top"] + r["height"] / 2) / max(1, rh) - ny))
        other = str(match.get("text", "")).strip()
        if text.lower() != other.lower() and difflib.SequenceMatcher(None, text.lower(), other.lower()).ratio() < 0.8:
            box = {"x": word["left"] / pw, "y": word["top"] / ph, "width": word["width"] / pw, "height": word["height"] / ph}
            diffs.append({"box": box, "primary": text, "reference": other})
            if len(notes) < 12:
                notes.append(f"OCR token differs at ({box['x']:.3f}, {box['y']:.3f}): exhibit '{text}' vs reference '{other}'.")
    return diffs, notes


def compare_pair(primary: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any]:
    target = primary.get("image")
    ref = reference.get("image")
    result: dict[str, Any] = {
        "aligned": False, "alignmentConfidence": 0.0, "notes": [],
        "changedRegions": [], "unchangedRegions": [], "regions": [],
        "textChanges": [], "textDifferences": [], "imageChanges": [],
        "structuralDifference": 1.0, "qr": {"status": "not-run"},
    }
    if target is None or ref is None or cv2 is None:
        result["notes"].append("Reference comparison requires two decodable raster images.")
        return result
    aligned, alignment_note, alignment_confidence = _align(ref, target)
    result["notes"].append(alignment_note)
    result["alignmentConfidence"] = round(alignment_confidence, 3)
    if aligned is None:
        return result
    result["aligned"] = alignment_confidence >= 0.35
    target = cv2.resize(target, (aligned.shape[1], aligned.shape[0]), interpolation=cv2.INTER_AREA)
    diff = cv2.absdiff(target, aligned).astype(np.float32).mean(axis=2)
    target_gray = modules.to_gray(target).astype(np.float32)
    aligned_gray = modules.to_gray(aligned).astype(np.float32)
    # Ignore a two-percent border where crop/alignment artifacts concentrate.
    margin_y, margin_x = max(2, int(diff.shape[0] * .02)), max(2, int(diff.shape[1] * .02))
    inner = diff[margin_y:-margin_y, margin_x:-margin_x]
    median = float(np.median(inner))
    mad = float(np.median(np.abs(inner - median))) + 1e-3
    z = np.clip((diff - median) / (8 * mad), 0, 1)
    # A difference is useful only when it occupies a compact region and is
    # substantially above the aligned-image baseline.
    mask = (z > .7).astype(np.uint8)
    mask[:margin_y] = 0; mask[-margin_y:] = 0; mask[:, :margin_x] = 0; mask[:, -margin_x:] = 0
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
    count, labels, stats, _ = cv2.connectedComponentsWithStats(mask, 8)
    for i in range(1, count):
        x, y, rw, rh, area = stats[i]
        if area < max(50, mask.size // 5000):
            continue
        score = float(np.mean(z[labels == i]))
        result["regions"].append({"x": x / target.shape[1], "y": y / target.shape[0], "width": rw / target.shape[1], "height": rh / target.shape[0], "score": round(score, 3), "area": int(area)})
    result["regions"] = sorted(result["regions"], key=lambda x: x["score"], reverse=True)[:20]
    def _region_type(r):
        cx, cy = r["x"] + r["width"] / 2, r["y"] + r["height"] / 2
        if cx < .30 and .25 < cy < .78:
            return "portrait-region-difference"
        if cy > .78:
            return "barcode-or-signature-region-difference"
        return "local-aligned-difference"

    result["changedRegions"] = [{"bbox": {k: v for k, v in r.items() if k in ("x", "y", "width", "height")}, "changeType": _region_type(r), "score": r["score"], "confidence": round(min(.95, .55 + r["score"] * .35), 3), "supportingEvidence": ["absolute pixel difference", "local residual z-score"]} for r in result["regions"]]
    result["imageChanges"] = [
        {"bbox": item["bbox"], "changeType": item["changeType"], "score": item["score"], "confidence": item["confidence"], "supportingEvidence": item["supportingEvidence"]}
        for item in result["changedRegions"] if item["changeType"] != "local-aligned-difference"
    ]
    # Structural similarity equivalent: normalized local SSIM mean, plus edge
    # agreement. These suppress uniform lighting/JPEG shifts better than raw
    # absolute differences.
    mu_a, mu_b = cv2.GaussianBlur(target_gray, (11, 11), 1.5), cv2.GaussianBlur(aligned_gray, (11, 11), 1.5)
    var_a = cv2.GaussianBlur(target_gray * target_gray, (11, 11), 1.5) - mu_a * mu_a
    var_b = cv2.GaussianBlur(aligned_gray * aligned_gray, (11, 11), 1.5) - mu_b * mu_b
    cov = cv2.GaussianBlur(target_gray * aligned_gray, (11, 11), 1.5) - mu_a * mu_b
    ssim = ((2 * mu_a * mu_b + 6.5025) * (2 * cov + 58.5225)) / ((mu_a * mu_a + mu_b * mu_b + 6.5025) * (var_a + var_b + 58.5225))
    edge_a = cv2.Canny(target_gray.astype(np.uint8), 80, 160)
    edge_b = cv2.Canny(aligned_gray.astype(np.uint8), 80, 160)
    edge_difference = float(np.mean(cv2.absdiff(edge_a, edge_b)) / 255.0)
    structural_difference = float(np.clip(1.0 - np.mean(ssim), 0.0, 1.0))
    result["structuralDifference"] = round(structural_difference, 4)
    if structural_difference > .08:
        result["imageChanges"].append({"changeType": "structural-or-texture", "score": round(structural_difference, 3), "confidence": round(min(.9, .5 + structural_difference), 3), "supportingEvidence": ["local SSIM", f"edge difference {edge_difference:.3f}"]})
    result["pixel"] = {"median": round(median, 3), "mad": round(mad, 3), "changedFraction": round(float(np.mean(z > .7)), 4), "regions": len(result["regions"]), "ssim": round(float(np.mean(ssim)), 4), "edgeDifference": round(edge_difference, 4)}
    heat = cv2.applyColorMap(np.uint8(np.clip(z * 255, 0, 255)), cv2.COLORMAP_JET)
    ok, encoded_heat = cv2.imencode(".jpg", heat, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
    result["heatmap"] = f"data:image/jpeg;base64,{base64.b64encode(encoded_heat).decode('ascii')}" if ok else None
    result["unchangedRegions"] = [{"bbox": {"x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0}, "score": round(float(np.mean(ssim)), 3), "supportingEvidence": ["high structural similarity outside promoted local regions"]}] if float(np.mean(ssim)) >= .85 else []
    primary_words = (primary.get("ocr") or {}).words if primary.get("ocr") is not None else []
    reference_words = (reference.get("ocr") or {}).words if reference.get("ocr") is not None else []
    text_diffs, text_notes = _text_differences(primary_words, reference_words, target.shape, ref.shape)
    result["textDifferences"] = text_diffs
    result["textChanges"] = [{"bbox": d["box"], "changeType": "ocr-text-change", "score": .9, "confidence": .82, "supportingEvidence": [f"OCR exhibit: {d['primary']}", f"OCR reference: {d['reference']}"]} for d in text_diffs]
    primary_fields = _identity_fields(primary_words, target.shape)
    reference_fields = _identity_fields(reference_words, ref.shape)
    field_differences = []
    for label in sorted(set(primary_fields) & set(reference_fields)):
        if primary_fields[label].lower() != reference_fields[label].lower():
            field_differences.append({"field": label, "primary": primary_fields[label], "reference": reference_fields[label]})
            result["notes"].append(f"Identity field '{label}' differs: exhibit '{primary_fields[label]}' vs reference '{reference_fields[label]}'.")
    result["fieldDifferences"] = field_differences
    result["notes"].extend(text_notes)
    result["qr"] = decode_codes(target, ref)
    return result


def _decode_qr(image) -> list[str]:
    if cv2 is None or image is None or not hasattr(cv2, "QRCodeDetector"):
        return []
    detector = cv2.QRCodeDetector()
    values: list[str] = []
    try:
        ok, decoded, _, _ = detector.detectAndDecodeMulti(image)
        if ok and decoded:
            values.extend([str(v).strip() for v in decoded if str(v).strip()])
    except Exception:
        pass
    try:
        value, _, _ = detector.detectAndDecode(image)
        if value and value not in values:
            values.append(value.strip())
    except Exception:
        pass
    return values


def decode_codes(primary, reference) -> dict[str, Any]:
    a = _decode_qr(primary)
    b = _decode_qr(reference)
    if not a and not b:
        return {"status": "not-detected", "primary": [], "reference": [], "match": None}
    return {"status": "decoded", "primary": a, "reference": b, "match": sorted(a) == sorted(b)}


def reference_id(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()[:16]
