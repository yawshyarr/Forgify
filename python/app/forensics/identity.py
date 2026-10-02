"""Generic identity-document field extraction and paired comparison."""

from __future__ import annotations

import difflib
import re
from typing import Any

import numpy as np

try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None


FIELD_LABELS: dict[str, tuple[str, ...]] = {
    "name": ("name", "full name", "candidate name", "student name"),
    "student_id": ("student id", "studentid", "id no", "id number"),
    "registration_number": ("reg no", "reg.no", "registration no", "registration number"),
    "prn": ("prn", "permanent registration number"),
    "roll_number": ("roll no", "roll number", "roll"),
    "date_of_birth": ("date of birth", "dob", "birth date"),
    "department": ("department", "dept", "branch", "faculty"),
    "course": ("course", "program", "programme", "class"),
    "academic_year": ("academic year", "academic yr", "year"),
    "validity": ("valid upto", "valid up to", "validity", "expires", "expiry"),
    "institution_name": ("institution", "university", "college", "school"),
}

_NORMAL = re.compile(r"[^a-z0-9]+")
_OCR_SEPARATORS = re.compile(r"[|¦·•]+")


def _norm(value: str) -> str:
    value = str(value or "").replace("–", "-").replace("—", "-").replace("−", "-")
    value = _OCR_SEPARATORS.sub(" ", value).lower()
    return _NORMAL.sub(" ", value).strip()


def _comparison(reference: dict, evidence: dict, field_type: str) -> tuple[str, float, list[str]]:
    ref, ev = reference["normalizedText"], evidence["normalizedText"]
    if ref == ev:
        return "MATCH", 0.98, ["normalized OCR text matches"]
    similarity = difflib.SequenceMatcher(None, ref, ev).ratio()
    ref_tokens, ev_tokens = ref.split(), ev.split()
    if field_type in {"registration_number", "student_id", "prn", "roll_number"}:
        if (len(ev_tokens) > len(ref_tokens) and ev_tokens[:len(ref_tokens)] == ref_tokens
                and len(ev_tokens) - len(ref_tokens) <= 2
                and all(len(token) <= 8 for token in ev_tokens[len(ref_tokens):])):
            return "UNRELIABLE_OCR", 0.48, ["identifier plus short trailing OCR token"]
        if similarity >= 0.86:
            return "LIKELY_MATCH", 0.62, [f"identifier similarity {similarity:.3f}"]
    if similarity >= 0.86:
        return "LIKELY_MATCH", 0.68, [f"normalized text similarity {similarity:.3f}"]
    if similarity >= 0.55:
        return "LIKELY_MISMATCH", 0.68, [f"normalized text similarity {similarity:.3f}"]
    return "MISMATCH", 0.90 if field_type == "name" else 0.82, ["normalized OCR text mismatch", f"text similarity {similarity:.3f}"]


def _label_match(text: str) -> tuple[str, int] | None:
    value = _norm(text)
    for field, labels in FIELD_LABELS.items():
        for label in labels:
            if value == _norm(label):
                return field, 1
    return None


def _label_spans(words: list[dict]) -> dict[int, tuple[str, int]]:
    """Match single- and multi-token labels across normal OCR line breaks."""
    spans: dict[int, tuple[str, int]] = {}
    for start, word in enumerate(words):
        for field_type, labels in FIELD_LABELS.items():
            for label in labels:
                tokens = _norm(label).split()
                if not tokens or start + len(tokens) > len(words):
                    continue
                candidate = words[start:start + len(tokens)]
                if [_norm(str(item.get("text", ""))) for item in candidate] != tokens:
                    continue
                if any(abs(float(item.get("top", 0)) - float(word.get("top", 0))) > max(18, float(word.get("height", 12)) * 1.8) for item in candidate):
                    continue
                if any(float(candidate[i + 1].get("left", 0)) < float(candidate[i].get("left", 0)) for i in range(len(candidate) - 1)):
                    continue
                spans[start] = (field_type, start + len(tokens) - 1)
                break
            if start in spans:
                break
    return spans


def _box(word: dict, shape) -> dict[str, float]:
    h, w = shape[:2]
    return {"x": word["left"] / w, "y": word["top"] / h, "width": word["width"] / w, "height": word["height"] / h}


def extract_fields(words: list[dict], shape) -> list[dict]:
    """Extract only fields supported by visible OCR labels; never invent missing fields."""
    usable = [word for word in words if str(word.get("text", "")).strip() and float(word.get("conf", -1)) >= 20]
    fields: list[dict] = []
    spans = _label_spans(usable)
    for index, label_word in enumerate(usable):
        span = spans.get(index)
        if span is None:
            match = _label_match(str(label_word["text"]).strip().rstrip(":"))
            if not match:
                continue
            field_type, _ = match
            label_end = index
        else:
            field_type, label_end = span
        label_tail = usable[label_end]
        # Values may begin on the following OCR line for split labels such as
        # Date / of / Birth, while still remaining close to the label.
        same_line = [
            word for word in usable[label_end + 1:]
            if word["left"] > label_tail["left"] + label_tail["width"]
            and float(word["top"]) - float(label_tail["top"]) <= max(24, label_tail["height"] * 1.8)
            and float(word["top"]) >= float(label_tail["top"]) - max(8, label_tail["height"] * .5)
        ]
        same_line.sort(key=lambda word: (word["top"], word["left"]))
        if not same_line:
            continue
        value_words: list[dict] = []
        for word in same_line[:8]:
            if value_words and _label_match(str(word["text"]).strip().rstrip(":")):
                break
            value_words.append(word)
        if not value_words:
            continue
        x0 = min(label_word["left"], value_words[0]["left"])
        y0 = min(label_word["top"], *(word["top"] for word in value_words))
        x1 = max(word["left"] + word["width"] for word in value_words)
        y1 = max(label_word["top"] + label_word["height"], *(word["top"] + word["height"] for word in value_words))
        label_conf = float(label_word.get("conf", 0)) / 100.0
        value_conf = float(np.mean([float(word.get("conf", 0)) for word in value_words])) / 100.0
        raw_text = " ".join(str(word["text"]).strip() for word in value_words).strip(" :")
        fields.append({
            "fieldType": field_type,
            "text": raw_text,
            "rawText": raw_text,
            "normalizedText": _norm(raw_text),
            "bbox": {"x": x0 / shape[1], "y": y0 / shape[0], "width": (x1 - x0) / shape[1], "height": (y1 - y0) / shape[0]},
            "confidence": round(max(0.0, min(1.0, 0.5 * label_conf + 0.5 * value_conf)), 3),
        })
    # Keep the highest-confidence observation if OCR sees a label more than once.
    unique: dict[str, dict] = {}
    for field in fields:
        if field["fieldType"] not in unique or field["confidence"] > unique[field["fieldType"]]["confidence"]:
            unique[field["fieldType"]] = field
    return list(unique.values())


def _decode_codes(image) -> list[str]:
    if cv2 is None or image is None:
        return []
    values: list[str] = []
    try:
        detector = cv2.QRCodeDetector()
        ok, decoded, _, _ = detector.detectAndDecodeMulti(image)
        if ok and decoded:
            values.extend(str(value).strip() for value in decoded if str(value).strip())
        value, _, _ = detector.detectAndDecode(image)
        if value and value.strip() not in values:
            values.append(value.strip())
    except Exception:
        pass
    return values


def analyze_identity(image, ocr, reference_image=None, reference_ocr=None) -> dict[str, Any]:
    shape = image.shape[:2] if image is not None else (1, 1)
    fields = extract_fields(getattr(ocr, "words", []) if ocr else [], shape)
    result: dict[str, Any] = {"fields": fields, "fieldFindings": [], "fieldComparisons": [], "codes": _decode_codes(image), "referenceCodes": [], "visualFindings": []}
    if reference_image is None or reference_ocr is None:
        return result
    reference_shape = reference_image.shape[:2]
    reference_fields = {field["fieldType"]: field for field in extract_fields(getattr(reference_ocr, "words", []), reference_shape)}
    evidence_fields = {field["fieldType"]: field for field in fields}
    for field_type in sorted(set(reference_fields) | set(evidence_fields)):
        reference_field = reference_fields.get(field_type)
        evidence_field = evidence_fields.get(field_type)
        if reference_field is None or evidence_field is None:
            # Absence is reported as a comparison difference, never as a
            # suspicious missing field by itself.
            comparison = {
                "fieldType": field_type,
                "type": "OCR_FIELD_REMOVED" if evidence_field is None else "OCR_FIELD_ADDED",
                "referenceText": reference_field["text"] if reference_field else None,
                "evidenceText": evidence_field["text"] if evidence_field else None,
                "bbox": (evidence_field or reference_field)["bbox"],
                "confidence": 0.82,
                "evidence": ["field exists in only one compared exhibit"],
            }
            result["fieldComparisons"].append(comparison)
            result["fieldFindings"].append(comparison)
            continue
        position_delta = abs(reference_field["bbox"]["x"] - evidence_field["bbox"]["x"]) + abs(reference_field["bbox"]["y"] - evidence_field["bbox"]["y"])
        state, confidence, comparison_evidence = _comparison(reference_field, evidence_field, field_type)
        result["fieldComparisons"].append({
            "fieldType": field_type, "comparisonState": state,
            "referenceText": reference_field["text"], "evidenceText": evidence_field["text"],
            "referenceRawText": reference_field["rawText"], "evidenceRawText": evidence_field["rawText"],
            "referenceNormalizedText": reference_field["normalizedText"], "evidenceNormalizedText": evidence_field["normalizedText"],
            "bbox": evidence_field["bbox"], "confidence": round(confidence, 3), "evidence": comparison_evidence,
        })
        if state not in {"MATCH", "LIKELY_MATCH"}:
            result["fieldFindings"].append({
                "fieldType": field_type,
                "type": "OCR_FIELD_MISMATCH" if state in {"MISMATCH", "LIKELY_MISMATCH"} else "OCR_FIELD_UNRELIABLE",
                "comparisonState": state,
                "referenceText": reference_field["text"],
                "referenceRawText": reference_field["rawText"],
                "referenceNormalizedText": reference_field["normalizedText"],
                "evidenceText": evidence_field["text"],
                "evidenceRawText": evidence_field["rawText"],
                "evidenceNormalizedText": evidence_field["normalizedText"],
                "bbox": evidence_field["bbox"],
                "confidence": round(confidence, 3),
                "evidence": comparison_evidence,
            })
        elif position_delta > 0.08:
            result["fieldFindings"].append({
                "fieldType": field_type, "type": "OCR_FIELD_POSITION_CHANGE",
                "comparisonState": "LIKELY_MATCH",
                "referenceText": reference_field["text"], "evidenceText": evidence_field["text"],
                "bbox": evidence_field["bbox"], "confidence": 0.72,
                "evidence": [f"normalized bbox displacement {position_delta:.3f}"],
            })
    result["referenceCodes"] = _decode_codes(reference_image)
    if sorted(result["codes"]) != sorted(result["referenceCodes"]) and (result["codes"] or result["referenceCodes"]):
        result["fieldFindings"].append({
            "fieldType": "qr_or_barcode", "type": "QR_BARCODE_MISMATCH",
            "referenceText": "; ".join(result["referenceCodes"]), "evidenceText": "; ".join(result["codes"]),
            "bbox": {"x": 0.0, "y": 0.0, "width": 1.0, "height": 1.0}, "confidence": 0.95,
            "evidence": ["decoded payloads differ between reference and evidence"],
        })
    return result
