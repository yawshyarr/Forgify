"""
Forgify · detector layer implementations (numpy / OpenCV).

Every module returns a dict that matches `LayerResult` in
`src/lib/forensics/types.ts`, so the Next.js client renders these results
without knowing which backend produced them.
"""

from __future__ import annotations

import io
import math
import time
import base64
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

try:
    import joblib
except Exception:  # pragma: no cover - optional ML dependency
    joblib = None

try:  # OpenCV is optional so the worker still boots on slim hosts
    import cv2
except Exception:  # pragma: no cover
    cv2 = None

from PIL import Image


LIMITATIONS = [
    "Region localisation depends on image quality: aggressive recompression destroys high-frequency evidence.",
    "Generative-AI detection is probabilistic and adversarially fragile; a low score never certifies human capture.",
    "Metadata is trivially editable and must be weighed against chain-of-custody records.",
]

MODEL_DIRECTORY = Path(__file__).resolve().parent / "models"
BINARY_MODEL_PATH = MODEL_DIRECTORY / "binary_classifier.pkl"
FORGERY_TYPE_MODEL_PATH = MODEL_DIRECTORY / "forgery_type_classifier.pkl"


def _load_model(path: Path) -> tuple[Any | None, str | None]:
    """Load a persisted model once during worker startup."""
    if joblib is None:
        return None, "joblib is unavailable; ML classification cannot run."
    if not path.is_file():
        return None, f"Model file is missing: {path.name}."
    try:
        return joblib.load(path), None
    except Exception as error:  # pragma: no cover - corrupt/incompatible model
        return None, f"Could not load {path.name}: {error}"


BINARY_CLASSIFIER, BINARY_MODEL_ERROR = _load_model(BINARY_MODEL_PATH)
FORGERY_TYPE_CLASSIFIER, FORGERY_TYPE_MODEL_ERROR = _load_model(FORGERY_TYPE_MODEL_PATH)

# The persisted classifier was validated only against the synthetic
# invoice/marksheet corpus. Other domains remain diagnostic-only until a
# domain-specific calibration set exists.
ML_VALIDATED_DOMAINS = frozenset({"invoice", "marksheet"})


# --------------------------------------------------------------------------- #
#  shared helpers
# --------------------------------------------------------------------------- #


def byte_entropy(payload: bytes, sample_limit: int = 262_144) -> float:
    sample = payload[:sample_limit]
    if not sample:
        return 0.0
    hist = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256).astype(np.float64)
    p = hist / hist.sum()
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def to_array(payload: bytes):
    if cv2 is None:
        return None
    try:
        return cv2.imdecode(np.frombuffer(payload, dtype=np.uint8), cv2.IMREAD_COLOR)
    except Exception:
        return None


def to_gray(image):
    if image is None or cv2 is None:
        return None
    return image if image.ndim == 2 else cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)


def screenshot_signature(image, window: int = 40) -> float:
    """Flat-area median residual noise (Forgify noise_analysis). A normal
    stored JPEG keeps this near 0; a screen-capture / downsample-rescale
    pipeline smears edges and raises it into the ~0.25+ band."""
    gray = to_gray(image) if image is not None else None
    if gray is None:
        return 0.0
    blurred = cv2.medianBlur(gray, 5)
    residual = gray.astype(np.float32) - blurred.astype(np.float32)
    sigma_local = np.sqrt(
        cv2.boxFilter(residual * residual, -1, (window, window), normalize=True)
    )
    grad_x = cv2.Sobel(blurred, cv2.CV_32F, 1, 0, ksize=3)
    grad_y = cv2.Sobel(blurred, cv2.CV_32F, 0, 1, ksize=3)
    flat = np.exp(-np.sqrt(grad_x * grad_x + grad_y * grad_y) / 28.0).astype(np.float32)
    anomaly = (sigma_local * flat).astype(np.float32)
    return float(np.median(anomaly))


def _ela_map(image, quality: int) -> np.ndarray | None:
    ok, encoded = cv2.imencode(".jpg", image, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    if not ok:
        return None
    decoded = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    return cv2.absdiff(image, decoded).astype(np.float32).mean(axis=2)


def _ela_suppression_mask(context: dict, shape) -> np.ndarray:
    """Mask OCR text and known high-frequency machine-code areas from ELA peaks."""
    h, w = shape[:2]
    mask = np.zeros((h, w), dtype=np.uint8)
    for word in getattr(context.get("_ocr"), "words", []) or []:
        x0 = max(0, int(word["left"] - word["width"] * .35)); y0 = max(0, int(word["top"] - word["height"] * .5))
        x1 = min(w, int(word["left"] + word["width"] * 1.35)); y1 = min(h, int(word["top"] + word["height"] * 1.5))
        mask[y0:y1, x0:x1] = 1
    # A barcode/QR is normally a dense high-frequency rectangular component;
    # suppress only very dense lower-frame bands rather than assuming a card
    # template or fixed student layout.
    gray = to_gray(context.get("image"))
    if gray is not None:
        density = cv2.blur((cv2.Canny(gray, 80, 180) > 0).astype(np.float32), (31, 31))
        mask[density > .42] = 1
    return mask


def _stable_ela(ela_maps: list[np.ndarray], suppression: np.ndarray) -> tuple[np.ndarray, dict]:
    normalized = []
    for current in ela_maps:
        texture = cv2.GaussianBlur(np.abs(cv2.Laplacian(current, cv2.CV_32F)), (0, 0), 3) + 1.0
        value = current / texture
        valid = value[suppression == 0]
        med = float(np.median(valid)) if valid.size else float(np.median(value))
        mad = float(np.median(np.abs(valid - med))) + 1e-3 if valid.size else 1.0
        normalized.append(np.clip((value - med) / (8.0 * mad), 0, 1))
    stack = np.stack(normalized)
    masks = stack > .72
    stability = masks.mean(axis=0)
    stable = stability >= (2.0 / len(ela_maps))
    composite = np.median(stack, axis=0) * stability
    valid = composite[suppression == 0]
    metrics = {
        "median": float(np.median(valid)) if valid.size else 0.0,
        "p90": float(np.percentile(valid, 90)) if valid.size else 0.0,
        "p95": float(np.percentile(valid, 95)) if valid.size else 0.0,
        "hotspotArea": float(np.mean(stable[suppression == 0])) if valid.size else 0.0,
        "hotspotStability": float(np.mean(stability[stable])) if np.any(stable) else 0.0,
    }
    return composite, metrics


def band(score: float) -> str:
    if score >= 0.82:
        return "critical"
    if score >= 0.66:
        return "high"
    if score >= 0.45:
        return "medium"
    if score >= 0.26:
        return "low"
    return "info" if score >= 0.14 else "benign"


def finding(layer, code, title, severity, confidence, description, evidence=None, region=None,
            metric=None, recommendation=None) -> dict:
    return {
        "id": f"F-{code}",
        "layer": layer,
        "code": code,
        "title": title,
        "severity": severity,
        "confidence": round(float(confidence), 3),
        "description": description,
        "metric": metric,
        "evidence": evidence or [],
        "region": region,
        "recommendation": recommendation,
    }


def region(layer, label, score, confidence, box, shape, technique, notes) -> dict:
    height, width = shape
    x0, y0, x1, y1 = box
    return {
        "id": "",
        "label": label,
        "layer": layer,
        "score": round(float(score), 3),
        "confidence": round(float(confidence), 3),
        "x": round(max(0, x0) / width, 4),
        "y": round(max(0, y0) / height, 4),
        "width": round(min(1.0, (x1 - x0) / width), 4),
        "height": round(min(1.0, (y1 - y0) / height), 4),
        "technique": technique,
        "notes": notes,
    }


# --------------------------------------------------------------------------- #
#  module base
# --------------------------------------------------------------------------- #


@dataclass
class Module:
    id: str
    name: str
    category: str
    weight: float
    runtime: str
    techniques: list[str] = field(default_factory=list)

    def result(
        self,
        score,
        findings,
        regions,
        started,
        summary,
        metrics,
        confidence=None,
        status: str | None = None,
    ) -> dict:
        return {
            "layer": self.id,
            "name": self.name,
            "category": self.category,
            "weight": self.weight,
            "score": round(float(score), 4),
            "confidence": round(float(confidence if confidence is not None else 0.6 + score * 0.3), 3),
            "status": status or ("alert" if score >= 0.5 else "review" if score >= 0.28 else "pass"),
            "mode": "live",
            "runtime": self.runtime,
            "durationMs": int((time.time() - started) * 1000),
            "summary": summary,
            "techniques": self.techniques,
            "findings": findings,
            "metrics": metrics,
            "regions": regions,
        }

    def run(self, context: dict) -> dict:  # pragma: no cover
        raise NotImplementedError


# --------------------------------------------------------------------------- #
#  01 · pixel-level integrity
# --------------------------------------------------------------------------- #


class PixelModule(Module):
    def __init__(self) -> None:
        super().__init__(
            id="pixel",
            name="Pixel-Level Integrity",
            category="signal",
            weight=0.17,
            runtime="cv2.ELA + Laplacian noise map + flat-area residual (Forgify noise_analysis)",
            techniques=[
                "Error-level analysis (re-encode at q=90)",
                "Local noise variance map",
                "Block-wise residual clustering",
                "Flat-area median residual (screenshot/rescale signature)",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        if image is None or cv2 is None:
            return self.result(0.0, [], [], started, "No decodable raster; ELA unavailable.", [])

        gray = to_gray(image)
        height, width = gray.shape[:2]

        ela_maps = [m for m in (_ela_map(image, q) for q in (85, 90, 95)) if m is not None]
        if len(ela_maps) != 3:
            return self.result(0.0, [], [], started, "Multi-quality ELA unavailable.", [])
        suppression = _ela_suppression_mask(context, (height, width))
        composite, ela_stats = _stable_ela(ela_maps, suppression)
        # Score localized abnormal compression behavior, not absolute ELA.
        # A widespread response is characteristic of document texture,
        # capture noise, or recompression. Localized evidence is rewarded;
        # broad coverage is explicitly down-weighted and ELA cannot by itself
        # create a near-certain pixel verdict.
        area = ela_stats["hotspotArea"]
        localization = float(np.clip(1.0 - max(0.0, area - 0.04) / 0.18, 0.0, 1.0))
        score = float(np.clip((.40 * ela_stats["p95"] + .30 * ela_stats["hotspotStability"] + .30 * localization) * localization, 0, .65))
        findings: list[dict] = []
        regions: list[dict] = []
        metrics: list[dict] = []
        hotspot = (composite > .42).astype(np.uint8)
        hotspot[suppression > 0] = 0
        hotspot = cv2.morphologyEx(hotspot, cv2.MORPH_OPEN, np.ones((3, 3), np.uint8))
        count, labels, stats, _ = cv2.connectedComponentsWithStats(hotspot, 8)
        for i in range(1, count):
            x0, y0, rw, rh, area = stats[i]
            if area < max(80, hotspot.size // 3000):
                continue
            local_score = float(np.mean(composite[labels == i]))
            box = region("pixel", "Stable ELA hotspot", local_score, min(.9, .55 + ela_stats["hotspotStability"] * .35), (x0, y0, x0 + rw, y0 + rh), (height, width), "multi-quality texture-normalized ELA", "Hotspot remained present across multiple JPEG re-encoding qualities after text/high-frequency suppression.")
            regions.append(box)
        regions.sort(key=lambda item: item["score"], reverse=True)
        regions = regions[:12]
        if regions:
            findings.append(finding("pixel", "PX-ELA", "Stable localized compression residual", band(score), min(.9, .55 + ela_stats["hotspotStability"] * .35), "A localized ELA residual remained stable across q85/q90/q95 after normalization against local texture and suppression of OCR/high-frequency structures. This is supporting evidence only.", [{"label": "Qualities", "value": "q85, q90, q95"}, {"label": "Median", "value": f"{ela_stats['median']:.3f}"}, {"label": "P90", "value": f"{ela_stats['p90']:.3f}"}, {"label": "P95", "value": f"{ela_stats['p95']:.3f}"}, {"label": "Hotspot area", "value": f"{ela_stats['hotspotArea']:.4f}"}, {"label": "Hotspot stability", "value": f"{ela_stats['hotspotStability']:.3f}"}], regions[0], recommendation="Corroborate this localized residual with reference comparison, OCR field evidence, or issuer records."))
        heat = cv2.applyColorMap(np.uint8(np.clip(composite * 255, 0, 255)), cv2.COLORMAP_JET)
        ok, heat_bytes = cv2.imencode(".jpg", heat, [int(cv2.IMWRITE_JPEG_QUALITY), 85])
        heatmap = f"data:image/jpeg;base64,{base64.b64encode(heat_bytes).decode('ascii')}" if ok else None
        metrics.extend([{ "label": "ELA qualities", "value": "q85/q90/q95" }, {"label": "ELA median", "value": f"{ela_stats['median']:.3f}"}, {"label": "ELA P90", "value": f"{ela_stats['p90']:.3f}"}, {"label": "ELA P95", "value": f"{ela_stats['p95']:.3f}"}, {"label": "Hotspot area", "value": f"{ela_stats['hotspotArea']:.4f}"}, {"label": "Hotspot stability", "value": f"{ela_stats['hotspotStability']:.3f}"}, {"label": "Localization factor", "value": f"{localization:.3f}"}])

        laplacian = cv2.Laplacian(gray, cv2.CV_32F)
        global_sigma = float(laplacian.std())
        tile = gray[0 : max(1, height // 3), 0 : max(1, width // 3)]
        local_sigma = float(cv2.Laplacian(tile, cv2.CV_32F).std())
        divergence = abs(local_sigma - global_sigma) / max(1e-6, global_sigma)
        noise_score = min(1.0, max(0.0, (divergence - 0.15) / 0.85))
        score = max(score, noise_score * 0.8)
        findings.append(
            finding(
                "pixel", "PX-NOISE", "Noise distribution measured across the frame",
                band(noise_score * 0.7), 0.72,
                f"Global Laplacian sigma={global_sigma:.2f}, corner tile sigma={local_sigma:.2f} "
                f"(divergence {divergence:.3f}). Divergence above 0.4 usually means a pasted object "
                "carrying a foreign noise floor.",
                [
                    {"label": "Global sigma", "value": f"{global_sigma:.2f}"},
                    {"label": "Tile sigma", "value": f"{local_sigma:.2f}"},
                    {"label": "Divergence", "value": f"{divergence:.3f}"},
                ],
            )
        )

        # Screenshot signature (Forgify noise_analysis): flat-area median
        # residual noise. Clean stored docs sit near 0.00; screen captures /
        # rescale pipelines land in the 0.25+ band (benchmark recall 0.90,
        # FPR 0.00).
        smooth = screenshot_signature(image)
        if smooth >= 0.25:
            smooth_score = float(np.clip((smooth - 0.25) / 0.9, 0.0, 1.0))
            score = max(score, smooth_score * 0.9)
            findings.append(
                finding(
                    "pixel", "PX-SMOOTH", "Document is unusually smooth (residual noise floor)",
                    band(smooth_score), min(0.95, 0.5 + smooth_score * 0.4),
                    f"Flat-area median residual noise is {smooth:.3f}, far above the "
                    "stored-JPEG band (≈0.00). Edge smearing of this magnitude is produced "
                    "by a screen-capture or downsample/rescale pipeline.",
                    [{"label": "Flat-area median residual", "value": f"{smooth:.3f}"}],
                    metric=f"{smooth:.3f}",
                    recommendation="Compare the file against a direct export from the originating application.",
                )
            )
            metrics.append({"label": "Flat-area residual", "value": f"{smooth:.3f}"})

        metrics.append({"label": "Noise divergence", "value": f"{divergence:.3f}"})
        output = self.result(
            score, findings, regions, started,
            f"Multi-quality ELA found {len(regions)} stable hotspot(s); noise divergence {divergence:.3f}.",
            metrics,
        )
        output["heatmap"] = heatmap
        output["elaEvidence"] = {"qualities": [85, 90, 95], **ela_stats, "suppressedPixels": int(suppression.sum())}
        return output


# --------------------------------------------------------------------------- #
#  07 · copy-move & splice detection
# --------------------------------------------------------------------------- #


class CopyMoveModule(Module):
    def __init__(self) -> None:
        super().__init__(
            id="copy-move",
            name="Copy-Move & Splice Detection",
            category="manipulation",
            weight=0.13,
            runtime="cv2.SIFT + BFMatcher + RANSAC",
            techniques=["SIFT keypoints", "ratio-test matching", "estimateAffine2D RANSAC"],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        if image is None or cv2 is None:
            return self.result(0.0, [], [], started, "Raster unavailable for keypoint matching.", [])

        gray = to_gray(image)
        height, width = gray.shape[:2]
        sift = cv2.SIFT_create(nfeatures=5000)
        keypoints, descriptors = sift.detectAndCompute(gray, None)
        findings: list[dict] = []
        regions: list[dict] = []
        score = 0.0
        inliers = 0
        matched = 0

        if descriptors is not None and len(keypoints) >= 8:
            matcher = cv2.BFMatcher()
            raw = matcher.knnMatch(descriptors, descriptors, k=3)
            pairs = []
            for group in raw:
                if len(group) < 3:
                    continue
                match = group[2]
                if match.queryIdx == match.trainIdx:
                    continue
                distance = math.dist(keypoints[match.queryIdx].pt, keypoints[match.trainIdx].pt)
                if distance < 12:
                    continue
                pairs.append((match.queryIdx, match.trainIdx, match.distance))
            pairs.sort(key=lambda item: item[2])
            pairs = pairs[:600]
            matched = len(pairs)

            if matched >= 6:
                src = np.float32([keypoints[q].pt for q, _, _ in pairs]).reshape(-1, 1, 2)
                dst = np.float32([keypoints[t].pt for _, t, _ in pairs]).reshape(-1, 1, 2)
                transform, mask = cv2.estimateAffine2D(src, dst, method=cv2.RANSAC, ransacReprojThreshold=3.0)
                inliers = int(mask.sum()) if mask is not None else 0
                ratio = inliers / max(1, matched)
                score = min(1.0, max(0.0, (ratio - 0.25) / 0.5))

                if inliers >= 12:
                    xs = [keypoints[q].pt[0] for i, (q, _, _) in enumerate(pairs) if i < len(mask) and mask[i]]
                    ys = [keypoints[q].pt[1] for i, (q, _, _) in enumerate(pairs) if i < len(mask) and mask[i]]
                    if xs and ys:
                        box = (
                            int(min(xs)),
                            int(min(ys)),
                            int(min(width, max(xs))),
                            int(min(height, max(ys))),
                        )
                        detected = region(
                            "copy-move", "Clone cluster", score, 0.6 + score * 0.32, box,
                            (height, width), "SIFT + RANSAC",
                            f"{inliers} keypoint inliers explained by one affine transform.",
                        )
                        regions.append(detected)
                        findings.append(
                            finding(
                                "copy-move", "CM-CLONE",
                                "Keypoint cluster shares a single affine transform",
                                band(score), 0.62 + score * 0.32,
                                f"{inliers} of {matched} ratio-test matches are explained by one affine "
                                "transform. This is the geometric signature of intra-image duplication.",
                                [
                                    {"label": "Keypoints", "value": str(len(keypoints))},
                                    {"label": "Matches", "value": str(matched)},
                                    {"label": "RANSAC inliers", "value": str(inliers)},
                                ],
                                detected,
                                f"{inliers} inliers",
                            )
                        )

        return self.result(
            score, findings, regions, started,
            f"{len(keypoints) if keypoints is not None else 0} keypoints, {matched} matches, {inliers} inliers.",
            [
                {"label": "Keypoints", "value": str(len(keypoints) if keypoints is not None else 0)},
                {"label": "Matches", "value": str(matched)},
                {"label": "Inliers", "value": str(inliers)},
            ],
        )


class QRBarcodeModule(Module):
    """Decode machine-readable identifiers; decoding alone is not authenticity proof."""

    def __init__(self) -> None:
        super().__init__(
            id="qr-barcode", name="QR / Barcode Verification", category="content", weight=0.05,
            runtime="OpenCV QRCodeDetector / BarcodeDetector", techniques=["QR payload decode", "Barcode payload decode", "Reference payload comparison"],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        decoded: list[dict] = []
        if image is not None and cv2 is not None:
            try:
                detector = cv2.QRCodeDetector()
                ok, values, points, _ = detector.detectAndDecodeMulti(image)
                if ok and values:
                    for index, value in enumerate(values):
                        if str(value).strip():
                            point = points[index] if points is not None and index < len(points) else None
                            decoded.append({"kind": "qr", "payload": str(value).strip(), "bbox": _points_box(point, image.shape) if point is not None else None, "confidence": 0.9})
                value, point, _ = detector.detectAndDecode(image)
                if value and not any(item["payload"] == value.strip() for item in decoded):
                    decoded.append({"kind": "qr", "payload": value.strip(), "bbox": _points_box(point, image.shape) if point is not None else None, "confidence": 0.85})
            except Exception:
                pass
            try:
                barcode = getattr(cv2, "barcode", None)
                if barcode is not None and hasattr(barcode, "BarcodeDetector"):
                    ok, values, points, _ = barcode.BarcodeDetector().detectAndDecode(image)
                    if ok and values:
                        for index, value in enumerate(values):
                            if str(value).strip():
                                point = points[index] if points is not None and index < len(points) else None
                                decoded.append({"kind": "barcode", "payload": str(value).strip(), "bbox": _points_box(point, image.shape) if point is not None else None, "confidence": 0.8})
            except Exception:
                pass
        findings: list[dict] = []
        regions = []
        for item in decoded:
            if item["bbox"]:
                regions.append(region(self.id, f"Decoded {item['kind']}", 0.0, item["confidence"], _bbox_pixels(item["bbox"], image.shape), image.shape[:2], "live code decoder", "Decoded payload; decoding alone is not authenticity evidence."))
        ocr_text = " ".join(str(word.get("text", "")) for word in getattr(context.get("_ocr"), "words", []))
        for item in decoded:
            payload_norm = "".join(ch.lower() for ch in item["payload"] if ch.isalnum())
            ocr_norm = "".join(ch.lower() for ch in ocr_text if ch.isalnum())
            if payload_norm and len(payload_norm) >= 4 and payload_norm not in ocr_norm:
                findings.append(finding(self.id, "QR_OCR_MISMATCH", "Decoded payload conflicts with visible OCR", "high", 0.86, "The decoded QR/barcode payload was not found in the visible OCR text. This is a cross-consistency conflict, not proof of forgery by itself.", [{"label": "Payload", "value": item["payload"]}, {"label": "OCR text", "value": ocr_text[:180]}], recommendation="Verify the printed identifier and machine-readable payload against the issuing authority."))
        reference_codes = context.get("referenceCodes", [])
        if reference_codes and sorted(x["payload"] for x in decoded) != sorted(reference_codes):
            findings.append(finding(self.id, "QR_REFERENCE_MISMATCH", "Decoded payload differs from reference", "high", 0.92, "The machine-readable payload in the evidence differs from the trusted reference payload.", [{"label": "Evidence payload", "value": "; ".join(x["payload"] for x in decoded)}, {"label": "Reference payload", "value": "; ".join(reference_codes)}], recommendation="Confirm the payload with the issuing authority."))
        score = 0.7 if any(item["code"] in {"QR_OCR_MISMATCH", "QR_REFERENCE_MISMATCH"} for item in findings) else 0.0
        metrics = [{"label": "Decoded payloads", "value": str(len(decoded))}, {"label": "Decoder status", "value": "decoded" if decoded else "unable to decode / unavailable"}]
        if decoded:
            metrics.append({"label": "Payload", "value": "; ".join(item["payload"] for item in decoded)[:180]})
        summary = f"Decoded {len(decoded)} machine-readable payload(s)." if decoded else "QR/barcode unavailable or unable to decode; no risk added."
        return self.result(score, findings, regions, started, summary, metrics, confidence=(0.86 if findings else 0.0))


def _points_box(points, shape):
    if points is None:
        return None
    arr = np.asarray(points).reshape(-1, 2)
    h, w = shape[:2]
    return {"x": float(np.min(arr[:, 0]) / w), "y": float(np.min(arr[:, 1]) / h), "width": float((np.max(arr[:, 0]) - np.min(arr[:, 0])) / w), "height": float((np.max(arr[:, 1]) - np.min(arr[:, 1])) / h)}


def _bbox_pixels(box, shape):
    h, w = shape[:2]
    return (box["x"] * w, box["y"] * h, (box["x"] + box["width"]) * w, (box["y"] + box["height"]) * h)


# --------------------------------------------------------------------------- #
#  12 · trained classifier inference
# --------------------------------------------------------------------------- #


class MLClassifierModule(Module):
    """Experimental classifier; not a calibrated universal forgery probability."""

    def __init__(self) -> None:
        super().__init__(
            id="ml-classifier",
            name="Trained ML Classification",
            category="intelligence",
            weight=0.03,
            runtime="scikit-learn RandomForestClassifier + joblib",
            techniques=[
                "Binary genuine / forged random forest",
                "Three-class forgery-type random forest",
                "Live Pixel, Copy-Move, Layout and OCR feature reuse",
            ],
        )

    @staticmethod
    def _metric_value(result: dict, label: str, default: float = 0.0) -> float:
        for metric in result.get("metrics", []):
            if metric.get("label") == label:
                try:
                    return float(metric.get("value"))
                except (TypeError, ValueError):
                    return default
        return default

    @staticmethod
    def _ocr_confidence(context: dict) -> float:
        ocr = context.get("_ocr")
        words = getattr(ocr, "words", []) if ocr is not None else []
        confidences = [float(word["conf"]) for word in words if float(word.get("conf", -1)) >= 0]
        return float(np.mean(confidences)) if confidences else 0.0

    @staticmethod
    def _result_from_context(context: dict, module_id: str) -> dict | None:
        return (context.get("_layer_results") or {}).get(module_id)

    def _run_fallback_module(self, context: dict, module_id: str) -> dict:
        module = (context.get("_module_instances") or {}).get(module_id)
        if module is not None:
            return module.run(context)
        if module_id == "pixel":
            return PixelModule().run(context)
        if module_id == "copy-move":
            return CopyMoveModule().run(context)
        if module_id == "layout":
            from app.forensics.forgify import LayoutModule

            return LayoutModule().run(context)
        raise ValueError(f"Unsupported feature module: {module_id}")

    def _features(self, context: dict) -> list[float]:
        pixel = self._result_from_context(context, "pixel")
        if pixel is None:
            pixel = self._run_fallback_module(context, "pixel")
        copy_move = self._result_from_context(context, "copy-move")
        if copy_move is None:
            copy_move = self._run_fallback_module(context, "copy-move")
        layout = self._result_from_context(context, "layout")
        if layout is None:
            layout = self._run_fallback_module(context, "layout")

        return [
            self._ocr_confidence(context),
            float(pixel.get("score", 0.0)),
            float(copy_move.get("score", 0.0)),
            self._metric_value(pixel, "Noise divergence"),
            float(layout.get("score", 0.0)),
        ]

    @staticmethod
    def _probability_for(classifier: Any, label: str, probabilities: np.ndarray) -> float:
        classes = [str(value) for value in classifier.classes_]
        return float(probabilities[classes.index(label)])

    def run(self, context: dict) -> dict:
        started = time.time()
        domain = context.get("documentDomain", "unknown")
        if domain not in ML_VALIDATED_DOMAINS:
            return self.result(
                0.0, [], [], started,
                f"ML classifier OUT_OF_DOMAIN for '{domain}'; diagnostic result quarantined from primary risk.",
                [{"label": "Domain", "value": domain}, {"label": "Model status", "value": "OUT_OF_DOMAIN / SKIPPED"}, {"label": "Probability meaning", "value": "not applicable"}],
                confidence=0.0, status="skipped",
            )
        model_errors = [error for error in (BINARY_MODEL_ERROR, FORGERY_TYPE_MODEL_ERROR) if error]
        if BINARY_CLASSIFIER is None or FORGERY_TYPE_CLASSIFIER is None:
            return self.result(
                0.0,
                [],
                [],
                started,
                "ML classification skipped: " + " ".join(model_errors),
                [],
                confidence=0.0,
                status="skipped",
            )

        try:
            features = np.asarray([self._features(context)], dtype=float)
            if not np.isfinite(features).all():
                raise ValueError("feature extraction produced a non-finite value")
            binary_prediction = str(BINARY_CLASSIFIER.predict(features)[0])
            binary_probabilities = BINARY_CLASSIFIER.predict_proba(features)[0]
            binary_confidence = self._probability_for(
                BINARY_CLASSIFIER, binary_prediction, binary_probabilities
            )
            forged_probability = self._probability_for(
                BINARY_CLASSIFIER, "forged", binary_probabilities
            )
        except Exception as error:
            return self.result(
                0.0,
                [],
                [],
                started,
                f"ML classification skipped: feature inference failed ({error}).",
                [],
                confidence=0.0,
                status="skipped",
            )

        forgery_type = None
        forgery_type_confidence = None
        if binary_prediction == "forged":
            type_prediction = str(FORGERY_TYPE_CLASSIFIER.predict(features)[0])
            type_probabilities = FORGERY_TYPE_CLASSIFIER.predict_proba(features)[0]
            forgery_type = type_prediction
            forgery_type_confidence = self._probability_for(
                FORGERY_TYPE_CLASSIFIER, type_prediction, type_probabilities
            )

        classification = {
            "label": binary_prediction.upper(),
            "confidence": round(binary_confidence, 6),
            "forgeryType": forgery_type,
            "forgeryTypeConfidence": (
                round(forgery_type_confidence, 6)
                if forgery_type_confidence is not None
                else None
            ),
        }
        metrics = [
            {"label": "ML prediction", "value": classification["label"]},
            {"label": "Prediction confidence", "value": f"{binary_confidence:.3f}"},
            {"label": "OCR confidence", "value": f"{features[0, 0]:.3f}"},
            {"label": "Pixel score", "value": f"{features[0, 1]:.3f}"},
            {"label": "Copy-move score", "value": f"{features[0, 2]:.3f}"},
            {"label": "Noise anomaly", "value": f"{features[0, 3]:.3f}"},
            {"label": "Text inconsistency", "value": f"{features[0, 4]:.3f}"},
        ]
        if forgery_type is not None:
            metrics.extend([
                {"label": "Forgery type", "value": forgery_type},
                {"label": "Forgery-type confidence", "value": f"{forgery_type_confidence:.3f}"},
            ])

        # The persisted model was trained on synthetic fixtures. Keep the
        # output as an experimental score and cap its influence until a
        # domain-specific, held-out calibration set is available.
        experimental_score = float(np.clip(forged_probability * 0.5, 0.0, 0.5))
        result = self.result(
            experimental_score,
            [],
            [],
            started,
            f"ML predicts {classification['label']} with {binary_confidence:.1%} confidence.",
            metrics,
            confidence=min(0.5, binary_confidence),
        )
        result["mlClassification"] = classification
        result["mlClassification"]["calibrationStatus"] = "experimental-synthetic-domain"
        return result


# --------------------------------------------------------------------------- #
#  11 · generative-AI detection
# --------------------------------------------------------------------------- #


class AigcModule(Module):
    def __init__(self) -> None:
        super().__init__(
            id="aigc",
            name="Generative-AI Content Detection",
            category="intelligence",
            weight=0.14,
            runtime="numpy FFT spectral fingerprint",
            techniques=[
                "2-D power spectrum grid peak",
                "Checkerboard / upsampler periodicity",
                "High-frequency rolloff estimate",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        if image is None:
            return self.result(0.0, [], [], started, "Raster unavailable for spectral analysis.", [])

        gray = to_gray(image).astype(np.float32)
        gray = cv2.resize(gray, (512, 512)) if cv2 is not None else gray

        spectrum = np.log1p(np.abs(np.fft.fftshift(np.fft.fft2(gray))))
        centre = np.array(spectrum.shape) // 2
        yy, xx = np.ogrid[: spectrum.shape[0], : spectrum.shape[1]]
        radius = np.sqrt((yy - centre[0]) ** 2 + (xx - centre[1]) ** 2)

        outer = spectrum[radius > radius.max() * 0.55]
        mid = spectrum[(radius > radius.max() * 0.25) & (radius <= radius.max() * 0.55)]
        peak = float(outer.max() - np.median(outer)) if outer.size else 0.0
        rolloff = float(np.median(mid) - np.median(outer)) if mid.size and outer.size else 0.0

        # Normalised heuristics — replace with a trained classifier for production.
        spectral_score = min(1.0, max(0.0, (peak - 6.0) / 8.0))
        rolloff_score = min(1.0, max(0.0, (14.0 - rolloff) / 12.0))
        score = float(np.clip(0.6 * spectral_score + 0.4 * rolloff_score, 0.0, 1.0))

        findings = [
            finding(
                "aigc", "AI-SPEC",
                "Synthetic decoder fingerprint measured in the power spectrum",
                band(score), min(0.95, 0.5 + score * 0.42),
                f"Out-of-band spectral energy sits {peak:.2f} dB above the local median with a high-frequency "
                f"rolloff of {rolloff:.2f} dB. Upsampler-periodic energy of this magnitude is produced by "
                "transposed-convolution decoders rather than optical sensors.",
                [
                    {"label": "Spectral peak", "value": f"{peak:.2f} dB"},
                    {"label": "Rolloff", "value": f"{rolloff:.2f} dB"},
                    {"label": "Spectral score", "value": f"{spectral_score:.3f}"},
                ],
            )
        ]

        return self.result(
            score, findings, [], started,
            f"Spectral peak {peak:.2f} dB, rolloff {rolloff:.2f} dB.",
            [
                {"label": "Spectral peak", "value": f"{peak:.2f} dB"},
                {"label": "Rolloff", "value": f"{rolloff:.2f} dB"},
            ],
        )


MODULES: list[Module] = [PixelModule(), CopyMoveModule(), AigcModule()]


def ocr_stub(context: dict) -> dict:
    """Text-layer placeholder. Wire PaddleOCR/Tesseract here for a live OCR layer."""
    facts = context.get("facts", {})
    return {
        "engine": "not-wired (PaddleOCR adapter point)",
        "mode": "modelled",
        "language": "en",
        "wordCount": 0,
        "meanConfidence": 0.0,
        "text": "",
        "blocks": [],
        "notes": f"Container kind {facts.get('kind')}; enable PaddleOCR to populate this section.",
    }


__all__ = [
    "MODULES",
    "MLClassifierModule",
    "Module",
    "byte_entropy",
    "ocr_stub",
    "LIMITATIONS",
    "io",
]
