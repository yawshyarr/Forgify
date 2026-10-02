"""Conservative multi-scale SRM residual support layer."""
from __future__ import annotations
import base64
import time
import numpy as np
from .modules import Module, finding, region, to_gray
try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None


def _srm_kernels():
    base = np.array([[0, 0, 0], [0, -1, 1], [0, 0, 0]], dtype=np.float32)
    return [base, base.T, np.rot90(base), np.rot90(base, 3),
            np.array([[0, -1, 0], [-1, 4, -1], [0, -1, 0]], dtype=np.float32) / 4,
            np.array([[-1, 0, 1], [0, 0, 0], [1, 0, -1]], dtype=np.float32) / 2]


def _expected_mask(context, shape):
    h, w = shape
    mask = np.zeros((h, w), dtype=np.uint8)
    for word in getattr(context.get("_ocr"), "words", []) or []:
        x0 = max(0, int(word["left"] - word["width"] * .4)); y0 = max(0, int(word["top"] - word["height"] * .6))
        x1 = min(w, int(word["left"] + word["width"] * 1.4)); y1 = min(h, int(word["top"] + word["height"] * 1.6))
        mask[y0:y1, x0:x1] = 1
    gray = to_gray(context.get("image"))
    if gray is not None:
        density = cv2.blur((cv2.Canny(gray.astype(np.uint8), 80, 180) > 0).astype(np.float32), (31, 31))
        mask[density > .42] = 1
    return mask


class DeepTamperSRMModule(Module):
    def __init__(self):
        super().__init__(id="deep-tamper-srm", name="Multi-scale Residual Localization", category="manipulation", weight=0.12, runtime="cv2 fixed SRM residual bank + multi-scale stable hotspot analysis", techniques=["Multi-scale SRM residual heatmap", "Expected-structure suppression", "Stable hotspot clustering", "OCR field mapping"])

    def run(self, context):
        started = time.time(); image = context.get("image"); gray = to_gray(image)
        if cv2 is None or gray is None or min(gray.shape[:2]) < 64:
            return self.result(0.0, [], [], started, "SRM layer skipped: no suitable raster image was decoded.", [], confidence=0.0, status="skipped")
        oh, ow = gray.shape[:2]; limit = min(1200.0 / max(oh, ow), 1.0)
        base = cv2.resize(gray.astype(np.float32), (max(64, int(ow * limit)), max(64, int(oh * limit))), interpolation=cv2.INTER_AREA)
        maps = []
        for factor in (.75, 1.0, 1.25):
            work = cv2.resize(base, None, fx=factor, fy=factor, interpolation=cv2.INTER_AREA)
            residual = np.mean([np.abs(cv2.filter2D(work, cv2.CV_32F, k, borderType=cv2.BORDER_REFLECT)) for k in _srm_kernels()], axis=0)
            residual = cv2.resize(residual, (base.shape[1], base.shape[0]), interpolation=cv2.INTER_AREA)
            texture = cv2.resize(np.abs(cv2.Laplacian(work, cv2.CV_32F)), (base.shape[1], base.shape[0]), interpolation=cv2.INTER_AREA)
            maps.append(residual / (1.0 + cv2.GaussianBlur(texture, (0, 0), 3)))
        stack = np.stack(maps); med = np.median(stack, axis=(1, 2), keepdims=True); mad = np.median(np.abs(stack - med), axis=(1, 2), keepdims=True) + 1e-3
        normalized = np.clip((stack - med) / (6.0 * mad), 0, 1); stability = np.mean(normalized > .65, axis=0)
        expected = cv2.resize(_expected_mask(context, (oh, ow)), (base.shape[1], base.shape[0]), interpolation=cv2.INTER_NEAREST) > 0
        border = max(2, int(min(base.shape) * .02)); expected[:border] = expected[-border:] = True; expected[:, :border] = expected[:, -border:] = True
        composite = np.median(normalized, axis=0) * stability; composite[expected] = 0
        valid = composite[~expected]; magnitude = float(np.percentile(valid, 95)) if valid.size else 0.0; area = float(np.mean((stability >= 2 / 3)[~expected])) if valid.size else 0.0
        localization = float(np.clip(1.0 - max(0.0, area - .04) / .18, 0, 1)); score = float(np.clip((.55 * magnitude + .25 * float(np.mean(stability[~expected])) + .20 * localization) * localization, 0, .65))
        hot = ((stability >= 2 / 3) & (composite > .38) & ~expected).astype(np.uint8); hot = cv2.morphologyEx(hot, cv2.MORPH_OPEN, np.ones((5, 5), np.uint8))
        count, labels, stats, _ = cv2.connectedComponentsWithStats(hot, 8); regions = []
        for i in range(1, count):
            x, y, rw, rh, pixels = stats[i]
            if pixels < max(30, hot.size // 5000): continue
            local = float(np.mean(composite[labels == i])); box = (x / limit, y / limit, (x + rw) / limit, (y + rh) / limit)
            mapped = []
            for word in getattr(context.get("_ocr"), "words", []) or []:
                wx, wy = word["left"] / ow, word["top"] / oh
                if box[0] / ow <= wx <= box[2] / ow and box[1] / oh <= wy <= box[3] / oh:
                    mapped.append(str(word.get("text", "")))
            note = "Persisted across at least two scales after expected high-frequency suppression."
            if mapped:
                note += " Overlaps OCR field/text: " + " ".join(mapped[:8]) + "."
            regions.append(region(self.id, "Stable SRM residual hotspot", local, .5 + .4 * float(np.mean(stability[labels == i])), box, (oh, ow), "multi-scale SRM heatmap", note))
        regions = sorted(regions, key=lambda item: item["score"], reverse=True)[:8]
        corroborated = any(float(layer.get("score", 0)) >= .55 for layer in (context.get("_layer_results") or {}).values() if layer.get("layer") != self.id)
        findings = []
        if regions:
            severity = "high" if corroborated else "medium"
            findings.append(finding(self.id, "SRM-LOCAL", "Stable residual hotspot requiring corroboration", severity, min(.88, .55 + float(np.mean(stability)) * .3), "Multi-scale SRM activity remains after suppressing OCR and dense expected structures. SRM is supporting evidence only and is not a standalone forgery conclusion.", [{"label": "Anomaly magnitude", "value": f"{magnitude:.3f}"}, {"label": "Stable hotspot area", "value": f"{area:.4f}"}, {"label": "Corroborated by another layer", "value": str(corroborated)}], regions[0], recommendation="Corroborate with reference field comparison, OCR mismatch, QR/barcode mismatch, or issuer records."))
        heat = cv2.applyColorMap(np.uint8(np.clip(composite * 255, 0, 255)), cv2.COLORMAP_JET); ok, encoded = cv2.imencode(".jpg", heat, [int(cv2.IMWRITE_JPEG_QUALITY), 85]); heatmap = f"data:image/jpeg;base64,{base64.b64encode(encoded).decode('ascii')}" if ok else None
        metrics = [{"label": "Scales", "value": "0.75x/1.0x/1.25x"}, {"label": "Anomaly magnitude", "value": f"{magnitude:.3f}"}, {"label": "Stable hotspot area", "value": f"{area:.4f}"}, {"label": "Hotspot stability", "value": f"{float(np.mean(stability[~expected])):.3f}"}, {"label": "Expected pixels suppressed", "value": f"{float(np.mean(expected)):.3f}"}, {"label": "Corroborated", "value": str(corroborated)}]
        output = self.result(score, findings, regions, started, f"SRM found {len(regions)} stable hotspot(s); residuals are supporting evidence only.", metrics, confidence=min(.86, .45 + float(np.mean(stability[~expected])) * .35)); output["heatmap"] = heatmap; output["srmEvidence"] = {"scales": [.75, 1.0, 1.25], "anomalyMagnitude": magnitude, "stableHotspotArea": area, "corroborated": corroborated}; return output


__all__ = ["DeepTamperSRMModule"]
