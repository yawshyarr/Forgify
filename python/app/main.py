"""
Forgify · Forensic inference worker
=======================================
FastAPI service that runs the *real* OpenCV / numpy implementations of the
detector layers. The Next.js runtime forwards ``POST /api/analyze`` here when
the ``FORENSICS_ENGINE_URL`` environment variable is set, and falls back to its
TypeScript reference engine when this worker is unreachable.

    uvicorn app.main:app --host 127.0.0.1 --port 8000

Contract (must stay byte-compatible with ``src/lib/forensics/types.ts``)::

    GET  /health   -> {"ok": true, "modules": [...]}
    GET  /layers   -> detector registry
    POST /analyze  -> multipart {file, reference?} -> AnalysisReport JSON

Module registration
-------------------
Forgify Phase-1/1.2 detectors (compression, metadata, layout, semantic) are
registered as additional Sentinel modules alongside the three reference
implementations. All share one Tesseract pass so the *``ocr``* section of the
report, *layout*, and *semantic* layers reuse the same word-level data.
"""

from __future__ import annotations

import hashlib
import time

import numpy as np
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.forensics import container, fusion, forgify, modules
from app.forensics.forgify import tesseract_words

app = FastAPI(title="Forgify Forensic Worker", version="2.5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ENGINE = {"name": "Forgify Forensic Engine", "version": "2.5.0", "backend": "python-fastapi"}

ALL_MODULES = list(modules.MODULES) + list(forgify.MODULES)


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #

def _perceptual_fingerprint(image) -> str:
    """64-bit mean-average-hash (8×8 → 64-bit hex string).  Not a true
    BlurHash, but serves as a stable content fingerprint in the report's
    ``hashes.blurHashFingerprint`` field when no dedicated library is wired."""
    if image is None:
        return "0" * 16
    gray = modules.to_gray(image)
    if gray is None:
        return "0" * 16
    try:
        import cv2
        small = cv2.resize(gray, (8, 8), interpolation=cv2.INTER_AREA)
    except Exception:
        return "0" * 16
    flat = small.astype(np.float64).flatten()
    mean = float(flat.mean())
    bits = int("".join("1" if b.item() else "0" for b in (flat > mean)), 2)
    return format(bits, "016x")


def _hashes(payload: bytes, image) -> dict:
    return {
        "md5": hashlib.md5(payload).hexdigest(),
        "sha1": hashlib.sha1(payload).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "blurHashFingerprint": _perceptual_fingerprint(image),
        "byteEntropy": round(float(modules.byte_entropy(payload)), 3),
    }


def _ocr_blocks(words: list[dict], shape) -> list[dict]:
    """Convert Tesseract word list into the OcrBlock shape expected by the
    frontend (``index, text, box{0..1}, confidence, anomalies``)."""
    height, width = shape[:2] if shape else (1e4, 1e4)
    out = []
    for i, w in enumerate(words):
        if w["conf"] < 0:
            continue
        out.append({
            "index": i,
            "text": w["text"],
            "box": {"x": round(w["left"] / width, 4), "y": round(w["top"] / height, 4),
                    "width": round(w["width"] / width, 4), "height": round(w["height"] / height, 4)},
            "confidence": round(w["conf"] / 100.0, 3),
            "anomalies": ["low-confidence"] if w["conf"] < 40 else [],
        })
    return out


# --------------------------------------------------------------------------- #
#  routes
# --------------------------------------------------------------------------- #

@app.get("/health")
def health() -> dict:
    return {"ok": True, "modules": [m.id for m in ALL_MODULES], **ENGINE}


@app.get("/layers")
def layers() -> dict:
    return {
        "ok": True,
        "engine": ENGINE,
        "layers": [
            {
                "id": m.id,
                "name": m.name,
                "category": m.category,
                "weight": m.weight,
                "runtime": m.runtime,
                "executionMode": "live",
                "techniques": m.techniques,
            }
            for m in ALL_MODULES
        ],
    }


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    reference: UploadFile | None = File(default=None),
) -> dict:
    t_start = time.time()
    pipeline: list[dict] = []
    step_start = time.time()

    def _step(key: str, label: str, detail: str, status: str = "ok"):
        nonlocal step_start
        pipeline.append({
            "step": len(pipeline) + 1, "key": key, "label": label,
            "detail": detail, "status": status,
            "durationMs": int((time.time() - step_start) * 1000),
        })
        step_start = time.time()

    # ---- 1. upload & intake ---------------------------------------------------
    payload = await file.read()
    if not payload:
        return {"ok": False, "error": "empty upload"}
    _step("upload", "Upload & intake",
          f"{file.filename} · {len(payload):,} bytes received over multipart POST")

    # ---- 2. validate & container extraction ------------------------------------
    facts = container.inspect(payload, file.content_type or "", file.filename or "evidence")
    _step("validate", "Validate & hash",
          f"SHA-256 {hashlib.sha256(payload).hexdigest()[:24]}… · "
          f"container resolved as {facts['detectedType']}"
          f"{(' (MIME mismatch)' if facts.get('typeMismatch') else '')}",
          status="warn" if facts.get("typeMismatch") else "ok")

    # ---- 3. decode + OCR (single pass) ----------------------------------------
    image = modules.to_array(payload)
    ocr = tesseract_words(image)

    def _ocr_detail():
        return f"{len(ocr.words)} OCR word(s) recovered" if ocr.words else "OCR unavailable"

    _step("extract", "Extract evidence", _ocr_detail())

    # ---- 4. metadata + container facts ---------------------------------------
    # (folds into the existing context; the layer modules read context["bytes"])
    context = {
        "bytes": payload,
        "seed": int.from_bytes(hashlib.sha256(payload).digest()[:4], "big"),
        "facts": facts,
        "name": file.filename or "evidence",
        "mime": file.content_type or "application/octet-stream",
        "image": image,
        "_ocr": ocr,
    }

    reference_facts = {"mode": "reference-free", "deltaNotes": [], "comparedLayers": []}
    if reference is not None:
        ref_payload = await reference.read()
        if ref_payload:
            ref_facts = container.inspect(ref_payload, reference.content_type or "", reference.filename or "reference")
            reference_facts = {
                "mode": "reference-based",
                "candidateId": hashlib.sha256(ref_payload).hexdigest()[:16],
                "candidateLabel": reference.filename,
                "deltaNotes": container.compare(facts, ref_facts, len(payload), len(ref_payload)),
                "comparedLayers": ["metadata", "compression", "pixel", "layout"],
            }
    context["reference"] = reference_facts

    # ---- 5. per-layer analysis -----------------------------------------------
    layer_results = [m.run(context) for m in ALL_MODULES]
    _step("analyze",
          f"Run {len(ALL_MODULES)}-layer analysis",
          f"{len([l for l in layer_results if l['status'] != 'skipped'])} detector(s) executed, "
          f"{len([l for l in layer_results if l['status'] == 'alert'])} returned an alert")

    all_findings = [f for layer in layer_results for f in layer["findings"]]
    regions = [r for layer in layer_results for r in layer.get("regions", [])]
    for index, region in enumerate(regions, start=1):
        region["id"] = f"R-{index:02d}"
    _step("regions", "Localise anomalies",
          f"{len(regions)} localised region(s) mapped")

    # ---- 6. cross-check + fusion ---------------------------------------------
    fused = fusion.fuse(layer_results, all_findings)
    _step("fuse", "Fuse evidence", fused["method"])
    _step("risk", "Risk scoring",
          f"Risk {fused['riskScore']}/100 · confidence {round(fused['confidence'] * 100)}%")
    _step("explain", "Explainable report",
          f"{len(all_findings)} finding(s) rendered with evidence, metric and recommendation")

    # ---- 7. OCR section (populated from the shared Tesseract pass) -----------
    ocr_section = {
        "engine": "tesseract (Forgify integration)",
        "mode": "live",
        "language": "en",
        "wordCount": len(ocr.words) if ocr.words else 0,
        "meanConfidence": round(
            sum(w["conf"] for w in ocr.words if w["conf"] >= 0) /
            max(1, len([w for w in ocr.words if w["conf"] >= 0])), 3
        ) if ocr.words else 0.0,
        "text": " ".join(w["text"] for w in ocr.words) if ocr.words else "",
        "blocks": _ocr_blocks(ocr.words, image.shape) if ocr.words and image is not None else [],
    }

    # ---- 8. report envelope ---------------------------------------------------
    report = {
        "ok": True,
        "id": "",
        "caseCode": fusion.case_code(int.from_bytes(hashlib.sha256(payload).digest()[:4], "big")),
        "createdAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "durationMs": int((time.time() - t_start) * 1000),
        "engine": {**ENGINE,
                   "modulesRegistered": len(ALL_MODULES),
                   "modulesExecuted": len([l for l in layer_results if l["status"] != "skipped"])},
        "file": {
            "name": file.filename or "evidence",
            "extension": (file.filename or "evidence.bin").split(".")[-1].lower(),
            "mimeType": file.content_type or "application/octet-stream",
            "sizeBytes": len(payload),
            "kind": facts["kind"],
            "dimensions": f"{facts.get('width')} × {facts.get('height')} px"
            if facts.get("width") else None,
        },
        "hashes": _hashes(payload, image),
        "container": facts,
        "metadata": facts.get("entries", []),
        "ocr": ocr_section,
        "layers": layer_results,
        "findings": all_findings,
        "regions": regions,
        "fusion": fused,
        "verdict": {
            "label": fusion.verdict_for(fused["riskScore"]),
            "riskScore": fused["riskScore"],
            "confidence": fused["confidence"],
            "recommendation": fusion.recommendation(fused["riskScore"]),
            "chainOfCustody": "Exhibit hashed before processing; opened read-only; no bytes mutated.",
        },
        "pipeline": pipeline,
        "reference": reference_facts,
        "limitations": modules.LIMITATIONS + [
            "Semantic, layout and metadata layers are ported from the Forgify corpus project "
            "(Phase 1 / 1.2) and were validated on a synthetic document corpus: real-world "
            "documents may differ significantly.",
            "A 'consistent' semantic result proves that arithmetic identities hold internally; "
            "it does not certify the document's authenticity against the issuing authority.",
        ],
    }
    return report


__all__ = ["app", "np"]