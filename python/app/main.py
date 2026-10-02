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

import asyncio
import hashlib
import os
import time
from urllib.error import URLError
from urllib.request import urlopen

import numpy as np
from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.forensics import container, fusion, forgify, modules
from app.forensics.deep_tamper import DeepTamperSRMModule
from app.forensics.forgify import tesseract_words
from app.forensics.reference import compare_pair, reference_id
from app.forensics.identity import analyze_identity
from app.forensics.regions import aggregate_regions

app = FastAPI(title="Forgify Forensic Worker", version="2.5.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ENGINE = {"name": "Forgify Forensic Engine", "version": "2.5.0", "backend": "python-fastapi"}

ALL_MODULES = list(modules.MODULES) + list(forgify.MODULES) + [modules.QRBarcodeModule(), DeepTamperSRMModule(), modules.MLClassifierModule()]


def _engine_health_url() -> str:
    engine_url = os.getenv("FORENSICS_ENGINE_URL", "http://127.0.0.1:8000").strip()
    return f"{engine_url.rstrip('/')}/health"


def _ping_engine_health(health_url: str) -> tuple[bool, str]:
    try:
        with urlopen(health_url, timeout=3) as response:  # nosec B310 - local/configured health endpoint
            if response.status == 200:
                return True, "reachable"
            return False, f"HTTP {response.status}"
    except (OSError, URLError) as error:
        return False, str(error)


async def _log_engine_health() -> None:
    # Uvicorn binds its socket after FastAPI startup events; let it become ready
    # before a worker that points at itself checks /health.
    await asyncio.sleep(0.25)
    health_url = _engine_health_url()
    reachable, detail = await asyncio.to_thread(_ping_engine_health, health_url)
    if reachable:
        print(f"FORENSICS ENGINE READY: {health_url}", flush=True)
        return
    banner = "!" * 76
    print(banner, flush=True)
    print(f"FORENSICS ENGINE WARNING: {health_url} is unreachable ({detail}).", flush=True)
    print("The frontend will fall back to the TypeScript reference engine.", flush=True)
    print(banner, flush=True)


@app.on_event("startup")
async def log_engine_health_on_startup() -> None:
    asyncio.create_task(_log_engine_health())


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


def _reference_layer(pair: dict, identity_findings: list[dict]) -> dict:
    """Adapt existing paired-comparison output into one fusion LayerResult."""
    aligned = bool(pair.get("aligned"))
    alignment = float(pair.get("alignmentConfidence", 0.0))
    structural = float(pair.get("structuralDifference", 0.0))
    changed = pair.get("changedRegions", [])
    direct = [item for item in identity_findings if item.get("type") in {"OCR_FIELD_MISMATCH", "OCR_FIELD_ADDED", "OCR_FIELD_REMOVED", "REF-FIELD"}]
    qr_mismatch = any(item.get("type") == "QR_BARCODE_MISMATCH" for item in identity_findings)
    stable = [item for item in changed if item.get("stable") is True or item.get("stableAcrossQualities") is True]
    # Direct paired evidence is stronger than a global image residual, but is
    # still discounted when alignment is weak. This is an adapter score only;
    # compare_pair() remains the source of all measurements.
    direct_score = 0.86 if direct else 0.92 if qr_mismatch else 0.0
    region_score = max((float(item.get("score", 0.0)) for item in changed), default=0.0)
    if direct or qr_mismatch:
        evidence_score = max(structural, region_score, direct_score)
        evidence_tier = "direct-comparative"
    elif stable:
        evidence_score = max(structural, region_score)
        evidence_tier = "localized-supporting"
    else:
        # A broad image/reference difference is compatible with exposure,
        # contrast, resize, and JPEG changes. Keep the measured score visible,
        # but do not promote an unstable global residual to direct evidence.
        evidence_score = min(structural, 0.28)
        evidence_tier = "global-supporting"
    score = min(1.0, evidence_score * alignment) if aligned else 0.0
    confidence = min(0.98, alignment * (0.72 + 0.12 * bool(direct or qr_mismatch)))
    metrics = [
        {"label": "Alignment confidence", "value": f"{alignment:.3f}"},
        {"label": "Structural difference", "value": f"{structural:.3f}"},
        {"label": "Changed regions", "value": str(len(changed))},
        {"label": "Stable changed regions", "value": str(len(stable))},
        {"label": "Direct field/code disagreements", "value": str(len(direct) + int(qr_mismatch))},
        {"label": "Evidence tier", "value": evidence_tier},
    ]
    findings = [{
        "id": "F-REF-COMPARE", "layer": "reference", "code": "REF-COMPARE",
        "title": "Trusted-reference comparison evidence", "severity": "high" if direct or qr_mismatch else "medium",
        "confidence": round(confidence, 3),
        "description": "Existing aligned reference comparison produced direct comparative evidence." if direct or qr_mismatch else "Existing aligned reference comparison produced structural difference evidence.",
        "evidence": [{"label": "Alignment", "value": f"{alignment:.3f}"}, {"label": "Structural difference", "value": f"{structural:.3f}"}, {"label": "Changed regions", "value": str(len(changed))}],
    }]
    return {
        "layer": "reference", "name": "Trusted Reference Comparison", "category": "manipulation",
        "weight": 0.24, "score": round(score, 4), "confidence": round(confidence, 3),
        "status": "alert" if score >= 0.5 else "review" if score >= 0.28 else "pass",
        "mode": "live", "runtime": "existing aligned reference comparison", "durationMs": 0,
        "summary": f"Aligned={aligned}; {len(changed)} changed region(s), {len(stable)} stable; {len(direct)} direct field disagreement(s); tier={evidence_tier}.",
        "techniques": ["perspective normalization", "ECC alignment", "absolute pixel difference", "structural comparison", "OCR/reference comparison", "QR comparison"],
        "findings": findings, "metrics": metrics, "regions": [],
    }


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
    ocr_text = " ".join(w["text"].lower() for w in ocr.words)
    if any(token in ocr_text for token in ("identity", "reg.no", "student's", "student’s", "student id")):
        document_domain = "identity-card"
    elif any(token in ocr_text for token in ("invoice", "gst", "subtotal", "tax")):
        document_domain = "invoice"
    elif any(token in ocr_text for token in ("marksheet", "marks", "semester", "grade")):
        document_domain = "marksheet"
    elif any(token in ocr_text for token in ("certificate", "certify", "degree")):
        document_domain = "certificate"
    else:
        document_domain = "general"

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
        "_module_instances": {module.id: module for module in ALL_MODULES},
        "_layer_results": {},
        "documentDomain": document_domain,
    }

    reference_facts = {"mode": "reference-free", "deltaNotes": [], "comparedLayers": []}
    reference_context = None
    if reference is not None:
        ref_payload = await reference.read()
        if ref_payload:
            ref_facts = container.inspect(ref_payload, reference.content_type or "", reference.filename or "reference")
            ref_image = modules.to_array(ref_payload)
            ref_ocr = tesseract_words(ref_image)
            reference_context = {"bytes": ref_payload, "facts": ref_facts, "image": ref_image, "ocr": ref_ocr}
            reference_facts = {
                "mode": "reference-based",
                "candidateId": reference_id(ref_payload),
                "candidateLabel": reference.filename,
                "deltaNotes": container.compare(facts, ref_facts, len(payload), len(ref_payload)),
                "comparedLayers": ["metadata", "compression", "pixel", "layout", "ocr", "qr-barcode"],
            }
    context["reference"] = reference_facts
    identity_analysis = analyze_identity(
        image,
        ocr,
        reference_context["image"] if reference_context else None,
        reference_context["ocr"] if reference_context else None,
    )
    context["referenceCodes"] = identity_analysis.get("referenceCodes", [])

    # ---- 5. per-layer analysis -----------------------------------------------
    layer_results = []
    for module in ALL_MODULES:
        layer_result = module.run(context)
        layer_results.append(layer_result)
        context["_layer_results"][module.id] = layer_result

    layout_layer = next((layer for layer in layer_results if layer["layer"] == "layout"), None)
    if layout_layer is not None:
        for finding_data in identity_analysis["fieldFindings"]:
            if finding_data.get("comparisonState") == "UNRELIABLE_OCR":
                # Preserve the detail in identityFindings, but do not turn an
                # OCR artifact into a fusion finding.
                continue
            layout_layer["findings"].append(modules.finding(
                "layout", finding_data["type"], f"Identity field comparison: {finding_data['fieldType']}",
                "high" if finding_data["type"] in {"OCR_FIELD_MISMATCH", "QR_BARCODE_MISMATCH"} else "medium",
                finding_data["confidence"],
                f"Reference {finding_data['fieldType']}: {finding_data.get('referenceText') or 'absent'}; evidence {finding_data['fieldType']}: {finding_data.get('evidenceText') or 'absent'}. This is comparison evidence and not standalone proof of forgery.",
                [{"label": "Reference", "value": str(finding_data.get("referenceText") or "absent")}, {"label": "Evidence", "value": str(finding_data.get("evidenceText") or "absent")}, {"label": "Type", "value": finding_data["type"]}],
                recommendation="Verify the changed field against the issuing authority or chain-of-custody record.",
            ))

    # Reference evidence is deliberately attached to existing report fields so
    # the AnalysisReport contract remains unchanged. It is not folded into a
    # forged verdict unless the caller supplied a trusted reference.
    pair = None
    if reference_context is not None:
        pair = compare_pair(
            {"image": image, "ocr": ocr},
            {"image": reference_context["image"], "ocr": reference_context["ocr"]},
        )
        reference_facts["deltaNotes"].extend(pair["notes"][:20])
        reference_facts["aligned"] = pair["aligned"]
        reference_facts["pixelComparison"] = pair.get("pixel", {})
        reference_facts["textDifferences"] = pair.get("textDifferences", [])
        reference_facts["fieldDifferences"] = pair.get("fieldDifferences", [])
        reference_facts["qrComparison"] = pair.get("qr", {})
        visual_fields = {item.get("field") for item in pair.get("fieldDifferences", [])}
        for finding_data in identity_analysis["fieldFindings"]:
            if finding_data.get("fieldType") in visual_fields and finding_data.get("comparisonState") in {"MISMATCH", "LIKELY_MISMATCH"}:
                finding_data["visualCorroboration"] = True
                finding_data["evidence"].append("aligned reference field comparison corroborates the OCR difference")
                finding_data["confidence"] = round(min(0.98, float(finding_data.get("confidence", 0.0)) + 0.06), 3)

        layout_layer = next((layer for layer in layer_results if layer["layer"] == "layout"), None)
        if layout_layer is not None:
            field_count = len(pair.get("fieldDifferences", []))
            if field_count:
                # Trusted-reference field disagreement is evidence of change,
                # not proof of forgery. Keep it in the existing content layer
                # so the public report contract and frontend remain stable.
                layout_layer["score"] = max(layout_layer["score"], min(0.85, 0.45 + field_count * 0.1))
                layout_layer["status"] = "alert" if layout_layer["score"] >= 0.5 else "review"
                layout_layer["confidence"] = max(layout_layer["confidence"], 0.8)
            for difference in pair.get("fieldDifferences", []):
                layout_layer["findings"].append(modules.finding(
                    "layout", "REF-FIELD", f"Identity field differs: {difference['field']}", "high", 0.9,
                    f"The trusted reference and exhibit disagree on the '{difference['field']}' field. This is direct change evidence; it does not independently establish which version is authentic.",
                    [{"label": "Exhibit value", "value": difference["primary"]}, {"label": "Reference value", "value": difference["reference"]}],
                    recommendation="Verify this field against the issuing institution or original acquisition record.",
                ))
            for index, difference in enumerate(pair.get("textDifferences", [])[:20], start=1):
                box = difference["box"]
                ref_region = {
                    "id": "",
                    "label": "Reference text difference",
                    "layer": "layout",
                    "score": 0.8,
                    "confidence": 0.75,
                    **box,
                    "technique": "aligned OCR reference comparison",
                    "notes": f"Exhibit '{difference['primary']}' vs reference '{difference['reference']}'.",
                }
                layout_layer["regions"].append(ref_region)
                layout_layer["findings"].append(modules.finding(
                    "layout", "REF-TEXT", "Text differs from trusted reference",
                    "high", 0.82,
                    f"Aligned OCR found a field-level token difference: exhibit '{difference['primary']}' versus reference '{difference['reference']}'. This identifies a change; it does not independently establish which version is authentic.",
                    [{"label": "Exhibit text", "value": difference["primary"]}, {"label": "Reference text", "value": difference["reference"]}],
                    ref_region,
                    recommendation="Verify the changed field against the issuing institution or original acquisition record.",
                ))
        qr = pair.get("qr", {})
        if qr.get("status") == "decoded" and qr.get("match") is False:
            all_qr = next((layer for layer in layer_results if layer["layer"] == "layout"), None)
            if all_qr is not None:
                all_qr["findings"].append(modules.finding(
                    "layout", "REF-QR", "Decoded QR payload differs from trusted reference", "critical", 0.95,
                    "The QR payloads decoded from the exhibit and trusted reference are different. Payload mismatch is direct reference evidence, but the issuing authority must still be consulted.",
                    [{"label": "Exhibit payload", "value": "; ".join(qr.get("primary", []))}, {"label": "Reference payload", "value": "; ".join(qr.get("reference", []))}],
                ))
        # Promote the existing paired comparison into a real layer before
        # flattening findings and calling fusion. No comparison is re-run.
        layer_results.append(_reference_layer(pair, identity_analysis["fieldFindings"]))
        context["_layer_results"]["reference"] = layer_results[-1]
    _step("analyze",
          f"Run {len(ALL_MODULES)}-layer analysis",
          f"{len([l for l in layer_results if l['status'] != 'skipped'])} detector(s) executed, "
          f"{len([l for l in layer_results if l['status'] == 'alert'])} returned an alert")

    all_findings = [f for layer in layer_results for f in layer["findings"]]
    regions = [r for layer in layer_results for r in layer.get("regions", [])]
    # Reference comparison is a first-class local detector.  Keep it separate
    # from the raw layout regions until aggregation so it can be merged with
    # SRM/ELA/portrait/field observations at the same physical coordinates.
    if pair is not None:
        for difference in pair.get("changedRegions", []):
            box = difference.get("bbox", difference.get("box", {}))
            if box:
                regions.append({
                    "label": "Aligned reference difference", "layer": "reference",
                    "detector": "reference", "score": float(difference.get("score", 0.75)),
                    "confidence": float(difference.get("confidence", 0.82)), **box,
                    "technique": "aligned reference comparison",
                    "notes": str(difference.get("changeType", "local structural difference")),
                })
    for index, region in enumerate(regions, start=1):
        region["id"] = f"R-{index:02d}"
    unified_regions, region_findings = aggregate_regions(
        regions, identity_analysis.get("fields", []), identity_analysis.get("fieldFindings", [])
    )
    _step("regions", "Localise anomalies",
          f"{len(unified_regions)} merged region(s) from {len(regions)} detector observation(s) mapped")

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
    ml_layer = next((layer for layer in layer_results if layer["layer"] == "ml-classifier"), None)
    ml_classification = ml_layer.get("mlClassification") if ml_layer else None

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
        "mlClassification": ml_classification,
        "layers": layer_results,
        "findings": all_findings,
        "regions": regions,
        "unifiedRegions": unified_regions,
        "regionFindings": region_findings,
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
        "referenceComparison": pair if pair is not None else None,
        "identityFields": identity_analysis["fields"],
        "identityFieldComparisons": identity_analysis.get("fieldComparisons", []),
        "identityFindings": identity_analysis["fieldFindings"],
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
