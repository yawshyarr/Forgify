"""Smoke tests for the Forgify worker with the integrated Forgify layers.

Verifies the FastAPI contract stays byte-compatible with the Next.js bridge
(``src/lib/forensics/types.ts``): every layer returns the ``LayerResult``
shape, the report carries ``pipeline`` + ``blurHashFingerprint`` + OCR blocks,
and the real semantic layer flags a tampered document while staying neutral on
a clean one.
"""

from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.main import app

SAMPLES = Path(__file__).resolve().parent / "samples"
CLEAN = SAMPLES / "invoice_004_clean.jpg"
TAMPERED = SAMPLES / "invoice_004_text_replace.jpg"

client = TestClient(app)


def _module_ids(report):
    return {layer["layer"] for layer in report["layers"]}


def _layer(report, module_id):
    return next(l for l in report["layers"] if l["layer"] == module_id)


def test_health_lists_integrated_modules():
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    assert {"pixel", "copy-move", "aigc", "compression", "metadata", "layout", "semantic"} <= set(body["modules"])


def test_layers_registry_exposes_live_modules():
    res = client.get("/layers")
    assert res.status_code == 200
    ids = {layer["id"] for layer in res.json()["layers"]}
    for expected in ("compression", "metadata", "layout", "semantic", "pixel", "copy-move", "aigc"):
        assert expected in ids


def test_analyze_clean_invoice_contract():
    with open(CLEAN, "rb") as fh:
        res = client.post("/analyze", files={"file": ("invoice_004_clean.jpg", fh, "image/jpeg")})
    assert res.status_code == 200
    report = res.json()
    assert report["ok"] is True
    # bridge-critical fields
    assert report["verdict"]["riskScore"] is not None
    assert isinstance(report["layers"], list)
    assert isinstance(report["pipeline"], list) and len(report["pipeline"]) >= 7
    assert len(report["hashes"]["blurHashFingerprint"]) == 16
    assert isinstance(report["ocr"]["blocks"], list)
    assert set(report["hashes"]) >= {"md5", "sha1", "sha256", "blurHashFingerprint", "byteEntropy"}
    # all fused modules present, none with an empty contract
    for layer in report["layers"]:
        assert layer["layer"] in _module_ids(report)
        assert 0.0 <= layer["score"] <= 1.0

    # clean invoice must NOT flag the semantic layer
    semantic = _layer(report, "semantic")
    assert semantic["score"] < 0.5
    assert not any(f["code"] == "SEM-ARITH" for f in report["findings"])


def test_analyze_tampered_invoice_semantic_alerts():
    with open(TAMPERED, "rb") as fh:
        res = client.post("/analyze", files={"file": ("invoice_004_text_replace.jpg", fh, "image/jpeg")})
    assert res.status_code == 200
    report = res.json()
    assert report["ok"] is True
    semantic = _layer(report, "semantic")
    assert semantic["score"] >= 0.5
    codes = {f["code"] for f in report["findings"]}
    assert "SEM-ARITH" in codes
    # localised region must exist on the tamper
    assert any(r["layer"] == "semantic" for r in report["regions"])


def test_analyze_reference_based_compares_two_exhibits():
    """Reference uploads must not 500 — `UploadFile` exposes `.filename`."""
    with open(CLEAN, "rb") as a, open(TAMPERED, "rb") as b:
        res = client.post(
            "/analyze",
            files={
                "file": ("invoice_004_clean.jpg", a, "image/jpeg"),
                "reference": ("invoice_004_text_replace.jpg", b, "image/jpeg"),
            },
        )
    assert res.status_code == 200
    report = res.json()
    assert report["ok"] is True
    ref = report["reference"]
    assert ref["mode"] == "reference-based"
    assert ref["candidateLabel"] == "invoice_004_text_replace.jpg"
    assert ref["deltaNotes"], "expected at least one delta note between the two exhibits"
    assert "metadata" in ref["comparedLayers"]


def test_analyze_screenshot_signature_path_does_not_crash():
    """Regression: the pixel module appended the PX-SMOOTH metric to a `metrics`
    list it only declared *after* the branch, so any image whose flat-area
    residual landed in the >=0.25 band raised UnboundLocalError and 500'd the
    whole request. Screen captures and rescaled documents hit that band."""
    from PIL import Image as PILImage
    import numpy as _np

    from app.forensics.modules import screenshot_signature, to_array

    # A low-noise gradient that has been through a JPEG encode: the encoder's
    # ringing lands in otherwise-flat areas and pushes the flat-area residual
    # into the band where PX-SMOOTH is emitted.
    yy, xx = _np.mgrid[0:520, 0:760].astype(_np.float32)
    arr = _np.stack([230 + xx * 0.016, 232 + yy * 0.019, 236 + xx * 0.004], axis=-1)
    arr += _np.random.default_rng(0).normal(0, 1.1, arr.shape)
    buf = __import__("io").BytesIO()
    PILImage.fromarray(_np.clip(arr, 0, 255).astype(_np.uint8)).save(buf, format="JPEG", quality=95)
    payload = buf.getvalue()

    smooth = screenshot_signature(to_array(payload))
    assert smooth >= 0.25, f"fixture must reach the PX-SMOOTH band (got {smooth:.3f})"

    res = client.post("/analyze", files={"file": ("rescaled.jpg", payload, "image/jpeg")})
    assert res.status_code == 200, "PX-SMOOTH band must not raise"
    report = res.json()
    assert report["ok"] is True
    pixel = _layer(report, "pixel")
    assert any(f["code"] == "PX-SMOOTH" for f in pixel["findings"])
    labels = {m["label"] for m in pixel["metrics"]}
    assert "Flat-area residual" in labels
    assert "ELA median" in labels, "the ELA metrics must survive the PX-SMOOTH branch"


def test_analyze_non_image_stays_neutral():
    junk = np.random.default_rng(0).bytes(4096)
    res = client.post("/analyze", files={"file": ("junk.bin", junk, "application/octet-stream")})
    assert res.status_code == 200
    report = res.json()
    assert report["ok"] is True
    assert all(layer["status"] != "alert" for layer in report["layers"])


def test_analyze_png_clean():
    buf = __import__("io").BytesIO()
    np.random.default_rng(1)
    from PIL import Image

    img = Image.fromarray(np.zeros((80, 120, 3), dtype=np.uint8))
    img.save(buf, format="PNG")
    res = client.post("/analyze", files={"file": ("blank.png", buf.getvalue(), "image/png")})
    assert res.status_code == 200
    assert res.json()["ok"] is True