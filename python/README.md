# Forgify · Python forensic worker

FastAPI service that implements the detector layers with real NumPy / OpenCV code.
The Next.js runtime forwards `POST /api/analyze` here whenever `FORENSICS_ENGINE_URL`
is configured, and transparently falls back to its TypeScript reference engine if the
worker is unreachable — so a dead worker never produces a broken dashboard.

```
python/
├── app/
│   ├── main.py               # FastAPI app: /health, /layers, POST /analyze
│   └── forensics/
│       ├── container.py      # JPEG/PNG/PDF byte-structure inspection (live)
│       ├── modules.py        # reference layers: pixel (ELA+screenshot), copy-move (SIFT), aigc
│       ├── forgify.py        # Forgify Phase-1/1.2 layers: compression, metadata, layout, semantic
│       └── fusion.py         # weighted opinion pool + logistic calibration
├── tests/                    # pytest contract + integration smoke tests
├── requirements.txt
└── README.md
```

## Run

Use a Python 3.12 interpreter (OpenCV/numpy do not ship stable wheels for 3.14):

```bash
cd python
/opt/homebrew/bin/python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # tesseract binary required too: brew install tesseract
uvicorn app.main:app --port 8000
```

Then point the web app at it:

```bash
# .env (Next.js side)
FORENSICS_ENGINE_URL=http://127.0.0.1:8000
```

Smoke the worker directly:

```bash
cd python
.venv/bin/python -m pytest -q          # contract + clean-vs-tampered integration tests
```

## Contract

The JSON envelope returned by `POST /analyze` is exactly `AnalysisReport` in
`src/lib/forensics/types.ts`. Both backends must keep this shape; the Next.js
bridge validates `verdict.riskScore` and `layers` before accepting a response.
The worker additionally emits the `pipeline` array, `hashes.blurHashFingerprint`
(a 64-bit perceptual hash) and a real OCR block list, so the explore page never
sees an undefined section when running against the FastAPI backend.

| Endpoint       | Purpose                                                        |
| -------------- | -------------------------------------------------------------- |
| `GET /health`  | liveness + registered module ids                               |
| `GET /layers`  | detector registry (weights, runtimes, execution mode)          |
| `POST /analyze`| multipart `file`, optional `reference` → full forensic report  |

## Registered layers

Seven live layers — three independent implementations plus four layers ported
from the Forgify corpus backend (validated there on a 560-document synthetic
corpus; figures below are from that validation, not this worker):

| Layer      | Technique                                             | Origin / benchmark on Forgify corpus                    |
| ---------- | ----------------------------------------------------- | ------------------------------------------------------- |
| `pixel`    | ELA @q90 + Laplacian noise + flat-area residual       | reference; screenshot signature recall 0.90, FPR 0.00   |
| `copy-move`| SIFT + BFMatcher + `estimateAffine2D` RANSAC          | reference                                               |
| `aigc`     | 2-D FFT spectral fingerprint + rolloff                | reference                                               |
| `compression` | PIL luminance DQT quality (re-encode chain band)   | Forgify `compression_forensics`: recompress recall 1.00 |
| `metadata` | EXIF/XMP/PDF self-consistency (per-file/per-format)   | Forgify `metadata`; missing metadata = neutral           |
| `layout`   | Tesseract font-size / baseline / alignment + low-conf | Forgify `layout_consistency` (conservative)             |
| `semantic` | Tesseract arithmetic reconciliation (invoice/marksheet)| Forgify `semantic_consistency`: invoice text_replace recall 0.375, clean FPR 0.00 |

All OCR layers share a single Tesseract pass (`--psm 6`), cached per analysis:
one invocation feeds `layout`, `semantic` and the report's OCR section.

## Adding a real model

1. Create a `Module` subclass in `app/forensics/modules.py` (or `forgify.py`).
2. Implement `run(context)` returning the `LayerResult` dict
   (`score`, `confidence`, `findings[]`, optional `regions[]`).
3. Append it to `ALL_MODULES` in `app/main.py`. Fusion, persistence and the
   whole UI pick it up automatically — no frontend change is required.

## Notes on honesty (per project guide)

- Detector outputs are *evidence*, not proof. `semantic` "consistent" means
  the document's own arithmetic identities hold internally — it never certifies
  authenticity against an issuing authority.
- Missing metadata / missing OCR stays **neutral**, never "suspicious".
- The worker supports JPEG/PNG rasters directly; PDFs currently contribute
  container + metadata evidence (pixel layers degrade to neutral because no
  raster page is decoded).