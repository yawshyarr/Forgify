# Forgify — AI Digital Forensics Platform

A full-stack digital forensics web platform that analyzes uploaded evidence files
(images, PDFs) for tampering, forgery, copy-move edits, AI generation, and
metadata/layout/semantic inconsistencies. It produces a structured forensic
report with per-layer scores, a fused risk score, findings, suspicious regions,
hashes, OCR blocks, and a pipeline trace.

> NOTE: this file is intended as context for AI coding agents — it documents
> the stack, architecture, data flow, contracts, and conventions of the repo.

---

## 1. Tech Stack

### Web frontend / API (Node)
- **Next.js 16.2.6** (App Router, React Server Components, route handlers)
- **React 19.2.6**, **TypeScript 5.9**, Node >= 20.9
- **Tailwind CSS 4.1** via `@tailwindcss/postcss`
- **Drizzle ORM 0.45** + **pg** (PostgreSQL persistence)
- **drizzle-kit** for schema/migrations
- ESLint 9 + `eslint-config-next`

### Forensics engine (Python)
- **FastAPI 0.115** + **uvicorn** + **pydantic 2** multipart service
- **NumPy 2.2**, **OpenCV (headless) 4.11**, **Pillow 11**, **scikit-learn 1.5**
- **piexif**, **defusedxml**, **pypdf** (metadata/provenance)
- **pytesseract** (OCR; requires the `tesseract` system binary)
- Optional: transformers/torch for a local semantic model (commented out)

### Infrastructure
- **PostgreSQL** database `app_db` (default `postgresql://postgres:postgres@127.0.0.1:5432/app_db`)
- `.env` holds `DATABASE_URL` and `FORENSICS_ENGINE_URL`

---

## 2. Repository Layout

```
.
├── src/                          # Next.js app
│   ├── app/
│   │   ├── page.tsx              # landing page
│   │   ├── analyze/page.tsx      # analysis workbench
│   │   ├── cases/                # list + case detail pages
│   │   └── api/
│   │       ├── analyze/route.ts  # POST evidence -> forensic report (main pipeline)
│   │       ├── analyses/         # list + get stored reports
│   │       ├── layers/route.ts   # detector registry passthrough
│   │       ├── health/route.ts   # liveness
│   │       └── requests/route.ts # access-request form capture
│   ├── components/               # ui, landing, analyze, site, shared, visuals
│   ├── db/                       # Drizzle schema + pg client
│   └── lib/
│       ├── forensics/            # TS reference engine + HTTP bridge to Python
│       │   ├── types.ts          # AnalysisReport contract (shared shape)
│       │   ├── engine.ts         # deterministic TS reference pipeline
│       │   ├── bridge.ts         # forwards /api/analyze to FastAPI worker
│       │   ├── fusion.ts         # weighted opinion pool + calibration
│       │   ├── registry.ts       # layer registry (weights, runtimes)
│       │   ├── core/             # hash, random, prior, container byte parsing
│       │   └── modules/          # pixel, signal, content, metadata
│       └── format.ts
├── python/                       # FastAPI forensic worker
│   ├── app/main.py               # /health, /layers, POST /analyze
│   ├── app/forensics/            # container, modules, forgify, fusion
│   └── tests/                    # pytest contract + integration tests
├── scripts/check-forensics-engine.mjs  # preflight dev check
├── dataset/, documents/, demo_tomorrow/  # sample evidence files
├── drizzle.config.json
└── package.json
```

---

## 3. How It Runs

Two processes must be up:

```bash
# 1) Python worker (port 8000)
cd python
.venv/bin/uvicorn app.main:app --port 8000

# 2) Next.js dev server (port 3000)
npm run dev        # runs scripts/check-forensics-engine.mjs first, then `next dev`
```

`.env`:
```
DATABASE_URL=postgresql://postgres@127.0.0.1:5432/app_db
FORENSICS_ENGINE_URL=http://127.0.0.1:8000
```

Flow: browser → `POST /api/analyze` (Next.js) → forwarded to FastAPI `/analyze`
when `FORENSICS_ENGINE_URL` is set and healthy; otherwise the TypeScript
reference engine (`src/lib/forensics/engine.ts`) is used only when
`FORENSICS_ALLOW_REFERENCE_ENGINE=true`. Per the project guide the app should
"fail closed" (no report) rather than present reference results as evidence.

---

## 4. Forensic Layers

Registered detector layers (registry in `src/lib/forensics/registry.ts` and
`python/app/main.py`):

| Layer         | Technique                                                   |
| ------------- | ----------------------------------------------------------- |
| `pixel`       | ELA @ q90, Laplacian noise, flat-area residuals             |
| `copy-move`   | SIFT + BFMatcher + affine RANSAC                            |
| `aigc`        | 2-D FFT spectral fingerprint + rolloff                      |
| `compression` | PIL luminance DQT quality / re-encode chain                 |
| `metadata`    | EXIF/XMP/PDF self-consistency (piexif, pypdf, defusedxml)    |
| `layout`      | Tesseract font-size / baseline / alignment / low-confidence |
| `semantic`    | Tesseract arithmetic reconciliation (invoices, marksheets)  |
| `ml-classifier` | (python worker health lists it; present in worker registry) |

Fusion: weighted opinion pool + logistic calibration (`fusion.ts` /
`python/app/forensics/fusion.py`) → `verdict.riskScore`, `confidence`,
per-layer scores, recommendation.

---

## 5. API Contract

`POST /api/analyze` (Next) and `POST /analyze` (FastAPI) accept multipart
`file` (required) + `reference` (optional). Response envelope matches
`AnalysisReport` in `src/lib/forensics/types.ts`:

- `verdict` { riskScore, label, confidence, recommendation }
- `layers[]` — per-layer { id, score, confidence, findings[], regions[] }
- `findings[]`, `regions[]`, `hashes` (sha256/md5/sha1/blurHashFingerprint)
- `ocr` block list, `pipeline[]` trace, `engine`, `executionMode`, `durationMs`

Storage: `analyses`, `findings`, `regions`, `access_requests` tables
(`src/db/schema.ts`). Full report JSON persisted on the `analyses` row so cases
re-render byte-for-byte.

---

## 6. Conventions & Guardrails

- The `AnalysisReport` JSON shape is the contract between worker and web —
  keep `src/lib/forensics/types.ts` and `python/app` in sync.
- Detector output is *evidence, not proof*. Missing metadata/OCR must be
  **neutral**, never "suspicious". Reports from the reference engine must be
  labelled non-evidence-grade.
- PDFs currently contribute container + metadata evidence only (no raster
  decode of pages).
- Max upload 20 MB; supported MIME types: jpeg/jpg/png/webp/tiff/bmp/heic/pdf.
- Tesseract binary required for OCR layers: `brew install tesseract`.
- Tests: `cd python && .venv/bin/python -m pytest -q`.
- Lint/typecheck: `npm run lint`, `npm run typecheck`.
