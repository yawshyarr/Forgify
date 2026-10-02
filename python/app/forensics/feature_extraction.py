#!/usr/bin/env python3
"""
Forgify · Feature extraction pipeline
======================================
Builds a feature table CSV (dataset/features.csv) by running the existing,
already-working detector modules in modules.py (PixelModule, CopyMoveModule,
and tesseract_words OCR from forgify.py / main.py, plus LayoutModule)
against every image sample in dataset/manifest.json.

Requirements:
- Imports and calls real existing detector modules directly.
- Handles missing or failing modules gracefully with NaN instead of silent fake values.
- Writes dataset/features.csv (both under documents/dataset/ and repo dataset/ symlink/path if desired).
- Outputs summary: row count, feature value ranges, class balance.
"""

from __future__ import annotations

import csv
import json
import logging
import math
import os
import sys
from pathlib import Path
from typing import Any

# Ensure python root is importable
REPO_ROOT = Path(__file__).resolve().parents[3]
PYTHON_ROOT = REPO_ROOT / "python"
if str(PYTHON_ROOT) not in sys.path:
    sys.path.insert(0, str(PYTHON_ROOT))

import numpy as np

from app.forensics.modules import CopyMoveModule, PixelModule, to_array
from app.forensics.forgify import LayoutModule, SemanticModule, tesseract_words

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("feature_extraction")

# Resolve dataset root (inside documents/dataset)
DOC_DATASET_DIR = REPO_ROOT / "documents" / "dataset"
MANIFEST_PATH = DOC_DATASET_DIR / "manifest.json"
CSV_PATH_DOCS = DOC_DATASET_DIR / "features.csv"
CSV_PATH_ROOT = REPO_ROOT / "dataset" / "features.csv"


def extract_features_for_sample(
    sample: dict[str, Any],
    pixel_module: PixelModule,
    copy_move_module: CopyMoveModule,
    layout_module: LayoutModule,
    semantic_module: SemanticModule,
) -> dict[str, Any]:
    sample_id = sample.get("id", "unknown")
    doc_type = sample.get("doc_type", "unknown")
    manipulation = sample.get("manipulation", "none")
    is_forged = 0 if manipulation == "none" else 1

    rel_path = sample.get("forged_path") if is_forged else sample.get("original_path")
    if not rel_path:
        raise ValueError(f"Sample {sample_id} has no image path")

    img_path = DOC_DATASET_DIR / rel_path
    if not img_path.exists():
        raise FileNotFoundError(f"Image not found at {img_path}")

    payload = img_path.read_bytes()
    image = to_array(payload)
    if image is None:
        raise ValueError(f"Failed to decode image at {img_path}")

    # Initialize feature outputs with NaN
    ocr_confidence = float("nan")
    ela_score = float("nan")
    copy_move_score = float("nan")
    noise_anomaly = float("nan")
    text_inconsistency = float("nan")

    # 1. OCR pass
    ocr = None
    try:
        ocr = tesseract_words(image)
        if ocr and ocr.available and ocr.words:
            valid_confs = [float(w["conf"]) for w in ocr.words if float(w.get("conf", -1)) >= 0]
            if valid_confs:
                ocr_confidence = float(np.mean(valid_confs))
            else:
                ocr_confidence = 0.0
        else:
            ocr_confidence = 0.0
    except Exception as exc:
        logger.warning(f"[{sample_id}] OCR extraction failed: {exc}")

    context = {
        "bytes": payload,
        "image": image,
        "_ocr": ocr,
        "facts": {"kind": "png"},
        "name": img_path.name,
    }

    # 2. PixelModule (ELA and Noise)
    try:
        pixel_res = pixel_module.run(context)
        ela_score = float(pixel_res.get("score", float("nan")))

        # Extract real sub-score / metric computed by PixelModule
        # metrics contain: [{'label': 'ELA median', ...}, {'label': 'ELA peak', ...}, {'label': 'Noise divergence', 'value': ...}]
        for m in pixel_res.get("metrics", []):
            if m.get("label") == "Noise divergence":
                try:
                    noise_anomaly = float(m.get("value"))
                except (ValueError, TypeError):
                    pass
            elif m.get("label") == "Flat-area residual" and math.isnan(noise_anomaly):
                try:
                    noise_anomaly = float(m.get("value"))
                except (ValueError, TypeError):
                    pass
    except Exception as exc:
        logger.warning(f"[{sample_id}] PixelModule failed: {exc}")

    # 3. CopyMoveModule
    try:
        cm_res = copy_move_module.run(context)
        copy_move_score = float(cm_res.get("score", float("nan")))
    except Exception as exc:
        logger.warning(f"[{sample_id}] CopyMoveModule failed: {exc}")

    # 4. Text Inconsistency (LayoutModule)
    # LayoutModule evaluates relative font size, baseline alignment, and OCR confidence outliers
    # without needing a reference document.
    try:
        layout_res = layout_module.run(context)
        text_inconsistency = float(layout_res.get("score", float("nan")))
    except Exception as exc:
        logger.warning(f"[{sample_id}] LayoutModule failed: {exc}")

    return {
        "sample_id": sample_id,
        "doc_type": doc_type,
        "label": is_forged,
        "forgery_type": manipulation,
        "ocr_confidence": ocr_confidence,
        "ela_score": ela_score,
        "copy_move_score": copy_move_score,
        "noise_anomaly": noise_anomaly,
        "text_inconsistency": text_inconsistency,
    }


def main() -> int:
    if not MANIFEST_PATH.exists():
        logger.error(f"Manifest not found at {MANIFEST_PATH}")
        return 1

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = manifest.get("samples", [])
    logger.info(f"Loaded {len(samples)} samples from {MANIFEST_PATH}")

    # Instantiate real detector modules
    pixel_module = PixelModule()
    copy_move_module = CopyMoveModule()
    layout_module = LayoutModule()
    semantic_module = SemanticModule()

    rows: list[dict[str, Any]] = []

    for idx, s in enumerate(samples, start=1):
        try:
            row = extract_features_for_sample(
                s,
                pixel_module=pixel_module,
                copy_move_module=copy_move_module,
                layout_module=layout_module,
                semantic_module=semantic_module,
            )
            rows.append(row)
        except Exception as exc:
            sid = s.get("id", f"index-{idx}")
            rel_path = s.get("forged_path") or s.get("original_path")
            logger.error(f"Failed processing sample {sid} ({rel_path}): {exc}")
            # Append row with NaNs rather than crashing or skipping
            rows.append({
                "sample_id": sid,
                "doc_type": s.get("doc_type", "unknown"),
                "label": 0 if s.get("manipulation") == "none" else 1,
                "forgery_type": s.get("manipulation", "none"),
                "ocr_confidence": float("nan"),
                "ela_score": float("nan"),
                "copy_move_score": float("nan"),
                "noise_anomaly": float("nan"),
                "text_inconsistency": float("nan"),
            })

        if idx % 40 == 0 or idx == len(samples):
            logger.info(f"Processed {idx}/{len(samples)} samples...")

    fieldnames = [
        "sample_id",
        "doc_type",
        "label",
        "forgery_type",
        "ocr_confidence",
        "ela_score",
        "copy_move_score",
        "noise_anomaly",
        "text_inconsistency",
    ]

    # Ensure output destinations exist
    CSV_PATH_DOCS.parent.mkdir(parents=True, exist_ok=True)
    CSV_PATH_ROOT.parent.mkdir(parents=True, exist_ok=True)

    for target_path in (CSV_PATH_DOCS, CSV_PATH_ROOT):
        with open(target_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                formatted_row = {}
                for k, v in r.items():
                    if isinstance(v, float):
                        formatted_row[k] = f"{v:.4f}" if not math.isnan(v) else "NaN"
                    else:
                        formatted_row[k] = v
                writer.writerow(formatted_row)
        logger.info(f"Wrote {len(rows)} feature rows to {target_path}")

    # Summary Statistics
    print("\n" + "=" * 60)
    print("FEATURE EXTRACTION SUMMARY")
    print("=" * 60)
    print(f"Total Rows: {len(rows)}")

    # Class balance
    genuine_count = sum(1 for r in rows if r["label"] == 0)
    forged_count = sum(1 for r in rows if r["label"] == 1)
    print(f"\nClass Balance:")
    print(f"  - Genuine (0) : {genuine_count}")
    print(f"  - Forged (1)  : {forged_count}")

    print(f"\nPer-Forgery-Type Counts:")
    forgery_types = sorted({r["forgery_type"] for r in rows})
    for ft in forgery_types:
        count = sum(1 for r in rows if r["forgery_type"] == ft)
        print(f"  - {ft:<15} : {count}")

    print(f"\nFeature Value Ranges (excluding NaN):")
    numeric_features = [
        "ocr_confidence",
        "ela_score",
        "copy_move_score",
        "noise_anomaly",
        "text_inconsistency",
    ]
    for feat in numeric_features:
        vals = [r[feat] for r in rows if not math.isnan(r[feat])]
        n_nans = len(rows) - len(vals)
        if vals:
            print(f"  - {feat:<20}: min={min(vals):.4f}, mean={np.mean(vals):.4f}, max={max(vals):.4f} (valid={len(vals)}, NaN={n_nans})")
        else:
            print(f"  - {feat:<20}: ALL NaN (count={n_nans})")

    print("=" * 60 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
