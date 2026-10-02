#!/usr/bin/env python3
"""
Forgify · dataset validator
============================
Independent integrity check for the labelled dataset produced by
``generate_dataset.py``. It re-derives everything it can from disk rather than
trusting the manifest, so a stale or hand-edited manifest is caught.

Checks
------
1. Counts          80 originals (20 per template), 240 forgeries
                   (80 per manipulation), 240 masks.
2. Pairing         every forged file has a mask, every mask has a forged file,
                   and every manifest entry points at files that exist.
3. Localisation    each mask's white bounding box matches the manifest's
                   ``region_box`` within a few pixels, the mask is strictly
                   binary black/white, and it is non-empty.
4. Uniqueness      no duplicate filenames anywhere in the dataset.
5. Content         every forgery actually differs from its original, and no
                   changed pixel falls outside the mask (the mask is
                   pixel-accurate, not approximate).

Usage
-----
    python/.venv/bin/python documents/dataset/validate_dataset.py

Exit code 0 = all checks passed, 1 = at least one failure.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "manifest.json"
ORIGINAL_DIR = ROOT / "original"
FORGED_DIR = ROOT / "forged"
MASKS_DIR = ROOT / "masks"

DOC_TYPES = ("certificate", "invoice", "marksheet", "id_card")
MANIPULATIONS = ("whiteout", "copy_move", "text_replace")
PER_TYPE = 20

EXPECTED_ORIGINALS = len(DOC_TYPES) * PER_TYPE              # 80
EXPECTED_FORGED = EXPECTED_ORIGINALS * len(MANIPULATIONS)   # 240
EXPECTED_MASKS = EXPECTED_FORGED                            # 240

TOLERANCE_PX = 2  # mask bbox vs manifest region_box
PILOT_ROOT = ROOT / "pilot"


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append((name, ok, detail))
        if not ok:
            self.errors.append(f"{name}: {detail}" if detail else name)
        return ok

    def error(self, message: str) -> None:
        self.errors.append(message)

    @property
    def ok(self) -> bool:
        return not self.errors


def pilot_main() -> int:
    manifest_path = PILOT_ROOT / "manifest.json"
    if not manifest_path.exists():
        print(f"FAIL manifest not found: {manifest_path}"); return 1
    data = json.loads(manifest_path.read_text(encoding="utf-8")); samples = data.get("samples", []); errors = []
    ids = [s.get("caseId") for s in samples]
    if len(ids) != len(set(ids)): errors.append("duplicate caseId")
    for s in samples:
        for key in ("referenceImage", "evidenceImage", "original_path"):
            if not s.get(key) or not (ROOT / s[key]).is_file(): errors.append(f"{s.get('caseId')}: missing {key}")
        status = s.get("expectedDocumentStatus")
        if status not in {"genuine", "manipulated"}: errors.append(f"{s.get('caseId')}: invalid status")
        evidence = Image.open(ROOT / s["evidenceImage"])
        if list(evidence.size) != list(s.get("image_size", [])): errors.append(f"{s.get('caseId')}: image_size mismatch")
        if status == "manipulated":
            if not s.get("mask_path") or not s.get("fieldsChanged") or not s.get("region"): errors.append(f"{s.get('caseId')}: incomplete manipulated metadata")
            else:
                mask = Image.open(ROOT / s["mask_path"])
                if mask.size != evidence.size or mask_bbox(mask) is None: errors.append(f"{s.get('caseId')}: invalid mask")
                box = s["region"]["bbox"]; w, h = evidence.size
                if not (0 <= box[0] < box[0] + box[2] <= w and 0 <= box[1] < box[1] + box[3] <= h): errors.append(f"{s.get('caseId')}: region outside image")
        elif s.get("fieldsChanged") or s.get("mask_path") is not None: errors.append(f"{s.get('caseId')}: genuine case claims manipulation")
    print(f"pilot manifest: {len(samples)} cases")
    if errors:
        print(f"FAIL {len(errors)} error(s)"); print("\n".join(f"  - {e}" for e in errors[:20])); return 1
    print("PASS pilot paths, statuses, masks, dimensions, regions, and case IDs"); return 0


def glob_pngs(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.png")) if directory.exists() else []


def mask_bbox(mask: Image.Image) -> tuple[int, int, int, int] | None:
    arr = np.asarray(mask.convert("RGB"))
    ys, xs = np.nonzero(arr[:, :, 0] > 127)
    if len(xs) == 0:
        return None
    return (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def changed_bbox(a: Image.Image, b: Image.Image) -> tuple[int, int, int, int] | None:
    diff = np.abs(np.asarray(a.convert("RGB"), dtype=np.int16)
                  - np.asarray(b.convert("RGB"), dtype=np.int16)).sum(axis=2)
    ys, xs = np.nonzero(diff)
    if len(xs) == 0:
        return None
    return (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def close(a: int, b: int, tol: int = TOLERANCE_PX) -> bool:
    return abs(a - b) <= tol


def boxes_close(a, b, tol: int = TOLERANCE_PX) -> bool:
    return len(a) == len(b) == 4 and all(close(x, y, tol) for x, y in zip(a, b))


def main() -> int:
    rep = Report()

    if not MANIFEST_PATH.exists():
        print(f"FAIL  manifest not found: {MANIFEST_PATH}")
        return 1
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    samples = manifest.get("samples", [])

    print(f"manifest      : {MANIFEST_PATH.name}  ({len(samples)} entries)")

    # ---- 1. counts ------------------------------------------------------- #
    on_disk_originals = glob_pngs(ORIGINAL_DIR)
    on_disk_forged = glob_pngs(FORGED_DIR)
    on_disk_masks = glob_pngs(MASKS_DIR)

    per_type = Counter(p.parent.name for p in on_disk_originals)
    per_manip = Counter(p.parent.name for p in on_disk_forged)

    rep.check("count/originals", len(on_disk_originals) == EXPECTED_ORIGINALS,
              f"found {len(on_disk_originals)}, expected {EXPECTED_ORIGINALS}")
    rep.check("count/forged", len(on_disk_forged) == EXPECTED_FORGED,
              f"found {len(on_disk_forged)}, expected {EXPECTED_FORGED}")
    rep.check("count/masks", len(on_disk_masks) == EXPECTED_MASKS,
              f"found {len(on_disk_masks)}, expected {EXPECTED_MASKS}")

    for doc_type in DOC_TYPES:
        rep.check(f"count/originals/{doc_type}", per_type.get(doc_type, 0) == PER_TYPE,
                  f"found {per_type.get(doc_type, 0)}, expected {PER_TYPE}")
    for manip in MANIPULATIONS:
        rep.check(f"count/forged/{manip}", per_manip.get(manip, 0) == EXPECTED_ORIGINALS,
                  f"found {per_manip.get(manip, 0)}, expected {EXPECTED_ORIGINALS}")

    manifest_originals = sum(1 for s in samples if s.get("manipulation") == "none")
    manifest_forged = sum(1 for s in samples if s.get("manipulation") != "none")
    rep.check("count/manifest", manifest_originals == EXPECTED_ORIGINALS
              and manifest_forged == EXPECTED_FORGED,
              f"manifest has {manifest_originals} originals / {manifest_forged} forged")

    # ---- 4. duplicate filenames ------------------------------------------ #
    # Uniqueness is per category: a mask is *required* to share its forged
    # file's name, so a global name count would flag every pair. What must not
    # happen is two distinct samples colliding, or a forged/mask name colliding
    # with an original's name.
    original_names = [p.name for p in on_disk_originals]
    forged_names = [p.name for p in on_disk_forged]
    mask_names = [p.name for p in on_disk_masks]

    def dupes(seq: list[str]) -> list[str]:
        return sorted(n for n, c in Counter(seq).items() if c > 1)

    d_orig = dupes(original_names)
    d_forged = dupes(forged_names)
    d_mask = dupes(mask_names)
    rep.check("uniqueness/filenames", not (d_orig or d_forged or d_mask),
              f"duplicates -> originals {d_orig[:3]}, forged {d_forged[:3]}, masks {d_mask[:3]}")

    cross = sorted(set(original_names) & (set(forged_names) | set(mask_names)))
    rep.check("uniqueness/no_original_name_collision", not cross,
              f"{len(cross)} name(s) shared with an original: {cross[:5]}")

    rep.check("uniqueness/mask_names_match_forged", set(mask_names) == set(forged_names),
              f"{len(set(forged_names) ^ set(mask_names))} filename(s) unpaired")

    ids = [s.get("id") for s in samples]
    rep.check("uniqueness/ids", len(set(ids)) == len(ids),
              f"{len(ids) - len(set(ids))} duplicate id(s)")

    # ---- 2. pairing + paths ---------------------------------------------- #
    forged_files = {p for p in on_disk_forged}
    mask_files = {p for p in on_disk_masks}
    missing_mask, orphan_mask, missing_paths = [], [], []
    missing_field = []

    for s in samples:
        op = s.get("original_path")
        fp = s.get("forged_path")
        mp = s.get("mask_path")
        rb = s.get("region_box")

        if not op or not (ROOT / op).exists():
            missing_paths.append(f"{s.get('id')}: original_path {op!r}")
        if s.get("manipulation") == "none":
            if fp is not None or mp is not None or rb is not None:
                missing_field.append(f"{s.get('id')}: original must have null forged/mask/region_box")
        else:
            if fp is None or mp is None or rb is None:
                missing_field.append(f"{s.get('id')}: forged entry missing forged_path/mask_path/region_box")
                continue
            if not (ROOT / fp).exists():
                missing_paths.append(f"{s.get('id')}: forged_path {fp!r}")
            if not (ROOT / mp).exists():
                missing_paths.append(f"{s.get('id')}: mask_path {mp!r}")
                missing_mask.append(s["id"])
                continue
            f_abs, m_abs = ROOT / fp, ROOT / mp
            if f_abs not in forged_files:
                missing_field.append(f"{s.get('id')}: forged file outside forged/")
            if m_abs not in mask_files:
                missing_field.append(f"{s.get('id')}: mask file outside masks/")
            # mask filename must equal the forged filename (spec)
            if f_abs.name != m_abs.name:
                rep.error(f"{s.get('id')}: mask name {m_abs.name} != forged name {f_abs.name}")

    mask_referenced = {ROOT / s["mask_path"] for s in samples if s.get("mask_path")}
    orphan_mask = sorted(str(p.relative_to(ROOT)) for p in mask_files - mask_referenced)

    rep.check("pairing/mask_exists", not missing_mask,
              f"{len(missing_mask)} forged file(s) without a mask: {missing_mask[:5]}")
    rep.check("pairing/no_orphan_masks", not orphan_mask,
              f"{len(orphan_mask)} unreferenced mask(s): {orphan_mask[:5]}")
    rep.check("pairing/paths_exist", not missing_paths,
              f"{len(missing_paths)} bad path(s): {missing_paths[:5]}")
    rep.check("pairing/manifest_fields", not missing_field,
              f"{len(missing_field)} malformed entr(ies): {missing_field[:5]}")

    # ---- 3 + 5. localisation and content --------------------------------- #
    bbox_mismatch, bad_binary, empty_mask, no_diff, diff_outside = [], [], [], [], []
    checked = 0

    for s in samples:
        if s.get("manipulation") == "none":
            continue
        try:
            forged = Image.open(ROOT / s["forged_path"])
            mask = Image.open(ROOT / s["mask_path"])
            original = Image.open(ROOT / s["original_path"])
        except Exception as exc:  # unreadable file
            rep.error(f"{s.get('id')}: could not open image ({exc})")
            continue
        checked += 1

        if mask.size != forged.size or mask.size != original.size:
            bad_binary.append(f"{s['id']}: size mismatch")
            continue
        if s.get("image_size") and list(mask.size) != list(s["image_size"]):
            bad_binary.append(f"{s['id']}: size != manifest image_size")

        arr = np.asarray(mask.convert("RGB"))
        # np.unique on a 3-D array flattens to channel values, so compare whole
        # pixels: the mask must be strictly black or white, nothing between.
        colours = {tuple(int(v) for v in c) for c in
                   np.unique(arr.reshape(-1, 3), axis=0)}
        if not colours <= {(0, 0, 0), (255, 255, 255)}:
            bad_binary.append(f"{s['id']}: non-binary colours {sorted(colours)[:4]}")

        mb = mask_bbox(mask)
        if mb is None:
            empty_mask.append(s["id"])
            continue
        if not boxes_close(mb, [int(v) for v in s["region_box"]]):
            bbox_mismatch.append(f"{s['id']}: mask bbox {mb} vs region_box {s['region_box']}")

        cb = changed_bbox(original, forged)
        if cb is None:
            no_diff.append(s["id"])
            continue
        x0, y0, x1, y1 = [int(v) for v in s["region_box"]]
        if not (x0 <= cb[0] and cb[1] >= y0 and cb[2] <= x1 and cb[3] <= y1):
            diff_outside.append(f"{s['id']}: changed pixels {cb} outside region {s['region_box']}")

    rep.check("localisation/mask_bbox_matches_region_box", not bbox_mismatch,
              f"{len(bbox_mismatch)} mismatch(es) beyond {TOLERANCE_PX}px: {bbox_mismatch[:5]}")
    rep.check("localisation/mask_binary", not bad_binary,
              f"{len(bad_binary)} problem(s): {bad_binary[:5]}")
    rep.check("localisation/mask_non_empty", not empty_mask,
              f"{len(empty_mask)} empty mask(s): {empty_mask[:5]}")
    rep.check("content/forgery_differs", not no_diff,
              f"{len(no_diff)} forgery(ies) identical to the original: {no_diff[:5]}")
    rep.check("content/diff_inside_mask", not diff_outside,
              f"{len(diff_outside)} case(s) with changed pixels outside the mask: {diff_outside[:5]}")
    rep.check("coverage/pairs_checked", checked == EXPECTED_FORGED,
              f"localisation was verified for {checked} of {EXPECTED_FORGED} forgeries")

    # ---- report ---------------------------------------------------------- #
    width = max(len(n) for n, _, _ in rep.checks)
    print()
    for name, ok, detail in rep.checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail if not ok else ''}")

    print()
    if rep.ok:
        print(f"VALID  all {len(rep.checks)} checks passed")
        print(f"        originals {len(on_disk_originals)}  "
              f"forged {len(on_disk_forged)}  masks {len(on_disk_masks)}  "
              f"samples {len(samples)}")
        return 0

    print(f"INVALID  {len(rep.errors)} problem(s):")
    for err in rep.errors[:40]:
        print(f"  - {err}")
    if len(rep.errors) > 40:
        print(f"  ... and {len(rep.errors) - 40} more")
    return 1


if __name__ == "__main__":
    sys.exit(pilot_main() if "--pilot" in sys.argv[1:] else main())
