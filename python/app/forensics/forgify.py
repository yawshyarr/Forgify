"""
Reference-optional document detectors.
================================================================
Detectors ported from the Forgify corpus backend (Phase 1 / 1.1 /
1.2) and re-wrapped into the ``Module`` contract so the FastAPI
worker runs the same algorithms that were benchmarked against the
synthetic corpus:

    compression →  Forgify compression_forensics
                   JPEG quant-table quality recovery (re-encode chains)
    metadata    →  Forgify metadata (EXIF / PNG / PDF self-consistency)
    layout      →  Forgify layout_consistency
                   OCR font-size / baseline / alignment + low-conf clusters
    semantic    →  Forgify semantic_consistency
                   OCR arithmetic reconciliation (invoice + marksheet)

Measured on the sample corpus (before re-wrapping): compression recall
1.00 / FPR 0.00, noise_analysis (screenshot) recall 0.90 / FPR 0.00,
semantic invoice-text_replace recall 0.375 / FPR 0.00, layout conservative
(~0–1% flags). These are *signals to be weighed with other layers*, not
certificates of authenticity.

OCR is shared through a Tesseract adapter so layout, semantic and the
report's OCR section re-use one pass over the evidence.
"""

from __future__ import annotations

import io
import re
import time
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np

try:
    import cv2
except Exception:  # pragma: no cover
    cv2 = None

from PIL import Image

from app.forensics.modules import Module, band, finding, region


# =========================================================================== #
#  shared Tesseract adapter (one OCR pass, consumed by layout + semantic + OCR
# =========================================================================== #


@dataclass
class OcrWords:
    words: list[dict]
    available: bool = True

    @property
    def empty(self) -> bool:
        return self.words is None


def _ocr_ready(image):
    """Normalise an engine image to something ``Image.fromarray`` reads correctly.

    ``modules.to_array`` decodes with ``cv2.imdecode``, which yields **BGR**.
    Handing that straight to ``Image.fromarray`` labels the channels RGB, so red
    and blue are swapped before Tesseract ever sees the page. The damage is
    quiet rather than fatal: on the demo invoice the swapped channels were enough
    to truncate the totals label from "Total" to "Tota", which made
    ``_find_label(["total"])`` miss entirely and silently skipped the
    grand-total reconciliation — the strongest arithmetic check the semantic
    layer has. Grayscale sidesteps the ordering question altogether, and OCR does
    not benefit from colour on these documents.
    """
    if image is None:
        return None
    arr = np.asarray(image)
    if arr.ndim == 3:
        if cv2 is not None:
            arr = cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)
        else:  # pragma: no cover - cv2 missing
            arr = arr[..., :3].mean(axis=2).astype(np.uint8)
    return arr


def tesseract_words(image) -> OcrWords:
    """Word-level OCR (data dict with bbox + confidence). Returns
    ``OcrWords(available=False)`` when tesseract is missing or fails."""
    try:
        import pytesseract
    except ImportError:  # pragma: no cover
        return OcrWords([], available=False)
    if image is None:
        return OcrWords([], available=False)
    try:
        data = pytesseract.image_to_data(
            Image.fromarray(_ocr_ready(image)), config="--psm 6",
            output_type=pytesseract.Output.DICT, timeout=90,
        )
    except Exception:  # pragma: no cover - tesseract binary down
        return OcrWords([], available=False)
    words = []
    for i, text in enumerate(data["text"]):
        t = text.strip()
        if not t:
            continue
        w = int(data["width"][i])
        h = int(data["height"][i])
        if w <= 0 or h <= 0:
            continue
        words.append({
            "text": t, "conf": float(data["conf"][i]) if data["conf"][i] != "" else -1.0,
            "left": int(data["left"][i]), "top": int(data["top"][i]),
            "width": w, "height": h, "index": i,
        })
    return OcrWords(words)


# =========================================================================== #
#  compression — JPEG quant-table quality (Forgify compression_forensics)
# =========================================================================== #

_STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
]

_QUALITY_GUARD = 72.0


def _quality_from_bytes(payload: bytes) -> tuple[int, int] | None:
    """IJG-style quality estimate from the luminance DQT table. None when the
    input is not a JPEG (missing evidence never counts against a document)."""
    if not payload:
        return None
    try:
        image = Image.open(io.BytesIO(payload))
        image.load()
    except Exception:
        return None
    if getattr(image, "format", None) != "JPEG":
        return None
    tables = getattr(image, "quantization", None)
    if not tables:
        return None
    lum = list(tables[0]) if isinstance(tables, (dict, list, tuple)) and tables[0] else None
    if not lum:
        return None
    lq = np.array(lum, dtype=np.float32).reshape(8, 8)
    dc = float(lq[0, 0])
    if dc <= 0:
        return None
    scale = dc * 100.0 / 16.0  # q=50 => scale=100, DC(lum)=16 in the Annex-K base
    if scale >= 100:
        q = int(round(5000.0 / scale))
    else:
        q = int(round((200.0 - scale) / 2.0))
    return max(1, min(q, 100)), len(tables)


class CompressionModule(Module):
    """Recovers the stored quantisation quality straight from the bytes.
    Quality well below the normal document band is consistent with a heavy
    re-encode / re-save chain (mirrors the benchmarked compression_forensics)."""

    def __init__(self) -> None:
        super().__init__(
            id="compression",
            name="Compression History",
            category="signal",
            weight=0.1,
            runtime="PIL DQT quality recovery (Forgify compression_forensics)",
            techniques=[
                "Luminance DQT quant-table recovery",
                "IJG quality estimation (Annex-K scaling)",
                "Re-encode band test (q < 72)",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        payload = context.get("bytes")
        resolved = _quality_from_bytes(payload)
        if resolved is None:
            return self.result(
                0.0, [], [], started,
                "No JPEG quant table available (not a JPEG compile, or pixels-only input).",
                [{"label": "Estimated quality", "value": "n/a"}],
                confidence=0.0,
            )

        q, tables = resolved
        metrics = [{"label": "Estimated quality", "value": f"α {q}"}]
        if q >= _QUALITY_GUARD:
            return self.result(
                0.0, [], [], started,
                f"Stored quality α {q} is inside the normal document band.",
                metrics, confidence=0.0,
            )

        raw = float(np.clip((_QUALITY_GUARD - q) / 22.0, 0.05, 1.0))
        confidence = float(np.clip(0.5 + raw * 0.4, 0.5, 0.92))
        score = raw
        return self.result(
            score,
            [
                finding(
                    "compression", "CMP-RESAVE",
                    "File re-stored at an unusually low JPEG quality",
                    band(score), confidence,
                    f"The quantisation tables describe quality α {q}, well below the "
                    "normal document band (α ≥ 72). Heavy re-save / re-encode chains "
                    "produce exactly this profile — investigate, it is not conclusive on "
                    "its own.",
                    [
                        {"label": "Estimated quality", "value": f"α {q}"},
                        {"label": "Tables recovered", "value": str(tables)},
                    ],
                    metric=f"α {q}",
                    recommendation="Compare the quantisation tables against the issuing scanner/printer; request the original file from the custodian.",
                )
            ],
            [], started,
            f"Stored quality α {q} ({tables} table(s)); re-encode signature present.",
            metrics, confidence=confidence,
        )


# =========================================================================== #
#  metadata — EXIF / PNG / PDF self-consistency (Forgify metadata)
# =========================================================================== #


def _meta_fields(payload: bytes, kind: str) -> dict | None:
    if kind == "pdf":  # pragma: no cover - PDF metadata via pypdf
        from pypdf import PdfReader
        try:
            reader = PdfReader(io.BytesIO(payload))
            meta = dict(reader.metadata) if reader.metadata else {}
            return {k.lstrip("/"): str(v) for k, v in meta.items()} or None
        except Exception:
            return None
    try:
        image = Image.open(io.BytesIO(payload))
        image.load()
    except Exception:
        return None
    out: dict[str, str] = {}
    exif = image.getexif()
    for tag, label in ((306, "DateTimeOriginal"), (36867, "DateTimeOriginal"),
                       (36868, "DateTimeDigitized"), (305, "Software"), (271, "Make")):
        val = exif.get(tag)
        if val:
            out[label] = str(val)
    info = image.info or {}
    for key in ("Software", "Creation Time", "XML:com.adobe.xmp"):
        if info.get(key):
            out[key] = str(info[key])[:200]
    return out or None


def _to_dt(value) -> datetime | None:
    if not value:
        return None
    s = str(value).replace("D:", "").strip()
    for fmt in ("%Y%m%d%H%M%S", "%Y:%m:%d %H:%M:%S"):
        try:
            return datetime.strptime(s[:20].strip(), fmt)
        except ValueError:
            continue
    return None


class MetadataModule(Module):
    """Parses embedded metadata and applies self-consistency rules (mod date
    never precedes creation; software tags consistent with the container).
    MISSING metadata is neutral: absence is never treated as forgery."""

    def __init__(self) -> None:
        super().__init__(
            id="metadata",
            name="Metadata Forensics",
            category="container",
            weight=0.12,
            runtime="PIL / pypdf self-consistency (Forgify metadata)",
            techniques=[
                "EXIF / XMP / document-info extraction",
                "Timeline consistency (mod ≥ created)",
                "Software / producer re-save test",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        payload = context.get("bytes")
        kind = (context.get("facts") or {}).get("kind", "")
        info = _meta_fields(payload, kind) if payload else None

        if not info:
            return self.result(
                0.0, [], [], started,
                "No traceable metadata embedded in the file (cannot be used as evidence either way).",
                [{"label": "Fields", "value": "0"}], confidence=0.0,
            )

        issues: list[str] = []
        created = _to_dt(info.get("CreationDate") or info.get("DateTimeOriginal"))
        modified = _to_dt(info.get("ModDate") or info.get("DateTimeDigitized"))
        if created and modified and modified < created:
            issues.append(f"modification date ({modified}) precedes creation date ({created})")
        software = info.get("Software") or info.get("Producer")
        if software:
            s = str(software).lower()
            if "word" in s or "excel" in s or "powerpoint" in s:
                issues.append(f"software tag ({software}) implies a re-save/export chain")

        if not issues:
            return self.result(
                0.0, [], [], started,
                "Embedded metadata is internally self-consistent.",
                [{"label": "Fields", "value": str(len(info))}], confidence=0.0,
            )

        raw = min(1.0, len(issues) / 3.0)
        confidence = float(np.clip(0.4 + raw * 0.4, 0.4, 0.85))
        return self.result(
            raw,
            [
                finding(
                    "metadata", "META-CONS", "Metadata self-consistency violation(s) detected",
                    band(raw), confidence, "; ".join(issues),
                    [{"label": "Issue", "value": issue} for issue in issues],
                    metric=f"{len(issues)} issue(s)",
                    recommendation="Court the original file and its custody log; metadata alone never certifies forgery.",
                )
            ],
            [], started, f"{len(info)} metadata field(s); {len(issues)} violation(s).",
            [{"label": "Fields", "value": str(len(info))}, {"label": "Violations", "value": str(len(issues))}],
            confidence=confidence,
        )


# =========================================================================== #
#  layout — OCR font / baseline / alignment (Forgify layout_consistency)
# =========================================================================== #


class LayoutModule(Module):
    def __init__(self) -> None:
        super().__init__(
            id="layout",
            name="Layout & Geometry",
            category="content",
            weight=0.07,
            runtime="Tesseract structure (Forgify layout_consistency)",
            techniques=[
                "Font-size deviation scan",
                "Baseline drift per text line",
                "Column-left-edge outliers",
                "Low-confidence word clusters",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        ocr = context.get("_ocr") or tesseract_words(image)
        if not ocr.available or not ocr.words:
            return self.result(
                0.0, [], [], started,
                "OCR unavailable; layout check degraded to neutral.",
                [{"label": "Words", "value": "0"}], confidence=0.0,
            )

        words = ocr.words
        if len(words) < 20:
            return self.result(
                0.0, [], [], started,
                f"Too few OCR words ({len(words)}) for a relative layout test.",
                [{"label": "Words", "value": str(len(words))}], confidence=0.0,
            )

        heights = np.array([w["height"] for w in words], dtype=np.float32)
        typ_h = float(np.median(heights)) or 12.0
        row_key = lambda top: int(top // max(2.0, typ_h * 0.5))  # noqa: E731
        rows: dict[int, list[int]] = {}
        for i in range(len(words)):
            rows.setdefault(row_key(words[i]["top"]), []).append(i)
        weak_lines = {
            rk for rk, idxs in rows.items()
            if sum(1 for i in idxs if words[i]["conf"] < 40) >= 3
        }

        deviant: list[np.ndarray] = []
        reasons: dict[str, int] = {}
        for w in words:
            if w["top"] // max(2.0, typ_h * 0.5) in weak_lines:
                reasons["low_ocr_confidence"] = reasons.get("low_ocr_confidence", 0) + 1
            elif typ_h > 6 and (w["height"] > 2.0 * typ_h or w["height"] < 0.45 * typ_h):
                reasons["font_size_deviation"] = reasons.get("font_size_deviation", 0) + 1
            else:
                continue
            deviant.append(np.array([w["left"], w["top"], w["left"] + w["width"], w["top"] + w["height"]]))

        baseline_box, left_box = self._alignment_outliers(words, typ_h)
        for box, key in ((baseline_box, "baseline_deviation"), (left_box, "column_alignment_deviation")):
            if box is not None:
                deviant.append(box)
                reasons[key] = reasons.get(key, 0) + 1

        if len(deviant) < 2:
            return self.result(
                0.0, [], [], started,
                "OCR layout is internally consistent (font size, baseline and alignment).",
                [{"label": "Words", "value": str(len(words))}], confidence=0.0,
            )

        H, W = image.shape[:2]
        stacked = np.vstack(deviant)
        box = [max(0, int(stacked[:, 0].min())), max(0, int(stacked[:, 1].min())),
               min(W, int(stacked[:, 2].max()) + 1), min(H, int(stacked[:, 3].max()) + 1)]
        raw = float(np.clip(len(deviant) / len(words), 0, 1)) if deviant else 0.0
        confidence = float(np.clip(0.35 + raw * 0.55, 0.35, 0.95))
        score = raw
        nrm = region("layout", "Layout anomaly cluster", score, confidence, box,
                     (H, W), "OCR structure clustering",
                     f"{len(deviant)} deviant word(s) / {len(words)} total.")
        return self.result(
            score,
            [
                finding(
                    "layout", "LXT-DEV", "OCR-inconsistent text region (font / baseline / alignment)",
                    band(score), confidence,
                    "Font size, baseline or column alignment deviates from the document's own "
                    "dominant structure, or a whole line reads with low OCR confidence — a hallmark "
                    "of edited / overwritten regions.",
                    [{"label": k, "value": str(v)} for k, v in reasons.items()],
                    nrm, f"{len(deviant)} deviant word(s)",
                    recommendation="Visually inspect the highlighted region; confirm whether the text was re-rendered.",
                )
            ],
            [nrm], started,
            f"{len(deviant)}/{len(words)} word(s) deviate from the dominant layout.",
            [{"label": "Words", "value": str(len(words))}, {"label": "Deviant", "value": str(len(deviant))}],
            confidence=confidence,
        )

    @staticmethod
    def _alignment_outliers(words, typ_h):
        centers = np.array([w["left"] + w["width"] / 2 for w in words], dtype=np.float32)
        order = np.argsort(centers)
        columns: list[list[int]] = []
        current: list[int] = []
        prev = -1e9
        for ix in order:
            if current and centers[ix] - prev > max(24.0, typ_h):
                columns.append(current)
                current = []
            current.append(ix)
            prev = centers[ix]
        if current:
            columns.append(current)

        left_boxes = []
        for col in columns:
            if len(col) < 3:
                continue
            matrix = np.array([[words[i]["left"], words[i]["top"], words[i]["width"], words[i]["height"]] for i in col])
            med_left = float(np.median(matrix[:, 0]))
            tol = max(6.0, 0.5 * np.median(matrix[:, 2]))
            off = matrix[np.abs(matrix[:, 0] - med_left) > tol * 2.0]
            if len(off) >= 3:
                left_boxes.append(off)

        base_boxes = []
        row_key = lambda top: int(top // max(2.0, typ_h * 0.5))  # noqa: E731
        rows: dict[int, list] = {}
        for i, w in enumerate(words):
            rows.setdefault(row_key(w["top"]), []).append((i, w))
        for grp in rows.values():
            if len(grp) < 4:
                continue
            bottoms = np.array([w["top"] + w["height"] for _, w in grp], dtype=np.float32)
            med = float(np.median(bottoms))
            tol = max(5.0, 0.12 * np.median([w["height"] for _, w in grp]))
            off = np.array([[w["left"], w["top"], w["left"] + w["width"], w["top"] + w["height"]]
                            for _, w in grp if abs(w["top"] + w["height"] - med) > tol * 2.5])
            if len(off) >= 2:
                base_boxes.append(off)

        b = np.vstack(base_boxes) if base_boxes else None
        a = np.vstack(left_boxes) if left_boxes else None
        return b, a


# =========================================================================== #
#  semantic — arithmetic reconciliation (Forgify semantic_consistency)
# =========================================================================== #

MIN_TOK_CONF = 50.0
MIN_ROWS = 3
SUM_BASE_CONF = 0.92
ROW_BASE_CONF = 0.45

_NUM_STRIP = re.compile(r"[^\d.-]")
_AMOUNT_WORD = re.compile(r"^[0-9][0-9,.]*%?$")


def _num(text: str):
    s = _NUM_STRIP.sub("", text.strip())
    if not s or s in {"-", "."}:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _lower(w) -> str:
    return w["text"].lower()


def _typ_h(words) -> float:
    hs = [w["height"] for w in words if w["height"] > 0]
    return float(np.median(hs)) if hs else 12.0


def _value_right(label, words, typ_h):
    cy = label["top"] + label["height"] / 2.0
    cx = label["left"] + label["width"]
    best, best_gap = None, None
    for w in words:
        if _num(w["text"]) is None or not _AMOUNT_WORD.match(w["text"].strip()):
            continue
        if w["left"] < cx - 2:
            continue
        if abs((w["top"] + w["height"] / 2.0) - cy) > typ_h:
            continue
        gap = w["left"] - cx
        if best_gap is None or gap < best_gap:
            best, best_gap = w, gap
    return best


def _find_label(words, names, exclude, pos="first"):
    """Locate a totals label ("subtotal", "tax", "total") among OCR words.

    Matching is anchored at a *word boundary*, not a bare prefix. A bare
    ``startswith`` made the header word "TAXINVOICE" satisfy the "tax" query,
    so ``_value_right`` then looked for a figure beside the page heading, found
    none, and the grand-total reconciliation — the strongest arithmetic check
    the semantic layer has — was silently skipped on any invoice whose title
    contains "tax". Requiring the character after the label to be a separator
    ("tax", "tax:", "tax (18%)") while rejecting a longer word
    ("taxinvoice", "totalamount") fixes that without loosening anything.
    """
    hits = []
    for w in words:
        if w["index"] in exclude:
            continue
        tl = _lower(w)
        for n in names:
            if tl == n:
                hits.append(w)
                break
            if tl.startswith(n) and not tl[len(n):len(n) + 1].isalnum():
                hits.append(w)
                break
    if not hits:
        return None
    if pos == "last":
        # reading order (top, then left): the totals block runs downward, so
        # "last" is the bottom-most label, not merely the right-most one.
        return max(hits, key=lambda w: (w["top"], w["left"]))
    return hits[0]


def _tok_conf(tokens) -> float:
    confs = [t["conf"] for t in tokens if t is not None and t["conf"] >= 0]
    return float(min(confs)) if confs else MIN_TOK_CONF


def _conf(base: float, tokens, multi: bool) -> float:
    min_conf = _tok_conf(tokens)
    factor = 0.65 + 0.35 * max(0.0, min_conf) / 100.0
    c = base * factor
    if multi:
        c = min(0.97, c + 0.06)
    return round(max(0.0, min(0.97, c)), 3)


def _invoice_checks(words, image_h):
    exclude: set[int] = set()
    typ = _typ_h(words)
    sub_w = _find_label(words, ["subtotal"], exclude)
    tax_w = _find_label(words, ["tax"], exclude)
    tot_w = _find_label(words, ["total"], exclude, pos="last")
    exclude.update(w["index"] for w in (sub_w, tax_w, tot_w) if w is not None)

    sub_lab = _value_right(sub_w, words, typ) if sub_w is not None else None
    tax_lab = _value_right(tax_w, words, typ) if tax_w is not None else None
    tot_lab = _value_right(tot_w, words, typ) if tot_w is not None else None
    if sub_lab is not None and tax_lab is not None and tot_lab is not None:
        exp = _num(sub_lab["text"]) + _num(tax_lab["text"])
        act = _num(tot_lab["text"])
        tol = max(2.0, 0.01 * exp)
        yield {
            "name": "grand_total", "ok": abs(exp - act) <= tol,
            "expected": round(exp, 2), "actual": act, "diff": abs(exp - act),
            "base": SUM_BASE_CONF, "tokens": [sub_lab, tax_lab, tot_lab],
            "region": [tot_lab["left"], tot_lab["top"],
                       tot_lab["left"] + tot_lab["width"], tot_lab["top"] + tot_lab["height"]],
        }

    rows_bot = None
    if sub_w is not None:
        rows_bot = sub_w["top"] - 12
    elif tot_w is not None:
        rows_bot = tot_w["top"] - 12
    rows_bot = min(rows_bot, image_h) if rows_bot is not None else rows_bot
    if rows_bot is None:
        return

    cand = [w for w in words if _num(w["text"]) is not None
            and w["left"] >= 300 and w["top"] < rows_bot]
    cand.sort(key=lambda w: (w["top"], w["left"]))
    banks: list[list] = []
    for w in cand:
        if banks and w["top"] - banks[-1][-1]["top"] <= 18:
            banks[-1].append(w)
        else:
            banks.append([w])

    def xclusters(items) -> list[float]:
        cs = sorted(t["left"] + t["width"] / 2.0 for t in items)
        out: list[float] = []
        for c in cs:
            if not out or c - out[-1] > 34:
                out.append(c)
        return out

    cols: list[float] = None
    table_banks: list[list] = []
    for bk in banks:
        if cols is None:
            cl = xclusters(bk)
            if len(cl) < 3:
                continue
            cols = cl
        table_banks.append(bk)
    if cols is None or len(table_banks) < MIN_ROWS:
        return
    qc, pc, ac = cols[0], cols[1], cols[2]
    span = 55.0

    rows: list[dict] = []
    for bk in table_banks:
        cell: dict = {}
        for t in bk:
            xc = t["left"] + t["width"] / 2.0
            target = min([qc, pc, ac], key=lambda cx: abs(xc - cx))
            if abs(xc - target) <= span:
                cell.setdefault(target, t)
        if all(k in cell for k in (qc, pc, ac)):
            rows.append(cell)

    amounts = [r[ac] for r in rows]
    for r in rows:
        q = _num(r[qc]["text"])
        p = _num(r[pc]["text"])
        a = _num(r[ac]["text"])
        exp = q * p
        if all(w["conf"] >= 60 for w in (r[qc], r[pc], r[ac])) and exp > 0:
            diff = abs(exp - a)
            yield {
                "name": "line_amount", "ok": diff <= max(2.0, 0.05 * exp),
                "expected": round(exp, 2), "actual": a, "diff": diff,
                "base": ROW_BASE_CONF, "strong": diff > 0.8 * a,
                "tokens": [r[qc], r[pc], r[ac]],
                "region": [r[ac]["left"], r[ac]["top"],
                           r[ac]["left"] + r[ac]["width"], r[ac]["top"] + r[ac]["height"]],
            }

    if len(rows) == len(table_banks) and len(rows) >= MIN_ROWS and sub_lab is not None:
        exp = sum(_num(w["text"]) for w in amounts)
        act = _num(sub_lab["text"])
        tol = max(2.0, 0.01 * act)
        yield {
            "name": "subtotal", "ok": abs(exp - act) <= tol,
            "expected": round(exp, 2), "actual": act, "diff": abs(exp - act),
            "base": SUM_BASE_CONF, "tokens": amounts + [sub_lab],
            "region": [sub_lab["left"], sub_lab["top"],
                       sub_lab["left"] + sub_lab["width"], sub_lab["top"] + sub_lab["height"]],
        }


def _marksheet_checks(words, image_h):
    exclude: set[int] = set()
    typ = _typ_h(words)
    mark_hdr = _find_label(words, ["marks"], exclude, pos="last")
    if mark_hdr is None:
        return
    tot_w = _find_label(words, ["total"], exclude, pos="last")
    pct_w = _find_label(words, ["percentage"], exclude)
    exclude.update(w["index"] for w in (mark_hdr, tot_w, pct_w) if w is not None)
    if tot_w is None:
        return

    tot_lab = _value_right(tot_w, words, typ)
    if tot_lab is None:
        return
    cy = mark_hdr["left"] + mark_hdr["width"] / 2.0
    heads_top = mark_hdr["top"]
    rows_bot = tot_w["top"] - 4
    marks: list[dict] = []
    for w in words:
        if _num(w["text"]) is None:
            continue
        if not (heads_top + 14 < w["top"] < rows_bot):
            continue
        if abs(w["left"] + w["width"] / 2.0 - cy) > 40:
            continue
        marks.append(w)
    marks.sort(key=lambda w: w["top"])
    marks = [m for m in marks if not (_num(m["text"]) < 10.0 and m["conf"] < 85.0)]
    if len(marks) < MIN_ROWS:
        return

    # Row-structure guard: every data row carries a "100" in the maximum column,
    # which sits *beside* the column we anchored on. Anchor-column 100s are
    # excluded so a legitimately perfect score in the Marks column is not
    # double-counted — otherwise a marksheet with a subject scored 100 had one
    # more "100" than rows and was silently skipped instead of reconciled.
    max_marks_tokens = [w for w in words
                        if _num(w["text"]) == 100.0 and heads_top + 14 < w["top"] < rows_bot
                        and abs(w["left"] + w["width"] / 2.0 - cy) > 40]
    if len(marks) != len(max_marks_tokens) or len(marks) < MIN_ROWS:
        return

    vals = [_num(w["text"]) for w in marks]
    n = len(vals)
    exp = sum(vals)
    act = _num(tot_lab["text"])
    tol = max(2.5, 0.015 * act)
    sum_ok = abs(exp - act) <= tol
    yield {
        "name": "total", "ok": sum_ok,
        "expected": round(exp, 2), "actual": act, "diff": abs(exp - act),
        "base": SUM_BASE_CONF, "tokens": marks + [tot_lab],
        "region": [tot_lab["left"], tot_lab["top"],
                   tot_lab["left"] + tot_lab["width"], tot_lab["top"] + tot_lab["height"]],
    }

    if pct_w is not None and sum_ok:
        pct_lab = _value_right(pct_w, words, typ)
        if pct_lab is not None:
            exp_pct = round(exp / n, 1)
            act_pct = _num(pct_lab["text"])
            yield {
                "name": "percentage", "ok": abs(exp_pct - act_pct) <= 0.5,
                "expected": exp_pct, "actual": act_pct, "diff": abs(exp_pct - act_pct),
                "base": SUM_BASE_CONF, "tokens": marks + [pct_lab],
                "region": [pct_lab["left"], pct_lab["top"],
                           pct_lab["left"] + pct_lab["width"], pct_lab["top"] + pct_lab["height"]],
            }


class SemanticModule(Module):
    """Reference-free arithmetic reconciliation over OCR: invoice rows /
    subtotal / grand-total and marksheet total / percentage. Passed checks emit
    a benign "consistent" layer; a breached identity becomes a localized
    finding — with clean-document FPR 0.00 on the benchmark corpus."""

    def __init__(self) -> None:
        super().__init__(
            id="semantic",
            name="Semantic Consistency",
            category="intelligence",
            weight=0.08,
            runtime="Tesseract + arithmetic reconciliation (Forgify semantic_consistency)",
            techniques=[
                "Line amount = unit price × qty",
                "Subtotal = Σ line amounts",
                "Grand total = subtotal + tax",
                "Marksheet total = Σ marks; percentage = total ÷ n",
            ],
        )

    def run(self, context: dict) -> dict:
        started = time.time()
        image = context.get("image")
        ocr = context.get("_ocr") or tesseract_words(image)
        if ocr is None or not ocr.available or not ocr.words:
            return self.result(
                0.0, [], [], started,
                "OCR unavailable; semantic check degraded to neutral.",
                [{"label": "Checks", "value": "0"}], confidence=0.0,
            )

        words = ocr.words
        h, w = image.shape[:2]
        checks = list(_invoice_checks(words, h)) + list(_marksheet_checks(words, h))
        if not checks:
            return self.result(
                0.0, [], [], started,
                "No arithmetic structure recognized (nothing to reconcile).",
                [{"label": "Checks", "value": "0"}], confidence=0.0,
            )

        fails = [c for c in checks if not c["ok"] and c.get("strong", True)]
        if not fails:
            return self.result(
                0.0, [], [], started,
                "consistent",
                [{"label": "Checks", "value": ",".join(c["name"] for c in checks)}],
                confidence=0.0,
            )

        multi = len(fails) > 1
        findings_out: list[dict] = []
        regions_out: list[dict] = []
        worst_score = 0.0
        worst_conf = 0.0
        for c in fails:
            tokens = [t for t in c["tokens"] if t is not None and t["conf"] >= MIN_TOK_CONF]
            if not tokens:
                continue
            confidence = _conf(c["base"], tokens, multi)
            x0, y0, x1, y1 = c["region"]
            nrm = region("semantic", "Arithmetic violation", c["diff"] / max(1.0, float(c["actual"])),
                         confidence, (x0, y0, x1, y1), (h, w), "OCR arithmetic reconciliation",
                         f"{c['name']}: expected {c['expected']}, observed {c['actual']}.")
            score = confidence  # flag strength tracks trained confidence of the reconciliation
            findings_out.append(
                finding(
                    "semantic", "SEM-ARITH", f"Arithmetic inconsistency in {c['name']}",
                    band(score), confidence,
                    f"The document's own figures disagree: expected {c['expected']}, "
                    f"observed {c['actual']} (Δ {round(c['diff'], 2)}). OCR-derived "
                    "arithmetic identities must hold for every internally-consistent "
                    "document, so a breached identity localises a tampered value.",
                    [
                        {"label": "Check", "value": c["name"]},
                        {"label": "Expected", "value": f"{c['expected']}"},
                        {"label": "Observed", "value": f"{c['actual']}"},
                        {"label": "Delta", "value": f"{round(c['diff'], 2)}"},
                    ],
                    nrm, f"Δ {round(c['diff'], 2)}",
                    recommendation="Spot-check the highlighted value against the issuing authority; verify the underlying figures.",
                )
            )
            regions_out.append(nrm)
            worst_score = max(worst_score, score)
            worst_conf = max(worst_conf, confidence)

        score = float(min(0.95, worst_score))
        metric_conf = float(max(worst_conf, 0.5))
        return self.result(
            score, findings_out, regions_out, started,
            f"{len(fails)} arithmetic breach(es) in {len(checks)} check(s).",
            [{"label": "Checks", "value": str(len(checks))}, {"label": "Breaches", "value": str(len(fails))}],
            confidence=metric_conf,
        )


MODULES: list[Module] = [CompressionModule(), MetadataModule(), LayoutModule(), SemanticModule()]

__all__ = ["MODULES", "tesseract_words"]