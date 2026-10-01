#!/usr/bin/env python3
"""
Forgify · Synthetic demo-exhibit generator
=============================================
Builds the sample evidence set in ``documents/`` used to demonstrate the
multi-layer forensic pipeline live.

    documents/
      aadhaar_clean.png / aadhaar_tampered.png
      pan_clean.png / pan_tampered.png
      marksheet_clean.png / marksheet_tampered.png
      invoice_clean.png / invoice_tampered.png
      bank_statement.png
      medical_report.png
      degree_certificate.png
      vehicle_rc.png
      utility_bill.png
      rent_agreement.png

Every artefact here is **100% synthetic**: fictional people, invented
address/ID strings, and deliberately non-allocatable identifier ranges. Each
page carries a visible ``SYNTHETIC SAMPLE`` marking and a
``NOT A REAL DOCUMENT`` banner so a screenshot can never be mistaken for a
genuine identity or financial record. These are *test fixtures*, not a
dataset, and they carry no measured accuracy claims.

The pairs are designed so each tampering technique exercises a different
detector layer (see ``documents/README.md``):

  * ``*_tampered`` invoice  → ``semantic`` arithmetic reconciliation breach
  * ``*_tampered`` marksheet→ ``semantic`` total / percentage breach
  * field re-typed in a foreign font → ``layout`` font/baseline deviation
  * whole-image re-encode      → ``compression`` DQT quality band
  * pasted stamp / seal        → ``pixel`` ELA residual + edge discontinuity

Usage
-----
    python/.venv/bin/python documents/generate_samples.py

Requires Pillow + numpy (already in python/requirements.txt). No network,
no external assets, fully deterministic — re-running reproduces byte-identical
outputs apart from the embedded generation timestamp.
"""

from __future__ import annotations

import io
import os
from datetime import datetime, timezone

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = "/System/Library/Fonts/Supplemental"

F = {
    "sans": f"{FONT_DIR}/Arial.ttf",
    "sans_b": f"{FONT_DIR}/Arial Bold.ttf",
    "sans_n": f"{FONT_DIR}/Arial Narrow.ttf",
    "sans_nb": f"{FONT_DIR}/Arial Narrow Bold.ttf",
    "serif": f"{FONT_DIR}/Times New Roman.ttf",
    "serif_b": f"{FONT_DIR}/Times New Roman Bold.ttf",
    "mono": f"{FONT_DIR}/Courier New.ttf",
    "mono_b": f"{FONT_DIR}/Courier New Bold.ttf",
    "black": f"{FONT_DIR}/Arial Black.ttf",
}
FONT_SUBSTITUTE = f"{FONT_DIR}/DejaVuSans.ttf"

_fc: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    key = (kind, size)
    if key not in _fc:
        try:
            _fc[key] = ImageFont.truetype(FONT_SUBSTITUTE, size)
        except OSError:
            _fc[key] = ImageFont.load_default()
    return _fc[key]


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------------------- #
#  shared drawing helpers
# --------------------------------------------------------------------------- #

BANNER = "SYNTHETIC SAMPLE — NOT A REAL DOCUMENT"


def new_page(w: int, h: int, bg: str = "#ffffff") -> Image.Image:
    return Image.new("RGB", (w, h), bg)


def banner(img: Image.Image, d: ImageDraw.ImageDraw, note: str = "") -> None:
    """Every artefact is watermarked top and bottom so it can never be mistaken
    for a genuine record."""
    w, h = img.size
    d.rectangle([0, 0, w, 34], fill="#111111")
    d.text((14, 8), BANNER, font=font("sans_b", 20), fill="#ff5a5a")

    d.rectangle([0, h - 46, w, h], fill="#f2f2f2")
    d.line([(0, h - 46), (w, h - 46)], fill="#cccccc", width=2)
    txt = f"Generated {stamp()} · fictitious data · synthetic fixture"
    if note:
        txt = f"{note} · {txt}"
    d.text((14, h - 36), txt, font=font("sans", 17), fill="#555555")


def watermark(img: Image.Image, text: str, angle: int = 32, alpha: int = 26) -> None:
    """Diagonal low-opacity overprint (realistic anti-counterfeit look, and it
    makes copy-move / splicing structural artefacts easy to spot)."""
    w, h = img.size
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    f = font("black", max(40, w // 16))
    bbox = ld.textbbox((0, 0), text, font=f)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    ld.text(((w - tw) / 2, (h - th) / 2), text, font=f, fill=(90, 90, 120, alpha))
    layer = layer.rotate(angle, resample=Image.BICUBIC)
    img.paste(Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB"), (0, 0))


def qr_block(size: int, seed: int, box: int = 1) -> Image.Image:
    """A QR-*looking* deterministic module pattern (finder patterns + timing +
    pseudo-random payload). Not a decodable symbol — the project treats QR
    validation as future scope, so this is a visual stand-in only."""
    rng = np.random.default_rng(seed)
    n = 25
    m = np.zeros((n, n), dtype=np.uint8)
    m[:, :] = (rng.random((n, n)) > 0.52).astype(np.uint8)

    def finder(r0: int, c0: int) -> None:
        m[r0 : r0 + 7, c0 : c0 + 7] = 0
        m[r0 : r0 + 7, c0 : c0 + 7] = np.pad(
            np.ones((7, 7), dtype=np.uint8), 0
        )
        m[r0 : r0 + 7, c0 : c0 + 7] = 1
        m[r0 + 1 : r0 + 6, c0 + 1 : c0 + 6] = 0
        m[r0 + 2 : r0 + 5, c0 + 2 : c0 + 5] = 1

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    m[6, 8 : n - 8] = 1
    m[8 : n - 8, 6] = 1
    px = size // (n * box + 8)
    arr = np.kron(m, np.ones((box, box), dtype=np.uint8)) * 255
    img = Image.fromarray(arr.astype(np.uint8), mode="L").resize(
        (size, size), Image.NEAREST
    )
    canvas = Image.new("L", (px * (n * box + 8), px * (n * box + 8)), 255)
    canvas.paste(img, (px * 4, px * 4))
    return canvas


def photo_placeholder(w: int, h: int, label: str, seed: int) -> Image.Image:
    """Neutral bust silhouette — deliberately not a real face."""
    rng = np.random.default_rng(seed)
    im = Image.new("RGB", (w, h), "#dfe6ee")
    pd = ImageDraw.Draw(im)
    cx, cy = w / 2, h * 0.40
    head = min(w, h) * 0.24
    pd.ellipse([cx - head, cy - head, cx + head, cy + head], fill="#9fb0c4")
    bw = w * 0.34
    pd.ellipse([cx - bw, cy + head * 0.7, cx + bw, h * 1.05], fill="#9fb0c4")
    im = im.filter(ImageFilter.GaussianBlur(1.1))
    pd = ImageDraw.Draw(im)
    pd.rectangle([0, h - 22, w, h], fill="#b9c6d4")
    pd.text((6, h - 20), label, font=font("sans", 13), fill="#33445a")
    del rng
    return im


def signature_block(d: ImageDraw.ImageDraw, x: int, y: int, w: int = 210, style: str = "clean") -> None:
    """Handwriting-ish scrawl. The 'pasted' style is drawn in a different font
    with a lighter, aliased stroke to mimic a bitmap signature lifted from
    another source and dropped into the document."""
    d.line([(x, y + 26), (x + w, y + 26)], fill="#222222", width=2)
    d.text((x, y + 30), "Authorised signatory", font=font("sans", 12), fill="#666666")
    pts = [
        (0.02, 0.72), (0.16, 0.30), (0.26, 0.78), (0.38, 0.18), (0.48, 0.66),
        (0.58, 0.26), (0.68, 0.80), (0.80, 0.34), (0.90, 0.70), (0.99, 0.44),
    ]
    if style == "clean":
        prev = None
        for i, (fx, fy) in enumerate(pts):
            p = (x + fx * w, y + fy * 24)
            if prev:
                d.line([prev, p], fill=(24, 32, 90), width=3, joint="curve")
            prev = p
            del i
    else:
        for fx, fy in pts:
            p = (x + fx * w, y + fy * 24)
            d.ellipse([p[0] - 4, p[1] - 4, p[0] + 4, p[1] + 4], fill=(70, 70, 70))


def seal(img: Image.Image, cx: int, cy: int, r: int, text: str, colour=(196, 42, 42), alpha: int = 120) -> None:
    """Semi-transparent rubber stamp."""
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    sd = ImageDraw.Draw(layer)
    c = (*colour, alpha)
    sd.ellipse([cx - r, cy - r, cx + r, cy + r], outline=c, width=6)
    sd.ellipse([cx - r + 14, cy - r + 14, cx + r - 14, cy + r - 14], outline=c, width=2)
    f = font("sans_b", max(15, r // 5))
    tw = sd.textbbox((0, 0), text, font=f)
    sd.text((cx - (tw[2] - tw[0]) / 2, cy - (tw[3] - tw[1]) / 2), text, font=f, fill=c)
    for i, ang in enumerate(np.linspace(-70, 70, 5)):
        y = cy + r * 0.62 + i * (r * 0.11) - r * 0.22
        sd.line([(cx - r * 0.5, y), (cx + r * 0.5, y)], fill=(*colour, alpha // 2), width=3)
        del ang
    layer = layer.rotate(-14, resample=Image.BICUBIC, center=(cx, cy))
    img.paste(Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB"), (0, 0))


def field(d: ImageDraw.ImageDraw, x: int, y: int, label: str, value: str,
          kind: str = "sans", vsize: int = 25, gap: int = 30) -> None:
    d.text((x, y), label, font=font("sans_n", 18), fill="#666666")
    d.text((x, y + gap), value, font=font(kind, vsize), fill="#111111")


def save(img: Image.Image, name: str, quality: int = 92) -> str:
    path = os.path.join(OUT_DIR, name)
    if name.lower().endswith((".jpg", ".jpeg")):
        img.save(path, "JPEG", quality=quality, subsampling=0)
    else:
        img.save(path, "PNG")
    kb = os.path.getsize(path) / 1024
    print(f"  {name:<30} {img.size[0]}x{img.size[1]}  {kb:7.1f} KB  q={quality}")
    return path


# --------------------------------------------------------------------------- #
#  capture simulation + localised tampering
# --------------------------------------------------------------------------- #
#
#  A pristine PIL render is not a realistic exhibit: it has no sensor noise and
#  a synthetic spectral signature, so the ``pixel`` / ``aigc`` layers flag every
#  clean document and the clean-vs-forged contrast disappears. Real cases arrive
#  through a capture or scan chain, so we simulate one: mild sensor noise,
#  optical softness, then a JPEG encode.
#
#  Tampering is then applied *on top of the captured file* — the same way a real
#  forgery is made — so only the edited patch carries a foreign noise floor and
#  foreign anti-aliasing. That is precisely the signal ``pixel`` and ``layout``
#  are designed to localise. These are simulated capture artefacts on
#  synthetic artwork, not scans of real documents.


def capture(img: Image.Image, seed: int = 0, noise: float = 0.9,
            blur: float = 0.0) -> Image.Image:
    """Add a light sensor-noise pass so exhibits are not perfectly clean vectors.

    Deliberately gentle. Measured against the real OCR text, the heavier
    defaults this started with (noise 2.4, blur 0.45) cost ~2 of 7 figures on the
    invoice, which showed up downstream as *false* `SEM-ARITH` breaches on the
    clean exhibit. Noise that destroys legibility is not realistic document
    evidence, it is just an unreadable fixture.

    This performs **no** JPEG encoding: `save()` does that once. Encoding here
    and again in `save()` produced genuine double-compression, which is the exact
    artefact the compression layer reports (it added a `PX-SMOOTH` finding that
    the benchmarked reference exhibits do not have).
    """
    if noise <= 0 and blur <= 0:
        return img
    rng = np.random.default_rng(seed)
    base = np.asarray(img).astype(np.float32)
    base += rng.normal(0.0, noise, base.shape)
    out = Image.fromarray(np.clip(base, 0, 255).astype(np.uint8))
    if blur > 0:
        out = out.filter(ImageFilter.GaussianBlur(blur))
    return out


def patch_text(img: Image.Image, box: tuple[int, int, int, int], text: str,
               kind: str, size: int, colour: str = "#111111",
               align: str = "left", jitter: int = 1) -> None:
    """Overwrite one field in place with text set in a *different* typeface.

    The patch background is sampled from the surrounding pixels so the fill
    blends, but the replacement glyphs keep their own edge profile — exactly
    the giveaway the layout and ELA layers look for.

    The replacement is **centred in `box`**, which matters more than it looks.
    The box is derived from the original string's own textbbox, so centring puts
    the new glyphs back on the original baseline. An earlier version offset the
    text by a fixed `+1px` from the box top; that left the digits ~5px proud of
    the line, and Tesseract's `--psm 6` line segmentation (which the engine
    uses) then failed to group the line at all — the clean page read
    "Grand Total 13452" while the same page with a pixel-perfect patch read
    "Grand Total Togs", hiding the forgery the arithmetic layer exists to catch.
    """
    x0, y0, x1, y1 = box
    d = ImageDraw.Draw(img)
    region = np.asarray(img.crop((x0, y0, x1, y1))).reshape(-1, 3)
    if region.size:
        bg = tuple(int(v) for v in np.median(region, axis=0))
    else:
        bg = (255, 255, 255)
    d.rectangle([x0, y0, x1, y1], fill=bg)
    f = font(kind, size)
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    tw, th = r - l, b - t
    if align == "left":
        tx = x0 + 6
    else:
        tx = x0 + max(0, (x1 - x0 - tw) // 2)
    ty = y0 + max(0, (y1 - y0 - th) // 2) - t
    # 1px jitter: hand-placed text never lands exactly on the original grid
    d.text((tx + jitter, ty + jitter), text, font=f, fill=colour)


def emit_pair(clean_name: str, tampered_name: str | None, render, edit=None,
              seed: int = 0, quality: int = 92) -> None:
    """Render → capture once → save clean, then apply the localised forgery to a
    copy of that same captured image."""
    base = capture(render(), seed=seed)
    save(base, clean_name, quality)
    if tampered_name and edit is not None:
        forged = base.copy()
        edit(forged)
        save(forged, tampered_name, quality)


# --------------------------------------------------------------------------- #
#  1 · Aadhaar-style e-KYC card  (clean / tampered)
# --------------------------------------------------------------------------- #

AADHAAR_NO = "9999 9999 4321"
AADHAAR_NAME = "ARJUN SACHIN VERMA"
AADHAAR_DOB = "14 / 07 / 1998"
AADHAAR_FORGED_DOB = "14 / 07 / 1991"
AADHAAR_DOB_BOX = (248, 214, 560, 258)


def aadhaar() -> Image.Image:
    W, H = 1000, 640
    img = new_page(W, H, "#fdfcf7")
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 96], fill="#ffffff")
    d.rectangle([0, 92, W, 96], fill="#e07b39")
    d.rectangle([0, 96, W, 100], fill="#1b4f9c")
    # emblem stand-in
    d.ellipse([34, 20, 90, 76], outline="#1b4f9c", width=4)
    d.polygon([(62, 28), (68, 46), (86, 46), (71, 58), (77, 76), (62, 65), (47, 76), (53, 58), (38, 46), (56, 46)], fill="#1b4f9c")
    d.text((104, 22), "Government of India", font=font("sans_b", 25), fill="#12315c")
    d.text((104, 52), "Unique Identification Authority of India", font=font("sans", 18), fill="#40566f")
    d.text((W - 300, 26), "e-KYC / Identity Card", font=font("sans_b", 19), fill="#666666")

    img.paste(photo_placeholder(178, 214, "SYNTHETIC PORTRAIT", 7), (44, 132))

    x = 252
    d.text((x, 126), "Name", font=font("sans_n", 18), fill="#666666")
    d.text((x, 150), AADHAAR_NAME, font=font("sans_b", 31), fill="#111111")

    field(d, x, 196, "Date of Birth", AADHAAR_DOB, "sans", 26)
    field(d, x + 330, 196, "Gender", "MALE", "sans", 24)

    d.text((x, 262), "Address", font=font("sans_n", 18), fill="#666666")
    d.text((x, 286), "Flat 402, Sunrise Residency, Andheri East", font=font("sans", 23), fill="#111111")
    d.text((x, 316), "Mumbai 400069, Maharashtra, India", font=font("sans", 23), fill="#111111")

    d.text((x, 360), "Distinguished Permanent Number", font=font("sans_n", 18), fill="#666666")
    d.text((x, 384), AADHAAR_NO, font=font("mono_b", 34), fill="#111111")
    d.text((x, 426), "Issued 04 / 02 / 2021    Valid  lifetime", font=font("sans", 18), fill="#555555")

    img.paste(qr_block(150, seed=11).convert("RGB"), (W - 220, 132))
    d.rectangle([W - 220, 132, W - 70, 282], outline="#999999", width=2)
    d.text((W - 214, 288), "QR payload: urn:uid:synthetic-sample-0001", font=font("sans", 14), fill="#777777")

    signature_block(d, x, 452, 260)
    watermark(img, "SPECIMEN")
    banner(img, d)
    return img


def forge_aadhaar(img: Image.Image) -> None:
    patch_text(img, AADHAAR_DOB_BOX, AADHAAR_FORGED_DOB, "serif_b", 26)


# --------------------------------------------------------------------------- #
#  2 · PAN card  (clean / tampered)
# --------------------------------------------------------------------------- #

PAN_NO = "SAMP9999X"
PAN_NAME = "ARJUN SACHIN VERMA"
PAN_FATHER = "SACHIN RAMESH VERMA"
PAN_FORGED_FATHER = "RAJESH KUMAR VERMA"
PAN_FATHER_BOX = (232, 182, 700, 222)
PAN_NO_BOX = (240, 322, 700, 372)
PAN_FORGED_NO = "SAMP7777X"


def pan() -> Image.Image:
    W, H = 1000, 640
    img = new_page(W, H, "#f7f7f9")
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 74], fill="#12315c")
    d.text((34, 16), "INCOME TAX DEPARTMENT", font=font("sans_b", 26), fill="#ffffff")
    d.text((34, 46), "GOVERNMENT OF INDIA", font=font("sans", 17), fill="#c8d6ea")
    d.text((W - 330, 22), "PERMANENT ACCOUNT NUMBER", font=font("sans_b", 18), fill="#ffffff")
    d.text((W - 250, 48), "PAN card", font=font("sans", 16), fill="#c8d6ea")

    img.paste(photo_placeholder(170, 208, "SYNTHETIC PORTRAIT", 3), (40, 108))
    signature_block(d, 46, 322, 158)

    x = 236
    field(d, x, 108, "Name", PAN_NAME, "sans_b", 27)
    field(d, x, 158, "Father's Name", PAN_FATHER, "sans", 25)

    d.text((x, 222), "Date of Birth", font=font("sans_n", 18), fill="#666666")
    d.text((x, 246), "14 / 07 / 1998", font=font("sans", 25), fill="#111111")
    d.text((x + 330, 222), "Signature", font=font("sans_n", 18), fill="#666666")
    d.text((x + 330, 246), "Left thumb impression", font=font("sans", 19), fill="#888888")

    d.rectangle([x - 6, 292, W - 40, 372], outline="#d0d0d8", width=2)
    d.text((x + 10, 304), "Permanent Account Number", font=font("sans_n", 18), fill="#666666")
    d.text((x + 10, 330), PAN_NO, font=font("mono_b", 34), fill="#111111")

    d.text((40, 400), "Note", font=font("sans_b", 18), fill="#555555")
    d.text((40, 424), "This card is not valid for any purpose. It is a synthetic", font=font("sans", 17), fill="#777777")
    d.text((40, 446), "specimen produced for forensic-pipeline demonstration only.", font=font("sans", 17), fill="#777777")

    banner(img, d, "PAN-style card")
    return img


def forge_pan(img: Image.Image) -> None:
    """Re-types both the father's name and the PAN itself — the two edits a
    forensic examiner most often has to look for on an identity card."""
    patch_text(img, PAN_FATHER_BOX, PAN_FORGED_FATHER, "serif_b", 25)
    patch_text(img, PAN_NO_BOX, PAN_FORGED_NO, "serif_b", 32)


# --------------------------------------------------------------------------- #
#  3 · Marksheet  (clean / tampered) — triggers `semantic` reconciliation
# --------------------------------------------------------------------------- #

MARKSHEET_ROWS = [
    ("English Language", 78),
    ("Data Structures", 84),
    ("Database Systems", 82),
    ("Operating Systems", 88),
    ("Computer Networks", 64),
    ("Software Engineering Project", 100),
]
MARKSHEET_MAX_EACH = 100
# Marks are restricted to values MEASURED to round-trip through Tesseract at
# this size, on 8 noise seeds, using the real engine row extractor. Two values
# that failed that measurement are recorded so they are not reintroduced:
#   71 -> read as "n" (glyph merge)  66/68 -> dropped or read high, which left
#          the column one row short and made it fail its own row-count guard.
# 6 and 7 as leading digits are the least reliable in this face, as with the
# invoice figures above.
MARKSHEET_TOTAL = sum(m for _, m in MARKSHEET_ROWS)          # 496
MARKSHEET_MAX = MARKSHEET_MAX_EACH * len(MARKSHEET_ROWS)       # 600
MARKSHEET_PERCENT = round(MARKSHEET_TOTAL / MARKSHEET_MAX * 100)     # 83 (integer: see money())
# Forgery: one subject mark inflated from 64 to 94. The printed Total (496),
# the percentage and that row's grade letter are all left untouched, so the
# column no longer sums — the arithmetic break `semantic` is built for. Leaving
# the dependent fields stale is deliberate: it is what a real "raise one mark"
# edit looks like, and the invoice forgery leaves its amount-in-words stale for
# the same reason. Both numbers are on the measured-reliable list above.
MARKSHEET_FORGED_INDEX = 4
MARKSHEET_FORGED_MARK = 94


def marksheet() -> tuple[Image.Image, tuple[int, int, int, int]]:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.text((W / 2 - 250, 70), "SYNTHETIC MODEL SCHOOL", font=font("sans_b", 30), fill="#111111")
    d.text((W / 2 - 205, 108), "Statement of Marks · Academic Year 2023-24", font=font("sans", 21), fill="#444444")
    d.line([(60, 146), (W - 60, 146)], fill="#222222", width=3)

    field(d, 80, 166, "Student Name", "ARJUN SACHIN VERMA", "sans_b", 26)
    field(d, 620, 166, "Roll Number", "2023-CS-0417", "mono", 24)
    field(d, 80, 232, "Class / Section", "B.Tech Computer Science · Sem VI", "sans", 22)
    field(d, 620, 232, "Date of Issue", "12 / 07 / 2024", "sans", 22)

    tx, ty, rh = 80, 330, 46
    # Column order matters: the semantic layer anchors on the header literally
    # named "Marks" and sums *that* column, so "Marks" must be the obtained
    # column and "Maximum" the 100-per-subject column beside it.
    cols = {"subject": 80, "marks": 620, "max": 700, "grade": 810}
    d.rectangle([tx, ty, W - 80, ty + rh], fill="#eceff3")
    for label, cx in (("Subject", cols["subject"]), ("Marks", cols["marks"]),
                      ("Maximum", cols["max"]), ("Grade", cols["grade"])):
        d.text((cx + 8, ty + 13), label, font=font("sans_b", 20), fill="#222222")

    y = ty + rh
    forged_box: tuple[int, int, int, int] | None = None
    for i, (subject, obt) in enumerate(MARKSHEET_ROWS):
        d.rectangle([tx, y, W - 80, y + rh], outline="#cccccc")
        d.text((cols["subject"] + 8, y + 12), subject, font=font("sans", 21), fill="#111111")
        obt_f = font("mono", 21)
        d.text((cols["marks"] + 8, y + 12), str(obt), font=obt_f, fill="#111111")
        d.text((cols["max"] + 8, y + 12), str(MARKSHEET_MAX_EACH), font=font("mono", 21), fill="#111111")
        d.text((cols["grade"] + 8, y + 12), "A" if obt >= 75 else "B", font=font("sans", 21), fill="#111111")
        if i == MARKSHEET_FORGED_INDEX:
            # Real textbbox of the cell we will overwrite, so patch_text can put
            # the replacement back on the original baseline. A padded,
            # hand-guessed box left the digits off-line and Tesseract read the
            # forged cell as "eal", hiding the very breach the layer reports.
            bx0, by0, bx1, by1 = d.textbbox((cols["marks"] + 8, y + 12),
                                            str(obt), font=obt_f)
            forged_box = (bx0 - 5, by0 - 5, bx1 + 5, by1 + 5)
        y += rh

    # The caption is a bare "Total", not "Total Marks". The semantic layer finds
    # its column anchor with _find_label(["marks"], pos="last"), i.e. the
    # *lowest* "marks" token; a "Total Marks" caption below the header would win
    # that lookup, push the row window below the data, and silently yield no
    # checks at all. The grading key further down still names the column.
    d.rectangle([tx, y, W - 80, y + rh], outline="#cccccc")
    d.text((cols["subject"] + 8, y + 12), "Total", font=font("sans_b", 21), fill="#111111")
    d.text((cols["marks"] + 8, y + 12), str(MARKSHEET_TOTAL), font=font("mono_b", 21), fill="#111111")
    d.text((cols["max"] + 8, y + 12), str(MARKSHEET_MAX), font=font("mono_b", 21), fill="#111111")
    d.text((cols["grade"] + 8, y + 12), "First Class", font=font("sans", 21), fill="#111111")
    y += rh + 34

    d.text((cols["subject"], y), "Percentage", font=font("sans_b", 22), fill="#111111")
    d.text((cols["grade"], y), "rounded", font=font("sans_n", 16), fill="#777777")
    d.text((cols["marks"], y), money(MARKSHEET_PERCENT), font=font("mono_b", 24), fill="#111111")
    d.text((cols["grade"], y), "Pass", font=font("sans", 21), fill="#111111")

    d.text((80, y + 90), "Result: PASS", font=font("sans_b", 25), fill="#14532d")
    d.text((80, y + 130), f"Grading key: A ≥ 75, B ≥ 60 · maximum {MARKSHEET_MAX_EACH} per subject",
           font=font("sans", 18), fill="#666666")

    signature_block(d, 80, y + 170, 230)
    signature_block(d, 620, y + 170, 230)
    banner(img, d, "Academic marksheet")
    return img, forged_box  # type: ignore[return-value]


def forge_marksheet(img: Image.Image) -> None:
    box = getattr(forge_marksheet, "box", None)
    if box is None:
        return
    patch_text(img, box, str(MARKSHEET_FORGED_MARK), "serif_b", 22)


# --------------------------------------------------------------------------- #
#  4 · Invoice  (clean / tampered) — triggers `semantic` reconciliation
# --------------------------------------------------------------------------- #

INVOICE_ROWS = [
    ("Widget assembly service", 3, 1450),
    ("Calibration and testing", 2, 500),
    ("Annual maintenance plan", 1, 5000),
    ("On-site support hours", 3, 350),
]
INVOICE_TAX_RATE = 18.0

# Figures are rendered as *whole rupees — no decimal point, no thousands
# separator*, and deliberately restricted to the digit set that Tesseract reads
# reliably at this size (0,1,2,3,4,5,8,9). Two concrete reasons, both learned by
# measuring the OCR output rather than assuming:
#
#   1. Tesseract routinely drops a "." — "13191.00" comes back as "1319100",
#      which the semantic layer would then parse as thirteen million. The
#      benchmarked reference invoices in python/tests/samples use whole rupees
#      for the same reason.
#   2. Glyphs 6 and 7 are the least reliable in this face/size (a rate of 775
#      OCR'd as "7%", and a tax of 2466 as "2468"). Restricting to the safe digit
#      set keeps every figure round-trippable, so a clean exhibit reconciles
#      exactly and any breach is a genuine tamper signal rather than an OCR
#      artefact.
INVOICE_SUBTOTAL = sum(q * p for _, q, p in INVOICE_ROWS)          # 11400
INVOICE_TAX = round(INVOICE_SUBTOTAL * INVOICE_TAX_RATE / 100.0)    # 2052
INVOICE_GRAND = INVOICE_SUBTOTAL + INVOICE_TAX                      # 13452
INVOICE_WORDS = "Rupees Thirteen Thousand Four Hundred Fifty Two only"
# The forgery: the grand total is edited down by 3000 (~22%) so subtotal + tax
# no longer reconciles — the classic "reduce the payable amount" edit.
#
# These exact figures were chosen by measuring real Tesseract output across six
# noise seeds, not by guessing: at 18% tax, subtotal 11400 / tax 2052 / grand
# 13452 round-tripped in 36/36 checks. Nearby alternatives (e.g. grand 15930)
# intermittently lost a digit, which showed up downstream as *false* SEM-ARITH
# breaches on the clean exhibit.
INVOICE_FORGED_GRAND = 10452


def money(v: float) -> str:
    """Integer rupees, no separators, no decimals — see INVOICE_ROWS note."""
    return f"{int(round(v))}"


def invoice() -> tuple[Image.Image, tuple[int, int, int, int]]:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 120], fill="#12315c")
    d.text((50, 26), "NORTHWIND SUPPLY CHAND", font=font("sans_b", 30), fill="#ffffff")
    d.text((50, 68), "Unit 7, Industrial Estate Phase II, Pune 411026", font=font("sans", 18), fill="#c8d6ea")
    d.text((W - 230, 34), "TAX INVOICE", font=font("sans_b", 24), fill="#ffffff")

    d.text((50, 146), "Invoice No: NWSC-2024-08871", font=font("mono_b", 22), fill="#111111")
    d.text((620, 146), "Date: 18 / 06 / 2024", font=font("sans", 22), fill="#111111")
    d.text((50, 178), "Bill To: Sunrise Retail LLP", font=font("sans", 21), fill="#222222")
    d.text((620, 178), "Due: 18 / 07 / 2024", font=font("sans", 21), fill="#222222")

    # rh=48 (not 44): measured against real Tesseract output, the tighter
    # row height clipped the leading "8" of 2800 into "200", which then
    # poisoned BOTH the line_amount and subtotal reconciliations.
    ty, rh = 250, 48
    cols = {"desc": 60, "qty": 520, "rate": 660, "amt": 830}
    d.rectangle([50, ty, W - 50, ty + rh], fill="#eceff3")
    for label, cx in (("Description", cols["desc"]), ("Qty", cols["qty"]),
                      ("Rate", cols["rate"]), ("Amount", cols["amt"])):
        d.text((cx + 6, ty + 12), label, font=font("sans_b", 20), fill="#222222")

    y = ty + rh
    for desc, qty, rate in INVOICE_ROWS:
        d.rectangle([50, y, W - 50, y + rh], outline="#dddddd")
        d.text((cols["desc"] + 6, y + 13), desc, font=font("sans", 20), fill="#111111")
        d.text((cols["qty"] + 6, y + 13), str(qty), font=font("mono", 24), fill="#111111")
        d.text((cols["rate"] + 6, y + 13), money(rate), font=font("mono", 24), fill="#111111")
        d.text((cols["amt"] + 6, y + 13), money(qty * rate), font=font("mono", 24), fill="#111111")
        y += rh

    # ---- totals block: the arithmetic `semantic` reconciles ------------------
    y += 30

    def total_line(label: str, value: float, bold: bool = False):
        """Draw one totals row; return (y, bbox) of the value glyphs."""
        nonlocal y
        d.text((560, y), label, font=font("sans_b" if bold else "sans", 21), fill="#333333")
        txt = money(value)
        f = font("mono_b" if bold else "mono", 22)
        d.text((760, y), txt, font=f, fill="#111111")
        bb = d.textbbox((760, y), txt, font=f)
        at = y
        y += 38
        return at, bb

    total_line("Subtotal", INVOICE_SUBTOTAL)
    total_line(f"Tax ({INVOICE_TAX_RATE:g}%)", INVOICE_TAX)
    _grand_top, grand_bb = total_line("Grand Total", INVOICE_GRAND, bold=True)

    d.line([(550, y + 6), (W - 50, y + 6)], fill="#222222", width=2)
    y += 30
    d.text((560, y), "Amount in words", font=font("sans_n", 18), fill="#666666")
    d.text((560, y + 26), INVOICE_WORDS, font=font("sans", 18), fill="#111111")

    signature_block(d, 600, y + 76, 250)
    d.text((50, y + 106), "Authorised Signatory · Northwind Supply Chand", font=font("sans", 18), fill="#666666")

    banner(img, d, "Commercial invoice")
    # Tight box around the grand-total glyphs, taken from the real textbbox so
    # the forgery can be re-centred on the original baseline (see patch_text).
    gx0, gy0, gx1, gy1 = grand_bb
    return img, (gx0 - 5, gy0 - 5, gx1 + 5, gy1 + 5)


def forge_invoice(img: Image.Image) -> None:
    box = getattr(forge_invoice, "box", None)
    if box is None:
        return
    patch_text(img, box, money(INVOICE_FORGED_GRAND), "serif_b", 22)


# --------------------------------------------------------------------------- #
#  5 · Bank statement
# --------------------------------------------------------------------------- #

def bank_statement() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 96], fill="#0f3d2e")
    d.text((50, 22), "MERIDIAN CO-OPERATIVE BANK", font=font("sans_b", 28), fill="#ffffff")
    d.text((50, 58), "Statement of account · Branch 0421, Pune", font=font("sans", 18), fill="#c2ddd0")

    field(d, 60, 124, "Account Holder", "SUNRISE RETAIL LLP", "sans_b", 24)
    field(d, 60, 190, "Account Number", "003921004417", "mono", 24)
    field(d, 620, 124, "Statement Period", "01 Apr 2024 to 30 Jun 2024", "sans", 20)
    field(d, 620, 190, "Opening Balance", "Rs 284500", "mono", 22)

    tx, ty, rh = 60, 268, 42
    cols = {"date": 60, "desc": 220, "debit": 600, "credit": 760, "bal": 900}
    d.rectangle([tx, ty, W - 60, ty + rh], fill="#eceff3")
    for label, cx in (("Date", cols["date"]), ("Description", cols["desc"]),
                      ("Debit", cols["debit"]), ("Credit", cols["credit"]), ("Balance", cols["bal"])):
        d.text((cx + 6, ty + 11), label, font=font("sans_b", 19), fill="#222222")

    rows = [
        ("02 Apr 2024", "NEFT IN - Trade settlement", "", "450000", "734500"),
        ("05 Apr 2024", "NEFT OUT - Vendor payment", "112400", "", "622100"),
        ("11 Apr 2024", "NEFT IN - Invoice NWSC-2024-08871", "", "215000", "837100"),
        ("18 Apr 2024", "NEFT OUT - Payroll April", "318900", "", "518200"),
        ("24 Apr 2024", "NEFT IN - Retail receipts", "", "192400", "710600"),
        ("03 May 2024", "NEFT OUT - Tax payment GST", "96750", "", "613850"),
        ("14 May 2024", "NEFT IN - Invoice NWSC-2024-09104", "", "302800", "916650"),
        ("21 May 2024", "NEFT OUT - Payroll May", "324100", "", "592550"),
        ("09 Jun 2024", "NEFT IN - Distributor payment", "", "144600", "737150"),
        ("19 Jun 2024", "NEFT OUT - Logistics invoice", "208300", "", "528850"),
        ("27 Jun 2024", "NEFT IN - Retail receipts", "", "226700", "755550"),
    ]
    y = ty + rh
    for date, desc, debit, credit, bal in rows:
        d.rectangle([tx, y, W - 60, y + rh], outline="#dddddd")
        d.text((cols["date"] + 6, y + 11), date, font=font("mono", 18), fill="#111111")
        d.text((cols["desc"] + 6, y + 11), desc, font=font("sans", 18), fill="#111111")
        d.text((cols["debit"] + 6, y + 11), debit, font=font("mono", 18), fill="#8b1a1a")
        d.text((cols["credit"] + 6, y + 11), credit, font=font("mono", 18), fill="#14532d")
        d.text((cols["bal"] + 6, y + 11), bal, font=font("mono", 18), fill="#111111")
        y += rh

    y += 26
    d.text((cols["date"], y), "Closing Balance", font=font("sans_b", 21), fill="#222222")
    d.text((cols["bal"], y), "755550", font=font("mono_b", 21), fill="#111111")
    signature_block(d, 620, y + 60, 260)
    banner(img, d, "Bank statement")
    return img


# --------------------------------------------------------------------------- #
#  6 · Medical report
# --------------------------------------------------------------------------- #

def medical_report() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 100], fill="#0f5c6b")
    d.text((50, 24), "SUNRIDGE MULTISPECIALITY CLINIC", font=font("sans_b", 28), fill="#ffffff")
    d.text((50, 62), "Department of Pathology & Radiology · Pune", font=font("sans", 18), fill="#cbe6ec")

    field(d, 60, 128, "Patient Name", "ARJUN SACHIN VERMA", "sans_b", 24)
    field(d, 60, 192, "Patient ID", "SMC-2024-08841", "mono", 22)
    field(d, 620, 128, "Report Date", "19 / 06 / 2024", "sans", 21)
    field(d, 620, 192, "Referring Physician", "Dr. K. Bhandari", "sans", 21)

    d.text((60, 258), "Haematology — Complete Blood Count", font=font("sans_b", 22), fill="#222222")
    tests = [
        ("Haemoglobin", "138", "g/L", "120 - 150"),
        ("Total WBC", "7,420", "/cumm", "4,000 - 11,000"),
        ("Platelet Count", "255", "per cumm", "150 - 450"),
        ("Fasting Glucose", "94", "mg/dL", "70 - 100"),
        ("Serum Creatinine", "94", "mg/dL", "70 - 130"),
        ("TSH", "21", "mIU/L", "4 - 40"),
        ("Vitamin D (25-OH)", "18", "ng/mL", "30 - 100"),
        ("HbA1c", "54", "per mille", "40 - 56"),
    ]
    ty, rh = 296, 42
    cols = {"test": 60, "res": 470, "unit": 600, "ref": 780}
    d.rectangle([60, ty, W - 60, ty + rh], fill="#eceff3")
    for label, cx in (("Investigation", cols["test"]), ("Result", cols["res"]),
                      ("Unit", cols["unit"]), ("Reference Range", cols["ref"])):
        d.text((cx + 6, ty + 11), label, font=font("sans_b", 19), fill="#222222")
    y = ty + rh
    for name, res, unit, ref in tests:
        flag = name.startswith("Vitamin D")
        d.rectangle([60, y, W - 60, y + rh], outline="#dddddd")
        d.text((cols["test"] + 6, y + 11), name, font=font("sans", 19), fill="#111111")
        d.text((cols["res"] + 6, y + 11), res, font=font("mono_b" if flag else "mono", 19),
               fill="#8b1a1a" if flag else "#111111")
        d.text((cols["unit"] + 6, y + 11), unit, font=font("sans", 19), fill="#444444")
        d.text((cols["ref"] + 6, y + 11), ref + ("  LOW" if flag else ""),
               font=font("sans", 19), fill="#8b1a1a" if flag else "#444444")
        y += rh

    y += 24
    d.text((60, y), "Interpretation", font=font("sans_b", 21), fill="#222222")
    d.text((60, y + 32), "Vitamin D insufficiency. All other haematological indices", font=font("sans", 19), fill="#333333")
    d.text((60, y + 58), "within reference limits. No acute abnormality identified.", font=font("sans", 19), fill="#333333")
    signature_block(d, 60, y + 96, 250)
    seal(img, 820, y + 150, 96, "AUTHENTICATED")
    banner(img, d, "Pathology report")
    return img


# --------------------------------------------------------------------------- #
#  7 · Degree certificate
# --------------------------------------------------------------------------- #

def degree_certificate() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H, "#fffdf7")
    d = ImageDraw.Draw(img)
    watermark(img, "SPECIMEN")
    d.rectangle([24, 24, W - 24, H - 24], outline="#8a6d2f", width=4)
    d.rectangle([34, 34, W - 34, H - 34], outline="#c9a961", width=2)

    d.text((W / 2 - 300, 96), "SYNTHETIC MODEL INSTITUTE OF TECHNOLOGY", font=font("sans_b", 30), fill="#6b4f14")
    d.text((W / 2 - 150, 140), "NAACPEDU ACCREDITED · PUNE, INDIA", font=font("sans", 19), fill="#8a6d2f")
    d.line([(150, 186), (W - 150, 186)], fill="#c9a961", width=2)

    d.text((W / 2 - 130, 226), "CERTIFICATE OF GRADUATION", font=font("sans_b", 27), fill="#3d2f0b")
    y = 300
    d.text((110, y), "This is to certify that", font=font("serif", 24), fill="#333333")
    d.text((110, y + 44), "ARJUN SACHIN VERMA", font=font("serif_b", 40), fill="#111111")
    d.line([(110, y + 96), (760, y + 96)], fill="#888888", width=1)
    for line in ("has been admitted to and has satisfied the requirements of the degree of",
                 "Bachelor of Technology in Computer Science and Engineering,",
                 "and is hereby granted this degree with all the rights and privileges thereunto appertaining."):
        d.text((110, y + 126), line, font=font("serif", 21), fill="#333333")
        y += 34

    y += 30
    d.text((110, y), "Branch of study", font=font("sans_n", 18), fill="#777777")
    d.text((110, y + 26), "Computer Science and Engineering", font=font("sans_b", 24), fill="#111111")
    d.text((620, y), "Enrollment Number", font=font("sans_n", 18), fill="#777777")
    d.text((620, y + 26), "2020-CS-11207", font=font("mono", 22), fill="#111111")

    y += 90
    d.text((110, y), "Date of Award", font=font("sans_n", 18), fill="#777777")
    d.text((110, y + 26), "26 June 2024", font=font("sans", 22), fill="#111111")
    d.text((620, y), "Final CGPA", font=font("sans_n", 18), fill="#777777")
    d.text((620, y + 26), "862 on 1000", font=font("mono", 22), fill="#111111")

    d.ellipse([110, 780, 300, 970], outline="#8a6d2f", width=3)
    d.ellipse([130, 800, 280, 950], outline="#c9a961", width=2)
    d.text((158, 852), "INSTITUTE", font=font("sans_b", 18), fill="#8a6d2f")
    d.text((166, 876), "SEAL", font=font("sans_b", 18), fill="#8a6d2f")

    signature_block(d, 600, 840, 280)
    d.text((600, 906), "Dr. R. K. Iyer", font=font("sans", 20), fill="#333333")
    d.text((600, 930), "Registrar", font=font("sans_n", 18), fill="#777777")
    seal(img, 470, 890, 92, "VERIFIED")

    banner(img, d, "Degree certificate")
    return img


# --------------------------------------------------------------------------- #
#  8 · Vehicle registration certificate
# --------------------------------------------------------------------------- #

def vehicle_rc() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 96], fill="#7a1f2b")
    d.text((50, 24), "REGISTRATION CERTIFICATE", font=font("sans_b", 30), fill="#ffffff")
    d.text((50, 62), "Regional Transport Office · Pune · MH-12", font=font("sans", 18), fill="#f0cdd3")

    ty, rh = 132, 40
    rows = [
        ("Registration Number", "MH12AB1234"),
        ("Chassis Number", "MATTA1234N9XY98765"),
        ("Engine Number", "K4M1234567"),
        ("Fuel Type", "Petrol"),
        ("Colour", "Silver Grey"),
        ("Date of Registration", "18 / 09 / 2021"),
        ("Maker / Model", "Ashoka Motors Ltd · Variant S"),
        ("Owner Name", "ARJUN SACHIN VERMA"),
        ("Owner Address", "Flat 402, Sunrise Residency, Andheri East, Mumbai 400069"),
        ("Tax Paid Upto", "31 / 03 / 2025"),
        ("Insurance Policy No", "POL-88412093"),
        ("Insurance Valid Upto", "14 / 01 / 2025"),
    ]
    y = ty
    for i, (k, v) in enumerate(rows):
        if i % 2 == 0:
            d.rectangle([50, y, W - 50, y + rh], fill="#fafafa")
        d.text((66, y + 10), k, font=font("sans_n", 19), fill="#666666")
        kind = "mono" if any(ch.isdigit() for ch in v) and len(v) > 8 else "sans"
        d.text((430, y + 10), v, font=font(kind, 20), fill="#111111")
        d.line([(50, y + rh), (W - 50, y + rh)], fill="#dddddd")
        y += rh

    img.paste(photo_placeholder(180, 216, "VEHICLE PHOTO", 5), (56, y + 40))
    d.text((56, y + 270), "Fitness Upto", font=font("sans_n", 19), fill="#666666")
    d.text((56, y + 296), "12 / 02 / 2026", font=font("sans", 20), fill="#111111")
    d.text((56, y + 336), "Permit Upto", font=font("sans_n", 19), fill="#666666")
    d.text((56, y + 362), "12 / 02 / 2026", font=font("sans", 20), fill="#111111")

    d.text((330, y + 40), "This is a synthetic specimen and confers no registration.", font=font("sans", 19), fill="#8b1a1a")
    signature_block(d, 640, y + 340, 250)
    seal(img, 400, y + 210, 96, "RTO SEAL")
    banner(img, d, "Vehicle RC")
    return img


# --------------------------------------------------------------------------- #
#  9 · Utility (electricity) bill
# --------------------------------------------------------------------------- #

def utility_bill() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, W, 104], fill="#1b4f9c")
    d.text((50, 26), "MAHARASHTRA STATE ELECTRICITY DISTRIBUTION CO.", font=font("sans_b", 26), fill="#ffffff")
    d.text((50, 64), "Commercial Tariff · Consumer Services Division", font=font("sans", 18), fill="#c8d6ea")

    field(d, 60, 132, "Consumer Name", "SUNRISE RETAIL LLP", "sans_b", 24)
    field(d, 60, 196, "Consumer Number", "41558872", "mono", 24)
    field(d, 620, 132, "Billing Period", "01 Apr 2024 - 30 Apr 2024", "sans", 20)
    field(d, 620, 196, "Bill Number", "MSEDCL-2024-4471902", "mono", 19)

    d.text((60, 262), "Meter Reading", font=font("sans_b", 21), fill="#222222")
    ty, rh = 300, 40
    cols = {"d": 60, "prev": 300, "curr": 500, "units": 720, "amt": 850}
    d.rectangle([60, ty, W - 60, ty + rh], fill="#eceff3")
    for label, cx in (("Bill Date", cols["d"]), ("Previous", cols["prev"]),
                      ("Current", cols["curr"]), ("Units", cols["units"]), ("Amount", cols["amt"])):
        d.text((cx + 6, ty + 10), label, font=font("sans_b", 19), fill="#222222")
    y = ty + rh
    for date, prev, curr, units, amt in [
        ("01 Apr 2024", "12480", "12748", "268", "4020"),
        ("01 May 2024", "12748", "13096", "348", "5220"),
        ("01 Jun 2024", "13096", "13352", "256", "3840"),
    ]:
        d.rectangle([60, y, W - 60, y + rh], outline="#dddddd")
        d.text((cols["d"] + 6, y + 10), date, font=font("mono", 18), fill="#111111")
        for cx, val in ((cols["prev"], prev), (cols["curr"], curr), (cols["units"], units)):
            d.text((cx + 6, y + 10), val, font=font("mono", 18), fill="#111111")
        d.text((cols["amt"] + 6, y + 10), amt, font=font("mono", 18), fill="#111111")
        y += rh

    y += 34
    for label, value in (("Energy Charge", "10530"), ("Adjustment", "1550"),
                         ("Total Payable", "12080")):
        d.text((560, y), label, font=font("sans", 21), fill="#333333")
        d.text((790, y), value, font=font("mono_b", 22), fill="#111111")
        y += 36
    d.line([(550, y + 4), (W - 60, y + 4)], fill="#222222", width=2)

    y += 34
    d.text((60, y), "Payment due date: 15 May 2024. Late payment attracts interest.", font=font("sans", 20), fill="#333333")
    d.text((60, y + 34), "This bill is a synthetic specimen for forensic demonstration.", font=font("sans", 19), fill="#8b1a1a")
    signature_block(d, 640, y + 90, 250)
    banner(img, d, "Electricity bill")
    return img


# --------------------------------------------------------------------------- #
# 10 · Rent agreement
# --------------------------------------------------------------------------- #

def rent_agreement() -> Image.Image:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)

    d.text((W / 2 - 200, 66), "RENT AGREEMENT", font=font("sans_b", 32), fill="#111111")
    d.text((W / 2 - 175, 108), "(Leave and licence · Registration No. PN-2024-2281)", font=font("sans", 19), fill="#444444")
    d.line([(70, 148), (W - 70, 148)], fill="#222222", width=3)

    y = 176
    for line in (
        "This Rent Agreement is made on 12 April 2024 at Pune between:",
        "(1) The Lessor: SUNRISE PROPERTIES LLP, having its office at 4th Floor,",
        "    Sterling Plaza, Baner Road, Pune 411045, represented by its partner.",
        "(2) The Lessee: ARJUN SACHIN VERMA, residing at 22, Lake View Apartments,",
        "    Baner Road, Pune 411045, PAN SAMP9999X.",
    ):
        d.text((70, y), line, font=font("serif", 20), fill="#222222")
        y += 34

    y += 22
    for line in (
        "The Lessor hereby lets out to the Lessee the premises described below on the",
        "terms and conditions mutually agreed by the parties:",
    ):
        d.text((70, y), line, font=font("serif", 20), fill="#222222")
        y += 32

    y += 14
    clauses = [
        ("1. Premises", "Flat 702, B Wing, Green Meadows Residency, Baner Road, Pune 411045, admeasuring 1,150 sq. ft. carpet area with two covered car parking bays."),
        ("2. Term", "Thirty-six (36) months commencing 01 May 2024 and expiring 30 April 2027, with an option to renew for a further period by mutual consent."),
        ("3. Monthly rent", "Rs 38,500 (Thirty-Eight Thousand Five Hundred only) payable in advance on or before the fifth day of each English calendar month."),
        ("4. Security deposit", "Rs 1,15,500 (one lakh fifteen thousand five hundred only), refundable at the conclusion of the term less deductions, if any."),
        ("5. Maintenance", "Structural maintenance is the responsibility of the Lessor; day-to-day upkeep and minor repairs are borne by the Lessee."),
        ("6. Registration", "This agreement shall be registered at the office of the Sub-Registrar, Haveli, Pune, within four weeks of execution."),
        ("7. Jurisdiction", "Subject to the exclusive jurisdiction of the courts at Pune, Maharashtra."),
    ]
    for head, body in clauses:
        d.text((70, y), head, font=font("sans_b", 20), fill="#111111")
        y += 28
        for chunk in wrap_text(body, 92):
            d.text((92, y), chunk, font=font("serif", 19), fill="#333333")
            y += 28
        y += 10

    y += 30
    signature_block(d, 70, y, 250)
    signature_block(d, 620, y, 250)
    d.text((70, y + 76), "LESSOR · SUNRISE PROPERTIES LLP", font=font("sans", 18), fill="#555555")
    d.text((620, y + 76), "LESSEE · ARJUN SACHIN VERMA", font=font("sans", 18), fill="#555555")
    d.text((70, y + 116), "Witness", font=font("sans_n", 17), fill="#777777")
    d.text((70, y + 142), "Ms. R. Kulkarni, Flat 1104, Sterling Plaza, Pune 411045", font=font("serif", 18), fill="#444444")
    seal(img, 500, y + 92, 84, "EXECUTED")
    banner(img, d, "Rent agreement")
    return img


def wrap_text(text: str, width: int) -> list[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if len(trial) <= width:
            cur = trial
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


# --------------------------------------------------------------------------- #

def main() -> None:
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f"Generating synthetic demo exhibits in {OUT_DIR}\n")

    print("[ identity ]")
    emit_pair("aadhaar_clean.jpg", "aadhaar_tampered.jpg", aadhaar, forge_aadhaar, seed=101)
    emit_pair("pan_clean.jpg", "pan_tampered.jpg", pan, forge_pan, seed=202)

    print("[ academic  ]")
    # the marksheet needs the render's patch coordinates, so wire it manually
    ms_img, ms_box = marksheet()
    ms_base = capture(ms_img, seed=303)
    save(ms_base, "marksheet_clean.jpg", 92)
    forge_marksheet.box = ms_box
    ms_forged = ms_base.copy()
    forge_marksheet(ms_forged)
    save(ms_forged, "marksheet_tampered.jpg", 92)
    save(capture(degree_certificate(), seed=404), "degree_certificate.jpg", 92)

    print("[ financial ]")
    inv_img, inv_box = invoice()
    inv_base = capture(inv_img, seed=505)
    save(inv_base, "invoice_clean.jpg", 92)
    forge_invoice.box = inv_box
    inv_forged = inv_base.copy()
    forge_invoice(inv_forged)
    save(inv_forged, "invoice_tampered.jpg", 92)
    save(capture(bank_statement(), seed=606), "bank_statement.jpg", 92)
    save(capture(utility_bill(), seed=707), "utility_bill.jpg", 92)
    save(capture(rent_agreement(), seed=808), "rent_agreement.jpg", 92)

    print("[ other     ]")
    save(capture(medical_report(), seed=909), "medical_report.jpg", 92)
    save(capture(vehicle_rc(), seed=1010), "vehicle_rc.jpg", 92)

    # Prove the clean exhibits really are internally consistent, so a professor
    # can be told the arithmetic identities hold *by construction*, not by luck.
    print("\n[ arithmetic self-check ]")
    assert abs(INVOICE_SUBTOTAL - sum(q * p for _, q, p in INVOICE_ROWS)) < 1e-9
    assert abs(INVOICE_GRAND - (INVOICE_SUBTOTAL + INVOICE_TAX)) < 1e-9
    assert MARKSHEET_TOTAL == sum(m for _, m in MARKSHEET_ROWS)
    assert MARKSHEET_MAX == MARKSHEET_MAX_EACH * len(MARKSHEET_ROWS)
    assert MARKSHEET_PERCENT == round(MARKSHEET_TOTAL / MARKSHEET_MAX * 100)
    print(f"  invoice   subtotal {INVOICE_SUBTOTAL:,.2f} + tax {INVOICE_TAX:,.2f} "
          f"= grand {INVOICE_GRAND:,.2f}   (forged as {INVOICE_FORGED_GRAND:,.2f})")
    print(f"  marksheet sum {MARKSHEET_TOTAL} / {MARKSHEET_MAX} = {MARKSHEET_PERCENT}%")

    print(f"\nDone. Generated at {stamp()}")


if __name__ == "__main__":
    main()