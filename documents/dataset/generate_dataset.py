#!/usr/bin/env python3
"""
Forgify · labelled synthetic forgery dataset generator
======================================================
Builds a *labeled* dataset for training / evaluating the detection and
localisation layers. This is deliberately **separate** from
``documents/generate_samples.py`` (the demo exhibits), and that file is left
untouched.

For every one of the four document templates we render ``PER_TYPE`` seeded
originals and, from each original, three forgeries produced with real
PIL/OpenCV pixel operations:

    whiteout       a solid rectangle is pasted over a known text field
                   (optionally re-setting the field in a foreign typeface)
    copy_move      a rectangular region (signature / stamp box) is copied and
                   pasted at a *different* location in the same image
    text_replace   one numeric/text field is re-drawn with a different value,
                   matched to the surrounding typeface as closely as possible

Each forgery ships with a pixel-accurate ``mask.png`` — black everywhere
except the manipulated region, which is white. The mask is built from the very
coordinates handed to the paste/draw operation, never approximated, and the
generator asserts that every changed pixel of the forgery lies inside the mask.
That invariant is what makes the dataset usable for localisation evaluation.

Output layout (relative to this file's directory)::

    dataset/
      manifest.json
      original/{certificate,invoice,marksheet,id_card}/*.png   20 each = 80
      forged/{whiteout,copy_move,text_replace}/*.png           80 each = 240
      masks/{whiteout,copy_move,text_replace}/*.png            80 each = 240

Usage
-----
    python/.venv/bin/python documents/dataset/generate_dataset.py
    python/.venv/bin/python documents/dataset/validate_dataset.py

Everything is deterministic: content and tamper choices come from
``random.Random`` seeded with ``SEED_BASE:doc_type:index[:manipulation]``, so
re-running reproduces identical images. Strings seed the Mersenne Twister via
SHA-512, so the output does not depend on ``PYTHONHASHSEED``.

This script produces **images, masks and a manifest only**. It computes no
forensic scores, contains no ground-truth scores, and makes no accuracy claim —
scoring is a later phase.

All content is fictional: invented people, invented organisations, deliberately
non-allocatable identifier ranges, and a visible
``SYNTHETIC SAMPLE — NOT A REAL DOCUMENT`` banner on every page.
"""

from __future__ import annotations

import json
import io
import math
import random
import shutil
import sys
from dataclasses import dataclass, field as dc_field
from datetime import date, timedelta
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from PIL import ImageEnhance

# --------------------------------------------------------------------------- #
# paths + configuration
# --------------------------------------------------------------------------- #

ROOT = Path(__file__).resolve().parent
ORIGINAL_DIR = ROOT / "original"
FORGED_DIR = ROOT / "forged"
MASKS_DIR = ROOT / "masks"
MANIFEST_PATH = ROOT / "manifest.json"

DOC_TYPES = ("certificate", "invoice", "marksheet", "id_card")
MANIPULATIONS = ("whiteout", "copy_move", "text_replace")
PER_TYPE = 20

SEED_BASE = 20260101
MASK_TOLERANCE_PX = 2  # validator tolerance when comparing mask bbox to manifest
PILOT_ROOT = ROOT / "pilot"
PILOT_MANIFEST = PILOT_ROOT / "manifest.json"
PILOT_SEED = 20260501


# --------------------------------------------------------------------------- #
# fonts
# --------------------------------------------------------------------------- #
# The face map mirrors the ``F`` table declared in generate_samples.py (Arial /
# Times New Roman / Courier New). It is re-declared here rather than imported
# because generate_samples.font() tries a font file that is not installed and
# silently falls back to ImageFont.load_default(), which ignores the requested
# size entirely — every size rendered to the same 8px-tall bitmap. Real scalable
# faces are required here because mask rectangles are derived from exact
# text bounding boxes.

FONT_DIR = "/System/Library/Fonts/Supplemental"
FONT_MAP = {
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

_FONT_CACHE: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    key = (kind, size)
    if key not in _FONT_CACHE:
        path = FONT_MAP.get(kind, FONT_MAP["sans"])
        try:
            _FONT_CACHE[key] = ImageFont.truetype(path, size)
        except OSError:
            # Last resort so the run still completes; sizes stay honoured.
            _FONT_CACHE[key] = ImageFont.load_default(size=size)
    return _FONT_CACHE[key]


# --------------------------------------------------------------------------- #
# drawing primitives (same geometry as the demo exhibits)
# --------------------------------------------------------------------------- #

BANNER_TEXT = "SYNTHETIC SAMPLE — NOT A REAL DOCUMENT"


def new_page(w: int, h: int, bg: str = "#ffffff") -> Image.Image:
    return Image.new("RGB", (w, h), bg)


def banner(img: Image.Image, d: ImageDraw.ImageDraw, note: str = "") -> None:
    """Watermark top and bottom so a crop can never be mistaken for a record."""
    w, h = img.size
    d.rectangle([0, 0, w, 34], fill="#111111")
    d.text((14, 8), BANNER_TEXT, font=font("sans_b", 20), fill="#ff5a5a")
    d.rectangle([0, h - 46, w, h], fill="#f2f2f2")
    d.line([(0, h - 46), (w, h - 46)], fill="#cccccc", width=2)
    txt = f"labelled dataset sample · id {note}" if note else "labelled dataset sample"
    d.text((14, h - 36), txt, font=font("sans", 17), fill="#555555")


def watermark(img: Image.Image, text: str, angle: int = 32, alpha: int = 26) -> None:
    """Diagonal low-opacity overprint; also creates real copy-move structure."""
    w, h = img.size
    layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    ld = ImageDraw.Draw(layer)
    f = font("black", max(40, w // 16))
    l, t, r, b = ld.textbbox((0, 0), text, font=f)
    ld.text(((w - (r - l)) / 2, (h - (b - t)) / 2), text, font=f, fill=(90, 90, 120, alpha))
    layer = layer.rotate(angle, resample=Image.BICUBIC)
    img.paste(Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB"), (0, 0))


def signature_block(d: ImageDraw.ImageDraw, x: int, y: int, w: int = 210,
                    style: str = "clean") -> tuple[int, int, int, int]:
    """Handwriting-ish scrawl. Returns the rect it occupies (used by copy_move)."""
    d.line([(x, y + 26), (x + w, y + 26)], fill="#222222", width=2)
    d.text((x, y + 30), "Authorised signatory", font=font("sans", 12), fill="#666666")
    pts = [
        (0.02, 0.72), (0.16, 0.30), (0.26, 0.78), (0.38, 0.18), (0.48, 0.66),
        (0.58, 0.26), (0.68, 0.80), (0.80, 0.34), (0.90, 0.70), (0.99, 0.44),
    ]
    prev = None
    for fx, fy in pts:
        p = (x + fx * w, y + fy * 24)
        if style == "clean":
            if prev:
                d.line([prev, p], fill=(24, 32, 90), width=3, joint="curve")
            prev = p
        else:
            d.ellipse([p[0] - 4, p[1] - 4, p[0] + 4, p[1] + 4], fill=(70, 70, 70))
    return (x, y, x + w, y + 48)


def seal(img: Image.Image, cx: int, cy: int, r: int, text: str,
         colour=(196, 42, 42), alpha: int = 120) -> tuple[int, int, int, int]:
    """Semi-transparent rubber stamp. Returns its bounding square."""
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    sd = ImageDraw.Draw(layer)
    c = (*colour, alpha)
    sd.ellipse([cx - r, cy - r, cx + r, cy + r], outline=c, width=6)
    # NB: the inner ring's y1 must be cy + r - 14. Using cx there raises
    # "y1 must be greater than y0" for any stamp whose centre sits well below
    # its horizontal position.
    sd.ellipse([cx - r + 14, cy - r + 14, cx + r - 14, cy + r - 14], outline=c, width=2)
    f = font("sans_b", max(15, r // 5))
    l, t, rr, bb = sd.textbbox((0, 0), text, font=f)
    sd.text((cx - (rr - l) / 2, cy - (bb - t) / 2), text, font=f, fill=c)
    # Hatching confined to the circle, so it reads as part of the stamp.
    for k in range(5):
        y = cy + r * 0.30 + k * (r * 0.11)
        frac = (y - cy) / float(r)
        half = max(3.0, (r * 0.5) * math.sqrt(max(0.0, 1.0 - frac * frac)))
        sd.line([(cx - half, y), (cx + half, y)],
                fill=(*colour, alpha // 2), width=3)
    layer = layer.rotate(-14, resample=Image.BICUBIC, center=(cx, cy))
    img.paste(Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB"), (0, 0))
    return (cx - r, cy - r, cx + r, cy + r)


def photo_box(d: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int,
              initials: str) -> tuple[int, int, int, int]:
    d.rectangle([x, y, x + w, y + h], outline="#9aa5b1", width=3)
    d.rectangle([x + 4, y + 4, x + w - 4, y + h - 4], fill="#dfe6ee")
    f = font("sans_b", int(w * 0.34))
    l, t, rr, bb = d.textbbox((0, 0), initials, font=f)
    d.text((x + (w - (rr - l)) / 2, y + (h - (bb - t)) / 2), initials, font=f, fill="#8a94a6")
    return (x, y, x + w, y + h)


def qr_block(size: int, seed: int) -> Image.Image:
    """QR-*looking* module pattern. Explicitly NOT a decodable symbol."""
    rng = np.random.default_rng(seed)
    n = 25
    m = (rng.random((n, n)) > 0.52).astype(np.uint8)

    def finder(r0: int, c0: int) -> None:
        m[r0:r0 + 7, c0:c0 + 7] = 0
        m[r0:r0 + 7, c0:c0 + 7] = 1
        m[r0 + 1:r0 + 6, c0 + 1:c0 + 6] = 0
        m[r0 + 2:r0 + 5, c0 + 2:c0 + 5] = 1

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    m[6, 8:n - 8] = 1
    m[8:n - 8, 6] = 1
    px = size // (n + 8)
    arr = np.kron(m, np.ones((3, 3), dtype=np.uint8)) * 255
    cell = Image.fromarray(arr.astype(np.uint8), mode="L").resize((size, size), Image.NEAREST)
    canvas = Image.new("L", (px * (n + 8), px * (n + 8)), 255)
    canvas.paste(cell, (px * 4, px * 4))
    return canvas


# --------------------------------------------------------------------------- #
# field bookkeeping
# --------------------------------------------------------------------------- #
# Boxes are half-open: [x0, y0, x1, y1). Every manipulation pastes its payload at
# exactly (x0, y0) with exactly (x1-x0, y1-y0) pixels, and the mask is filled
# over the identical rectangle, so the manifest's region_box is exact by
# construction rather than estimated.


@dataclass
class Field:
    """A known text region of the rendered document."""
    name: str
    box: tuple[int, int, int, int]
    kind: str
    size: int
    value: str
    numeric: bool = False
    alts: tuple[str, ...] = ()
    anchor: str = "left"  # how a replacement re-enters the box


@dataclass
class Template:
    doc_type: str
    image: Image.Image
    fields: list[Field]
    cm_src: tuple[int, int, int, int]
    cm_dst: tuple[int, int, int, int]
    serial: str
    meta: dict = dc_field(default_factory=dict)


def pad_box(l: int, t: int, r: int, b: int, pad: int = 3) -> tuple[int, int, int, int]:
    return (max(0, int(l) - pad), max(0, int(t) - pad), int(r) + pad, int(b) + pad)


def draw_value(d: ImageDraw.ImageDraw, xy: tuple[int, int], text: str, kind: str,
               size: int, fill: str = "#111111") -> tuple[int, int, int, int]:
    """Draw a value and return its half-open text box (padded for AA).

    The glyph offsets are measured at the origin and the integer-rounded anchor
    is added back afterwards. Measuring against a fractional anchor instead
    makes Pillow return float corners, and every downstream paste/mask rectangle
    inherits them.
    """
    f = font(kind, size)
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    ox, oy = int(round(xy[0])), int(round(xy[1]))
    d.text((ox, oy), text, font=f, fill=fill)
    return pad_box(l + ox, t + oy, r + ox, b + oy)


def draw_centered(d: ImageDraw.ImageDraw, cx: int, y: int, text: str, kind: str,
                  size: int, fill: str = "#111111") -> tuple[int, int, int, int]:
    f = font(kind, size)
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    return draw_value(d, (cx - (r - l) / 2, y), text, kind, size, fill)


# --------------------------------------------------------------------------- #
# fictional content pools
# --------------------------------------------------------------------------- #

FIRST_NAMES = [
    "Aarav", "Diya", "Vihaan", "Ananya", "Kabir", "Ishita", "Rohan", "Meera",
    "Aditya", "Saanvi", "Nikhil", "Priya", "Karan", "Tara", "Yash", "Ritika",
    "Manav", "Neha", "Arjun", "Divya", "Farhan", "Kavya", "Imran", "Sneha",
    "Vedant", "Pooja", "Rehan", "Aisha", "Naveen", "Shreya",
]
LAST_NAMES = [
    "Deshmukh", "Kulkarni", "Chatterjee", "Bhandari", "Nair", "Rao", "Menon",
    "Kapoor", "Joshi", "Pillai", "Banerjee", "Shetty", "Ghosh", "Trivedi",
    "Malhotra", "Venkatesh", "Sundaram", "Bhattacharya", "Agarwal", "Kamath",
]
CITIES = ["Pune", "Nagpur", "Indore", "Kochi", "Jaipur", "Bhopal", "Guwahati",
          "Coimbatore", "Vadodara", "Mysuru"]
ISSUERS = [
    "SYNTHETIC MODEL UNIVERSITY", "NORTHFIELD ACADEMY", "ST. ARDEN COLLEGE",
    "RIVERBANK INSTITUTE", "HALCYON POLYTECHNIC",
]
COMPANIES = [
    "NORTHWIND SUPPLY CHAND", "SUNRISE RETAIL LLP", "MERIDIAN LOGISTICS PVT LTD",
    "BLUE HARBOR TRADING", "KESTREL ENGINEERING WORKS", "ORCHARD FOODS LTD",
]
COURSES = [
    "B.E. Computer Science", "B.Sc. Statistics", "B.Com. Honours",
    "B.A. Economics", "B.Sc. Physics", "BBA", "B.Tech Information Technology",
]
SUBJECTS = [
    "English Language", "Data Structures", "Database Systems",
    "Operating Systems", "Computer Networks", "Software Engineering Project",
    "Discrete Mathematics", "Digital Electronics", "Business Statistics",
]
ITEM_DESCS = [
    "Assembly service", "Calibration and testing", "Annual maintenance plan",
    "On-site support hours", "Spare parts kit", "Site survey visit",
    "Installation labour", "Annual licence renewal",
]
BANKS = ["MERIDIAN CO-OPERATIVE BANK", "NORTHFIELD GRAMIN BANK", "CITRUS UNION BANK"]
GENDERS = ["MALE", "FEMALE", "OTHER"]
STATES = ["Maharashtra", "Kerala", "Karnataka", "Rajasthan", "Madhya Pradesh"]
DISTRICTS = ["Pune", "Ernakulam", "Bengaluru", "Jaipur", "Indore"]
STAMPS = ["AUTHENTICATED", "VERIFIED", "ISSUED", "CERTIFIED"]


def rng_date(rng: random.Random) -> date:
    base = date(2023, 6, 1)
    return base + timedelta(days=rng.randint(0, 700))


def fmt_date(d: date) -> str:
    return f"{d.day:02d} / {d.month:02d} / {d.year}"


def make_name(rng: random.Random) -> str:
    return f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"


def make_digits(rng: random.Random, n: int, lead: str = "") -> str:
    body = "".join(rng.choice("0123456789") for _ in range(len(lead), n))
    return (lead + body)[-n:]


# --------------------------------------------------------------------------- #
# template: certificate
# --------------------------------------------------------------------------- #

def build_certificate(rng: random.Random, serial: str) -> Template:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)
    flds: list[Field] = []

    issuer = rng.choice(ISSUERS)
    name = make_name(rng)
    course = rng.choice(COURSES)
    roll = make_digits(rng, 10, lead="2")
    issue = rng_date(rng)
    cgpa = rng.randint(61, 98) / 10.0
    duration = rng.choice(["3 Years", "4 Years", "2 Years"])

    d.rectangle([0, 0, W, 120], fill="#12315c")
    d.text((50, 24), issuer, font=font("sans_b", 28), fill="#ffffff")
    d.text((50, 68), "Office of the Controller of Examinations", font=font("sans", 18), fill="#c8d6ea")
    d.text((W - 240, 34), f"Ref: {serial}", font=font("mono", 18), fill="#ffffff")

    d.text((50, 168), "CERTIFICATE OF MERIT", font=font("serif_b", 38), fill="#12315c")
    d.line([(50, 220), (W - 50, 220)], fill="#12315c", width=3)
    d.text((50, 244), "This is to certify that", font=font("sans", 20), fill="#555555")

    name_box = draw_centered(d, W // 2, 282, name, "serif_b", 40)
    flds.append(Field("holder_name", name_box, "serif_b", 40, name,
                      alts=(make_name(rng), make_name(rng))))
    d.text((50, 344), "has satisfactorily completed the programme of", font=font("sans", 20), fill="#555555")
    draw_centered(d, W // 2, 376, course, "sans_b", 26, fill="#222222")

    y = 452
    durations = ["2 Years", "3 Years", "4 Years", "5 Years"]
    pairs = [
        ("Roll Number", roll, "mono_b", 24, True,
         tuple(make_digits(rng, 10, lead="2") for _ in range(5))),
        ("Date of Issue", fmt_date(issue), "sans", 22, False,
         tuple(fmt_date(rng_date(rng)) for _ in range(5))),
        ("Duration", duration, "sans", 22, False,
         tuple(x for x in durations if x != duration) or tuple(durations)),
        ("CGPA (10 scale)", f"{cgpa:.1f}", "mono_b", 24, True,
         tuple(f"{rng.randint(60, 98) / 10:.1f}" for _ in range(5))),
    ]
    for i, (label, value, kind, size, numeric, alts) in enumerate(pairs):
        x = 70 if i % 2 == 0 else 540
        yy = y + (i // 2) * 74
        d.text((x, yy), label, font=font("sans_n", 18), fill="#666666")
        box = draw_value(d, (x, yy + 26), value, kind, size)
        flds.append(Field(label.lower().replace(" ", "_"), box, kind, size, value,
                          numeric=numeric, alts=alts))

    y = 630
    d.text((70, y), "Awarded with distinction for academic performance across the full programme.",
           font=font("sans", 19), fill="#333333")
    d.text((70, y + 34), f"Issued at {rng.choice(CITIES)}, on {fmt_date(issue)}.",
           font=font("sans", 19), fill="#333333")

    sig_a = signature_block(d, 90, 740, 250)
    sig_b = signature_block(d, 600, 740, 250)
    seal_rect = seal(img, 845, 780, 78, rng.choice(STAMPS))
    d.text((70, 812), "Principal", font=font("sans_b", 18), fill="#222222")
    d.text((600, 812), "Controller of Examinations", font=font("sans_b", 18), fill="#222222")
    qr = qr_block(150, rng.randint(0, 10_000))
    img.paste(qr, (70, 900))
    d.text((240, 960), "Verify reference number against the issuing office.",
           font=font("sans", 18), fill="#666666")

    watermark(img, issuer.split()[0].upper(), alpha=22)
    banner(img, d, serial)

    return Template("certificate", img, flds, sig_a, sig_b, serial,
                    meta={"issuer": issuer, "course": course})


# --------------------------------------------------------------------------- #
# template: invoice
# --------------------------------------------------------------------------- #

def build_invoice(rng: random.Random, serial: str) -> Template:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)
    flds: list[Field] = []

    vendor = rng.choice(COMPANIES)
    buyer = rng.choice([c for c in COMPANIES if c != vendor])
    number = f"{make_digits(rng, 5, lead='2')}-{rng.randint(10, 99)}{rng.randint(100, 999)}"
    inv_date = rng_date(rng)
    due = inv_date + timedelta(days=rng.randint(7, 45))
    city = rng.choice(CITIES)

    d.rectangle([0, 0, W, 120], fill="#12315c")
    d.text((50, 26), vendor, font=font("sans_b", 30), fill="#ffffff")
    d.text((50, 68), f"Unit {rng.randint(1, 20)}, Industrial Estate, {city}", font=font("sans", 18), fill="#c8d6ea")
    d.text((W - 250, 34), "TAX INVOICE", font=font("sans_b", 26), fill="#ffffff")

    no_box = draw_value(d, (50, 146), f"Invoice No: {number}", "mono_b", 22)
    flds.append(Field("invoice_no", no_box, "mono_b", 22, number,
                      alts=tuple(make_digits(rng, 5, lead="2") + f"-{rng.randint(10, 99)}{rng.randint(100, 999)}"
                                 for _ in range(5))))
    date_box = draw_value(d, (620, 146), f"Date: {fmt_date(inv_date)}", "sans", 22)
    flds.append(Field("invoice_date", date_box, "sans", 22, fmt_date(inv_date),
                      alts=tuple(fmt_date(rng_date(rng)) for _ in range(5))))
    draw_value(d, (50, 178), f"Bill To: {buyer}", "sans", 21, fill="#222222")
    due_box = draw_value(d, (620, 178), f"Due: {fmt_date(due)}", "sans", 22)
    flds.append(Field("due_date", due_box, "sans", 22, fmt_date(due),
                      alts=tuple(fmt_date(rng_date(rng)) for _ in range(5))))

    descs = rng.sample(ITEM_DESCS, 4)
    rows = []
    for desc in descs:
        qty = rng.randint(1, 9)
        rate = rng.choice([120, 250, 350, 480, 500, 750, 900, 1250, 1450, 2000, 2500, 3000])
        rows.append((desc, qty, rate, qty * rate))
    subtotal = sum(a for *_, a in rows)
    tax_rate = rng.choice([5, 12, 18])
    tax = round(subtotal * tax_rate / 100.0)
    grand = subtotal + tax

    ty, rh = 250, 48
    cols = {"desc": 60, "qty": 520, "rate": 660, "amt": 830}
    d.rectangle([50, ty, W - 50, ty + rh], fill="#eceff3")
    for label, cx in (("Description", cols["desc"]), ("Qty", cols["qty"]),
                      ("Rate", cols["rate"]), ("Amount", cols["amt"])):
        d.text((cx + 6, ty + 12), label, font=font("sans_b", 20), fill="#222222")
    y = ty + rh
    for desc, qty, rate, amt in rows:
        d.rectangle([50, y, W - 50, y + rh], outline="#dddddd")
        d.text((cols["desc"] + 6, y + 13), desc, font=font("sans", 20), fill="#111111")
        d.text((cols["qty"] + 6, y + 13), str(qty), font=font("mono", 24), fill="#111111")
        d.text((cols["rate"] + 6, y + 13), str(rate), font=font("mono", 24), fill="#111111")
        d.text((cols["amt"] + 6, y + 13), str(amt), font=font("mono", 24), fill="#111111")
        y += rh

    y += 30

    def total_line(label: str, value: int, bold: bool = False):
        nonlocal y
        d.text((560, y), label, font=font("sans_b" if bold else "sans", 21), fill="#333333")
        box = draw_value(d, (760, y), str(value), "mono_b" if bold else "mono", 22)
        y += 38
        return box

    sub_box = total_line("Subtotal", subtotal)
    total_line(f"Tax ({tax_rate}%)", tax)
    grand_box = total_line("Grand Total", grand, bold=True)
    flds.append(Field("subtotal", sub_box, "mono", 22, str(subtotal), numeric=True,
                      alts=tuple(str(subtotal + k) for k in (500, 750, 1000, -400, -600))))
    flds.append(Field("grand_total", grand_box, "mono_b", 22, str(grand), numeric=True,
                      alts=tuple(str(grand + k) for k in (500, 750, 1000, -300, -1500))))

    d.line([(550, y + 6), (W - 50, y + 6)], fill="#222222", width=2)
    y += 30
    d.text((560, y), "Amount in words", font=font("sans_n", 18), fill="#666666")
    d.text((560, y + 26), f"Rupees {grand} (Indian Rupees) only", font=font("sans", 18), fill="#111111")

    sig = signature_block(d, 600, y + 76, 250)
    d.text((50, y + 106), "Authorised Signatory", font=font("sans", 18), fill="#666666")
    qr = qr_block(130, rng.randint(0, 10_000))
    img.paste(qr, (70, y + 40))
    seal_rect = seal(img, 300, 940, 74, rng.choice(STAMPS))
    # A second stamping position, the same size as the stamp: a duplicated seal
    # is the classic invoice forgery.
    sw = seal_rect[2] - seal_rect[0]
    sh = seal_rect[3] - seal_rect[1]
    cm_dst = (seal_rect[2] + 250, seal_rect[1] + 40,
              seal_rect[2] + 250 + sw, seal_rect[1] + 40 + sh)

    watermark(img, "TAX INVOICE", alpha=20)
    banner(img, d, serial)

    return Template("invoice", img, flds, seal_rect, cm_dst, serial,
                    meta={"vendor": vendor, "buyer": buyer, "subtotal": subtotal, "grand_total": grand})


# --------------------------------------------------------------------------- #
# template: marksheet
# --------------------------------------------------------------------------- #

def build_marksheet(rng: random.Random, serial: str) -> Template:
    W, H = 1000, 1300
    img = new_page(W, H)
    d = ImageDraw.Draw(img)
    flds: list[Field] = []

    school = rng.choice(ISSUERS)
    name = make_name(rng)
    roll = make_digits(rng, 10, lead="2")
    sem = rng.randint(1, 8)
    issue = rng_date(rng)

    d.rectangle([0, 0, W, 110], fill="#1d3557")
    d.text((50, 24), school, font=font("sans_b", 28), fill="#ffffff")
    d.text((50, 64), f"Statement of Marks: Academic Year {2023 + rng.randint(0, 1)}-{(24 + rng.randint(0, 1)) % 100:02d}",
           font=font("sans", 18), fill="#c8d6ea")

    d.text((60, 128), "Student Name", font=font("sans_n", 18), fill="#666666")
    name_box = draw_value(d, (260, 124), name, "sans_b", 22)
    flds.append(Field("student_name", name_box, "sans_b", 22, name,
                      alts=(make_name(rng), make_name(rng))))
    d.text((60, 164), "Roll Number", font=font("sans_n", 18), fill="#666666")
    roll_box = draw_value(d, (260, 160), roll, "mono", 22)
    flds.append(Field("roll_no", roll_box, "mono", 22, roll, numeric=True,
                      alts=tuple(make_digits(rng, 10, lead="2") for _ in range(5))))
    d.text((620, 128), "Class / Section", font=font("sans_n", 18), fill="#666666")
    draw_value(d, (620, 124), f"BTech Computer Science · Sem {sem}", "sans", 20)
    d.text((620, 164), "Date of Issue", font=font("sans_n", 18), fill="#666666")
    issue_box = draw_value(d, (620, 160), fmt_date(issue), "sans", 20)
    flds.append(Field("issue_date", issue_box, "sans", 20, fmt_date(issue),
                      alts=tuple(fmt_date(rng_date(rng)) for _ in range(5))))

    n_sub = rng.randint(5, 6)
    subjects = rng.sample(SUBJECTS, n_sub)
    marks = [rng.randint(45, 100) for _ in subjects]
    total = sum(marks)
    maximum = 100 * n_sub
    percent = round(total / maximum * 100)

    ty, rh = 330, 46
    cols = {"sub": 80, "marks": 620, "max": 700, "grade": 810}
    d.rectangle([80, ty, W - 80, ty + rh], fill="#eceff3")
    for label, cx in (("Subject", cols["sub"]), ("Marks", cols["marks"]),
                      ("Maximum", cols["max"]), ("Grade", cols["grade"])):
        d.text((cx + 8, ty + 12), label, font=font("sans_b", 20), fill="#222222")
    y = ty + rh
    for subject, m in zip(subjects, marks):
        d.rectangle([80, y, W - 80, y + rh], outline="#cccccc")
        d.text((cols["sub"] + 8, y + 12), subject, font=font("sans", 21), fill="#111111")
        d.text((cols["marks"] + 8, y + 12), str(m), font=font("mono", 21), fill="#111111")
        d.text((cols["max"] + 8, y + 12), str(100), font=font("mono", 21), fill="#111111")
        d.text((cols["grade"] + 8, y + 12), "A" if m >= 75 else "B", font=font("sans", 21), fill="#111111")
        y += rh

    d.rectangle([80, y, W - 80, y + rh], fill="#e8eef6")
    d.text((cols["sub"] + 8, y + 12), "Total", font=font("sans_b", 21), fill="#111111")
    total_box = draw_value(d, (cols["marks"] + 8, y + 12), str(total), "mono_b", 21)
    d.text((cols["max"] + 8, y + 12), str(maximum), font=font("mono_b", 21), fill="#111111")
    d.text((cols["grade"] + 8, y + 12), "Pass" if percent >= 40 else "Fail", font=font("sans", 21), fill="#111111")
    y += rh + 34
    d.text((cols["sub"], y), "Percentage", font=font("sans_b", 22), fill="#111111")
    pct_box = draw_value(d, (cols["marks"], y), str(percent), "mono_b", 24)
    d.text((cols["grade"], y), "rounded", font=font("sans_n", 16), fill="#777777")

    flds.append(Field("total", total_box, "mono_b", 21, str(total), numeric=True,
                      alts=tuple(str(total + k) for k in (30, -25, 44, -40, 60))))
    flds.append(Field("percentage", pct_box, "mono_b", 24, str(percent), numeric=True,
                      alts=tuple(str(min(100, max(0, percent + k))) for k in (9, -7, 14, -11))))

    d.text((80, y + 46), f"Result: {'PASS' if percent >= 40 else 'FAIL'}",
           font=font("sans_b", 25), fill="#14532d" if percent >= 40 else "#8b1a1a")
    sig_a = signature_block(d, 80, y + 120, 230)
    sig_b = signature_block(d, 620, y + 120, 230)
    d.text((80, y + 192), "Internal Examiner", font=font("sans", 18), fill="#666666")
    d.text((620, y + 192), "Principal", font=font("sans", 18), fill="#666666")
    seal(img, 850, y + 150, 70, rng.choice(STAMPS))

    watermark(img, "MARK SHEET", alpha=20)
    banner(img, d, serial)

    return Template("marksheet", img, flds, sig_a, sig_b, serial,
                    meta={"school": school, "total": total, "maximum": maximum, "percent": percent})


# --------------------------------------------------------------------------- #
# template: id_card
# --------------------------------------------------------------------------- #

def build_id_card(rng: random.Random, serial: str) -> Template:
    W, H = 1000, 680
    img = new_page(W, H)
    d = ImageDraw.Draw(img)
    flds: list[Field] = []

    name = make_name(rng)
    dob = rng_date(rng).replace(year=rng.randint(1965, 2004))
    gender = rng.choice(GENDERS)
    aadhaar = "9999 9999 " + make_digits(rng, 4)
    state = rng.choice(STATES)
    district = rng.choice(DISTRICTS)
    pin = make_digits(rng, 6, lead="4")
    addr_line = f"{rng.randint(1, 240)}, {rng.choice(['MG Road', 'Station Road', 'Park Street', 'Nehru Nagar'])}"
    city_line = f"{district}, {state} - {pin}"

    d.rectangle([0, 0, W, 96], fill="#f7f9fb")
    d.rectangle([0, 0, 8, H], fill="#12708c")
    d.text((40, 22), "SPECIMEN IDENTITY DOCUMENT", font=font("sans_b", 26), fill="#12708c")
    d.text((40, 58), "Non-official specimen · not usable as identification",
           font=font("sans", 16), fill="#5b6b7b")

    photo_rect = photo_box(d, 40, 130, 210, 260,
                           f"{name.split()[0][0]}{name.split()[-1][0]}")

    x = 290
    d.text((x, 126), "Name", font=font("sans_n", 17), fill="#5b6b7b")
    name_box = draw_value(d, (x, 148), name, "sans_b", 26)
    flds.append(Field("holder_name", name_box, "sans_b", 26, name,
                      alts=(make_name(rng), make_name(rng))))
    d.text((x, 196), "Date of Birth", font=font("sans_n", 17), fill="#5b6b7b")
    dob_box = draw_value(d, (x, 218), fmt_date(dob), "mono", 24)
    flds.append(Field("dob", dob_box, "mono", 24, fmt_date(dob),
                      alts=tuple(fmt_date(dob.replace(year=dob.year + k)) for k in (1, -3, 5, -7))))

    gx = 620
    d.text((gx, 126), "Gender", font=font("sans_n", 17), fill="#5b6b7b")
    draw_value(d, (gx, 148), gender, "sans_b", 24)
    d.text((gx, 196), "Document No.", font=font("sans_n", 17), fill="#5b6b7b")
    docno_box = draw_value(d, (gx, 218), aadhaar, "mono_b", 24)
    flds.append(Field("document_no", docno_box, "mono_b", 24, aadhaar,
                      alts=tuple("9999 9999 " + make_digits(rng, 4) for _ in range(5))))

    d.text((x, 268), "Address", font=font("sans_n", 17), fill="#5b6b7b")
    addr_box = draw_value(d, (x, 290), addr_line, "sans", 22)
    city_box = draw_value(d, (x, 320), city_line, "sans", 22)
    flds.append(Field("address", addr_box, "sans", 22, addr_line,
                      alts=(f"{rng.randint(1, 240)}, {rng.choice(['MG Road', 'Station Road'])}",)))
    flds.append(Field("address_city", city_box, "sans", 22, city_line,
                      alts=tuple(f"{rng.choice(DISTRICTS)}, {rng.choice(STATES)} - {make_digits(rng, 6, lead='4')}"
                                 for _ in range(4))))

    d.line([(290, 400), (W - 40, 400)], fill="#d3dae2", width=2)
    d.text((x, 414), "Issuing authority", font=font("sans_n", 17), fill="#5b6b7b")
    draw_value(d, (x, 436), f"Regional Registration Unit, {district}", "sans", 21)
    d.text((x, 468), f"Valid until {fmt_date(dob.replace(year=dob.year + 10))}", font=font("sans", 19), fill="#333333")

    sig = signature_block(d, 560, 500, 220)
    seal_rect = seal(img, 870, 540, 66, rng.choice(STAMPS))
    # Equal-size second stamping position (the card has only one signature box,
    # and a duplicated seal is the realistic copy-move forgery here).
    sw = seal_rect[2] - seal_rect[0]
    sh = seal_rect[3] - seal_rect[1]
    cm_dst = (seal_rect[0] - sw - 30, seal_rect[1] + 20,
              seal_rect[0] - 30, seal_rect[1] + 20 + sh)
    qr = qr_block(96, rng.randint(0, 10_000))
    img.paste(qr, (330, 500))

    banner(img, d, serial)

    return Template("id_card", img, flds, seal_rect, cm_dst, serial,
                    meta={"state": state, "district": district})


BUILDERS = {
    "certificate": build_certificate,
    "invoice": build_invoice,
    "marksheet": build_marksheet,
    "id_card": build_id_card,
}


# --------------------------------------------------------------------------- #
# manipulations — every one returns the exact rectangle it wrote
# --------------------------------------------------------------------------- #

def _sample_field(rng: random.Random, tpl: Template, numeric_only: bool) -> Field:
    pool = [f for f in tpl.fields if f.numeric == numeric_only] or list(tpl.fields)
    return rng.choice(pool)


def _replacement(fld: Field, rng: random.Random) -> str:
    """A different value of the same shape; never equal to the original."""
    if fld.numeric:
        alts = [a for a in fld.alts if a != fld.value]
        if alts:
            return rng.choice(alts)
        if fld.value.replace(".", "").isdigit():
            digits = list(fld.value)
            pos = rng.randrange(len(digits))
            for candidate in rng.sample("0123456789", len(digits)):
                if candidate != digits[pos]:
                    digits[pos] = candidate
                    break
            alt = "".join(digits)
            return alt if alt != fld.value else fld.value + "1"
        alts = [a for a in fld.alts if a != fld.value]
        return rng.choice(alts) if alts else fld.value + "9"
    alts = [a for a in fld.alts if a != fld.value]
    return rng.choice(alts) if alts else fld.value + "X"


def apply_whiteout(img: Image.Image, tpl: Template,
                   rng: random.Random) -> tuple[int, int, int, int]:
    """Paste a solid rectangle over a known field, sometimes re-setting it in a
    different typeface. The pasted payload is exactly the declared rect."""
    fld = _sample_field(rng, tpl, numeric_only=False)
    x0, y0, x1, y1 = fld.box
    w, h = x1 - x0, y1 - y0
    fill = rng.choice(["#ffffff", "#f7f7f7", "#fbfbfb"])
    patch = Image.new("RGB", (w, h), fill)

    # A blank field is not always what a forger leaves behind; about half the
    # time they type a substitute in a foreign face, which is a separate
    # (layout-visible) tell.
    if rng.random() < 0.5:
        pd = ImageDraw.Draw(patch)
        text = _replacement(fld, rng)
        foreign = rng.choice(["serif_b", "black", "sans_n"])
        pf = font(foreign, max(14, fld.size))
        l, t, r, b = pd.textbbox((0, 0), text, font=pf)
        pd.text(((w - (r - l)) / 2 - l, (h - (b - t)) / 2 - t),
                text, font=pf, fill="#1a1a1a")

    img.paste(patch, (x0, y0))
    return fld.box


def apply_copy_move(img: Image.Image, tpl: Template,
                    rng: random.Random) -> tuple[int, int, int, int]:
    """Copy a rectangular region and paste it at a different valid location.

    Only the destination is masked: that is the region the forgery *creates*.
    Masking the source too would make the mask's bounding box span the whole gap
    between the two copies and stop being a usable localisation label.
    """
    sx0, sy0, sx1, sy1 = tpl.cm_src
    dx0, dy0, dx1, dy1 = tpl.cm_dst
    if (sx1 - sx0, sy1 - sy0) != (dx1 - dx0, dy1 - dy0):
        raise ValueError(f"copy_move rect size mismatch for {tpl.doc_type}")
    region = img.crop(tpl.cm_src)
    img.paste(region, (dx0, dy0))
    return (dx0, dy0, dx1, dy1)


def apply_text_replace(img: Image.Image, tpl: Template,
                       rng: random.Random) -> tuple[int, int, int, int]:
    """Re-draw one field with a different value in the matching typeface.

    The patch is built as a standalone sub-image and pasted once, so the set of
    modified pixels is exactly ``box``.
    """
    fld = _sample_field(rng, tpl, numeric_only=rng.random() < 0.75)
    x0, y0, x1, y1 = fld.box
    w, h = x1 - x0, y1 - y0

    # Sample the local background so the patch blends into the page.
    region = np.asarray(img.crop(fld.box)).reshape(-1, 3)
    bg = tuple(int(v) for v in np.median(region, axis=0)) if region.size else (255, 255, 255)

    patch = Image.new("RGB", (w, h), bg)
    pd = ImageDraw.Draw(patch)
    text = _replacement(fld, rng)
    f = font(fld.kind, fld.size)
    l, t, r, b = pd.textbbox((0, 0), text, font=f)
    tw, th = r - l, b - t
    # Re-seat the new glyphs on the original baseline: the box came from the
    # original string's textbbox, so centring restores the original position.
    # A fixed +1px offset is what made earlier fixture patches unreadable.
    tx = 6 if fld.anchor == "left" else max(0, (w - tw) // 2)
    ty = max(0, (h - th) // 2) - t
    # 1px hand-placed jitter; hand-typed text never lands on the original grid.
    # It is part of this single paste, not a second one.
    pd.text((tx + 1, ty + 1), text, font=f, fill="#111111")
    img.paste(patch, (x0, y0))
    return fld.box


APPLY = {
    "whiteout": apply_whiteout,
    "copy_move": apply_copy_move,
    "text_replace": apply_text_replace,
}


# --------------------------------------------------------------------------- #
# masks + verification
# --------------------------------------------------------------------------- #

def make_mask(size: tuple[int, int], box: tuple[int, int, int, int]) -> Image.Image:
    """Black everywhere, white over exactly ``box`` (half-open)."""
    mask = Image.new("RGB", size, (0, 0, 0))
    d = ImageDraw.Draw(mask)
    x0, y0, x1, y1 = box
    d.rectangle([x0, y0, x1 - 1, y1 - 1], fill=(255, 255, 255))
    return mask


def mask_bbox(mask: Image.Image) -> tuple[int, int, int, int] | None:
    arr = np.asarray(mask)
    ys, xs = np.nonzero(arr[:, :, 0] > 127)
    if len(xs) == 0:
        return None
    return (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def changed_bbox(original: Image.Image, forged: Image.Image) -> tuple[int, int, int, int] | None:
    diff = np.abs(np.asarray(original, dtype=np.int16) - np.asarray(forged, dtype=np.int16)).sum(axis=2)
    ys, xs = np.nonzero(diff)
    if len(xs) == 0:
        return None
    return (int(xs.min()), int(ys.min()), int(xs.max()) + 1, int(ys.max()) + 1)


def verify_localisation(original: Image.Image, forged: Image.Image,
                        box: tuple[int, int, int, int], sample_id: str) -> None:
    """The mask must be exactly what was modified: non-empty, and no changed
    pixel may fall outside it."""
    cb = changed_bbox(original, forged)
    if cb is None:
        raise AssertionError(f"{sample_id}: forgery is pixel-identical to the original")
    x0, y0, x1, y1 = box
    if not (x0 <= cb[0] and cb[1] >= y0 and cb[2] <= x1 and cb[3] <= y1):
        raise AssertionError(
            f"{sample_id}: changed pixels {cb} escape the declared region {box}")


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #

PILOT_FIELD_MAP = {
    "name_replacement": "holder_name",
    "dob_replacement": "dob",
    # The current specimen ID template has Document No., not a separate
    # registration label. It is therefore recorded as registration_number in
    # pilot metadata while preserving the actual template field box.
    "registration_replacement": "document_no",
}
PILOT_FIELD_LABELS = {"name_replacement": "name", "dob_replacement": "date_of_birth", "registration_replacement": "registration_number"}


def _pilot_replace_field(img: Image.Image, tpl: Template, field_name: str,
                         rng: random.Random) -> tuple[int, int, int, int]:
    fld = next(field for field in tpl.fields if field.name == field_name)
    x0, y0, x1, y1 = fld.box
    patch = Image.new("RGB", (x1 - x0, y1 - y0), tuple(int(v) for v in np.median(np.asarray(img.crop(fld.box)).reshape(-1, 3), axis=0)))
    d = ImageDraw.Draw(patch)
    text = _replacement(fld, rng)
    f = font(fld.kind, fld.size)
    l, t, r, b = d.textbbox((0, 0), text, font=f)
    tw, th = r - l, b - t
    tx = 6 if fld.anchor == "left" else max(0, (x1 - x0 - tw) // 2)
    d.text((tx + 1, max(0, (y1 - y0 - th) // 2) - t + 1), text, font=f, fill="#111111")
    img.paste(patch, (x0, y0))
    return fld.box


def _pilot_benign(image: Image.Image, kind: str) -> Image.Image:
    if kind == "jpeg_recompression":
        buf = io.BytesIO(); image.save(buf, "JPEG", quality=82); buf.seek(0); return Image.open(buf).convert("RGB")
    if kind == "resize":
        small = image.resize((int(image.width * .92), int(image.height * .92)), Image.Resampling.LANCZOS)
        return small.resize(image.size, Image.Resampling.LANCZOS)
    if kind == "mild_crop":
        crop = image.crop((3, 3, image.width - 3, image.height - 3))
        return crop.resize(image.size, Image.Resampling.LANCZOS)
    if kind == "brightness":
        return ImageEnhance.Brightness(image).enhance(1.04)
    return ImageEnhance.Contrast(image).enhance(1.05)


def pilot_main() -> int:
    """Generate a small deterministic ID-card-only dataset without touching the main dataset."""
    if PILOT_ROOT.exists():
        shutil.rmtree(PILOT_ROOT)
    for sub in ("references", "evidence", "masks"):
        (PILOT_ROOT / sub).mkdir(parents=True, exist_ok=True)
    samples: list[dict] = []
    limitations = ["The current ID-card template has no explicit course/branch or academic-year field; those pilot cases are not generated."]
    manipulations = ("name_replacement", "dob_replacement", "registration_replacement")
    benign = ("jpeg_recompression", "resize", "mild_crop", "brightness", "contrast")
    for idx in range(5):
        serial = f"IDP-{idx:03d}"
        tpl = build_id_card(random.Random(f"{PILOT_SEED}:id_card:{idx}"), serial)
        reference = PILOT_ROOT / "references" / f"{serial}.png"
        tpl.image.save(reference, "PNG", optimize=True)
        samples.append({"caseId": f"{serial}_genuine", "doc_type": "id_card", "manipulation": "none", "original_path": rel(reference), "forged_path": None, "mask_path": None, "referenceImage": rel(reference), "evidenceImage": rel(reference), "region_box": None, "region": None, "fieldsChanged": [], "expectedDocumentStatus": "genuine", "image_size": list(tpl.image.size), "seed": f"{PILOT_SEED}:genuine:{idx}", "attributes": {}})
        for kind in manipulations:
            rng = random.Random(f"{PILOT_SEED}:{kind}:{idx}")
            evidence_img = tpl.image.copy()
            box = _pilot_replace_field(evidence_img, tpl, PILOT_FIELD_MAP[kind], rng)
            sid = f"{serial}_{kind}"
            evidence = PILOT_ROOT / "evidence" / f"{sid}.png"
            mask_path = PILOT_ROOT / "masks" / f"{sid}.png"
            evidence_img.save(evidence, "PNG", optimize=True); make_mask(tpl.image.size, box).save(mask_path, "PNG", optimize=True)
            samples.append({"caseId": sid, "doc_type": "id_card", "manipulation": kind, "original_path": rel(reference), "forged_path": rel(evidence), "mask_path": rel(mask_path), "referenceImage": rel(reference), "evidenceImage": rel(evidence), "region_box": list(box), "region": {"field": PILOT_FIELD_LABELS[kind], "bbox": [box[0], box[1], box[2]-box[0], box[3]-box[1]]}, "fieldsChanged": [PILOT_FIELD_LABELS[kind]], "expectedDocumentStatus": "manipulated", "image_size": list(tpl.image.size), "seed": f"{PILOT_SEED}:{kind}:{idx}", "attributes": {}})
        for kind in (benign[idx],):
            sid = f"{serial}_{kind}"; evidence = PILOT_ROOT / "evidence" / f"{sid}.png"
            _pilot_benign(tpl.image.copy(), kind).save(evidence, "PNG", optimize=True)
            samples.append({"caseId": sid, "doc_type": "id_card", "manipulation": kind, "original_path": rel(reference), "forged_path": rel(evidence), "mask_path": None, "referenceImage": rel(reference), "evidenceImage": rel(evidence), "region_box": None, "region": None, "fieldsChanged": [], "expectedDocumentStatus": "genuine", "image_size": list(tpl.image.size), "seed": f"{PILOT_SEED}:{kind}:{idx}", "attributes": {}})
    manifest = {"dataset": "forgify-identity-card-pilot-v1", "generator": "documents/dataset/generate_dataset.py --pilot", "seed_base": PILOT_SEED, "doc_types": ["id_card"], "manipulations": list(manipulations), "benign_transformations": list(benign), "expectedDocumentStatusValues": ["genuine", "manipulated"], "limitations": limitations, "samples": samples}
    PILOT_MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"pilot cases: {len(samples)} (15 manipulated, 10 genuine/benign)")
    print(f"manifest: {PILOT_MANIFEST}")
    return 0

def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def reset_output() -> None:
    for base in (ORIGINAL_DIR, FORGED_DIR, MASKS_DIR):
        if base.exists():
            shutil.rmtree(base)
    for doc_type in DOC_TYPES:
        (ORIGINAL_DIR / doc_type).mkdir(parents=True, exist_ok=True)
    for manip in MANIPULATIONS:
        (FORGED_DIR / manip).mkdir(parents=True, exist_ok=True)
        (MASKS_DIR / manip).mkdir(parents=True, exist_ok=True)


def main() -> int:
    reset_output()
    samples: list[dict] = []
    problems: list[str] = []

    for doc_type in DOC_TYPES:
        build = BUILDERS[doc_type]
        print(f"[ {doc_type} ]")
        for idx in range(PER_TYPE):
            serial = f"{doc_type.upper()}-{idx:03d}"
            content_rng = random.Random(f"{SEED_BASE}:{doc_type}:{idx}")
            tpl = build(content_rng, serial)
            w, h = tpl.image.size

            for fld in tpl.fields:
                fx0, fy0, fx1, fy1 = fld.box
                if not (0 <= fx0 < fx1 <= w and 0 <= fy0 < fy1 <= h):
                    problems.append(f"{serial}: field {fld.name} box {fld.box} out of page")
            sx0, sy0, sx1, sy1 = tpl.cm_src
            dx0, dy0, dx1, dy1 = tpl.cm_dst
            if not (0 <= sx0 < sx1 <= w and 0 <= sy0 < sy1 <= h):
                problems.append(f"{serial}: copy_move src {tpl.cm_src} out of page")
            if not (0 <= dx0 < dx1 <= w and 0 <= dy0 < dy1 <= h):
                problems.append(f"{serial}: copy_move dst {tpl.cm_dst} out of page")

            orig_path = ORIGINAL_DIR / doc_type / f"{serial}.png"
            tpl.image.save(orig_path, "PNG", optimize=True)
            samples.append({
                "id": f"{serial}_none",
                "doc_type": doc_type,
                "manipulation": "none",
                "original_path": rel(orig_path),
                "forged_path": None,
                "mask_path": None,
                "region_box": None,
                "image_size": [w, h],
                "seed": f"{SEED_BASE}:{doc_type}:{idx}",
                "attributes": tpl.meta,
            })

            for manip in MANIPULATIONS:
                rng = random.Random(f"{SEED_BASE}:{doc_type}:{idx}:{manip}")
                forged = tpl.image.copy()
                box = APPLY[manip](forged, tpl, rng)
                sid = f"{serial}_{manip}"

                try:
                    verify_localisation(tpl.image, forged, box, sid)
                except AssertionError as exc:
                    problems.append(str(exc))

                forged_path = FORGED_DIR / manip / f"{sid}.png"
                mask_path = MASKS_DIR / manip / f"{sid}.png"
                forged.save(forged_path, "PNG", optimize=True)
                mask = make_mask((w, h), box)
                mask.save(mask_path, "PNG", optimize=True)

                mb = mask_bbox(mask)
                if mb != box:
                    problems.append(f"{sid}: mask bbox {mb} != region {box}")

                samples.append({
                    "id": sid,
                    "doc_type": doc_type,
                    "manipulation": manip,
                    "original_path": rel(orig_path),
                    "forged_path": rel(forged_path),
                    "mask_path": rel(mask_path),
                    "region_box": list(box),
                    "image_size": [w, h],
                    "seed": f"{SEED_BASE}:{doc_type}:{idx}:{manip}",
                    "attributes": {},
                })

    manifest = {
        "dataset": "forgify-synthetic-forgery-v1",
        "description": "Labelled synthetic document forgery dataset: 4 templates x 20 "
                       "originals x 3 manipulations, with pixel-accurate masks.",
        "generator": "documents/dataset/generate_dataset.py",
        "seed_base": SEED_BASE,
        "doc_types": list(DOC_TYPES),
        "manipulations": list(MANIPULATIONS),
        "per_doc_type": PER_TYPE,
        "expected": {
            "originals": len(DOC_TYPES) * PER_TYPE,
            "forged": len(DOC_TYPES) * PER_TYPE * len(MANIPULATIONS),
            "masks": len(DOC_TYPES) * PER_TYPE * len(MANIPULATIONS),
        },
        "region_box_convention": "[x0, y0, x1, y1), half-open, pixel units",
        "notes": "Synthetic and fictional throughout. No forensic scores are stored here.",
        "samples": samples,
    }
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    n_orig = sum(1 for s in samples if s["manipulation"] == "none")
    n_forged = sum(1 for s in samples if s["manipulation"] != "none")
    n_mask = sum(1 for s in samples if s["mask_path"])
    print(f"\noriginals : {n_orig}")
    print(f"forged    : {n_forged}")
    print(f"masks     : {n_mask}")
    print(f"manifest  : {rel(MANIFEST_PATH)} ({len(samples)} entries)")

    if problems:
        print(f"\n{len(problems)} PROBLEM(S):")
        for p in problems[:20]:
            print(f"  - {p}")
        return 1
    print("\nall localisation invariants held (every changed pixel inside its mask).")
    return 0


if __name__ == "__main__":
    raise SystemExit(pilot_main() if "--pilot" in sys.argv[1:] else main())
