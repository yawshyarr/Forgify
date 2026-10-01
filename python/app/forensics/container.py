"""Byte-structure inspection for the Python worker (mirrors containers.ts)."""

from __future__ import annotations

import io
import re

from PIL import Image

STD_LUMA = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
]


def sniff(payload: bytes, mime: str, name: str) -> str:
    if payload[:2] == b"\xff\xd8":
        return "jpeg"
    if payload[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if payload[:5].startswith(b"%PDF"):
        return "pdf"
    if mime.startswith("image/") or re.search(r"\.(png|jpe?g|webp|tiff?|bmp|heic)$", name.lower()):
        return "raster"
    return "unknown"


def jpeg_quality(payload: bytes) -> float | None:
    """Estimate the IJG quality factor from the first luminance DQT table."""
    index = 2
    while index < len(payload) - 4:
        if payload[index] != 0xFF:
            index += 1
            continue
        marker = payload[index + 1]
        if marker == 0xD8 or marker == 0x01:
            index += 2
            continue
        if marker == 0xDA:
            break
        length = (payload[index + 2] << 8) | payload[index + 3]
        if marker == 0xDB:
            segment = payload[index + 4 : index + 2 + length]
            if len(segment) >= 65:
                table = list(segment[1:65])
                ratios = [(q * 100) / STD_LUMA[i] for i, q in enumerate(table) if q > 1 and i < 64]
                if ratios:
                    ratios.sort()
                    scale = ratios[len(ratios) // 2]
                    quality = (200 - scale) / 2 if scale < 100 else 5000 / scale
                    return round(float(min(100, max(1, quality))), 1)
        if length <= 0:
            break
        index += 2 + length
    return None


def png_facts(payload: bytes) -> dict:
    import zlib

    crc_errors: list[str] = []
    texts: dict[str, str] = {}
    idat = 0
    trailing = 0
    index = 8
    width = height = 0
    while index + 8 <= len(payload):
        length = int.from_bytes(payload[index : index + 4], "big")
        chunk_type = payload[index + 4 : index + 8].decode("latin1", errors="replace")
        data_start = index + 8
        data_end = min(len(payload), data_start + length)
        if data_end + 4 > len(payload):
            trailing = max(0, len(payload) - data_start)
            break
        expected = int.from_bytes(payload[data_end : data_end + 4], "big")
        actual = zlib.crc32(payload[index + 4 : data_end]) & 0xFFFFFFFF
        if expected != actual and chunk_type != "IEND":
            crc_errors.append(chunk_type)
        if chunk_type == "IHDR":
            width = int.from_bytes(payload[data_start : data_start + 4], "big")
            height = int.from_bytes(payload[data_start + 4 : data_start + 8], "big")
        elif chunk_type in {"tEXt", "iTXt", "zTXt"}:
            raw = payload[data_start:data_end].split(b"\x00", 1)
            if len(raw) == 2:
                texts[raw[0].decode("latin1", errors="replace")[:40]] = raw[1].decode(
                    "latin1", errors="replace"
                )[:200]
        elif chunk_type == "IDAT":
            idat += 1
        elif chunk_type == "IEND":
            trailing = len(payload) - (data_end + 4)
            break
        index = data_end + 4
    return {
        "width": width,
        "height": height,
        "crcErrors": crc_errors,
        "texts": texts,
        "idatCount": idat,
        "trailingBytes": trailing,
    }


def pdf_facts(payload: bytes) -> dict:
    text = payload[:3_000_000].decode("latin1", errors="replace")

    def grab(key: str) -> str | None:
        match = re.search(rf"/{key}\s*\(([^){{}}]{{0,180}})\)", text)
        return match.group(1).strip() if match else None

    return {
        "version": (re.search(r"%PDF-(\d\.\d)", text) or [None, "unknown"])[1],
        "producer": grab("Producer"),
        "creator": grab("Creator"),
        "title": grab("Title"),
        "pageCount": max(1, len(re.findall(r"/Type\s*/Page[^s]", text))),
        "imageCount": len(re.findall(r"/Subtype\s*/Image", text)),
        "eofCount": len(re.findall(r"%%EOF", text)),
        "incrementalUpdates": max(0, len(re.findall(r"%%EOF", text)) - 1),
        "encrypted": bool(re.search(r"/Encrypt\s+\d+\s+\d+\s+R", text)),
        "javascript": bool(re.search(r"/JavaScript|/JS\s|/OpenAction", text)),
        "signed": bool(re.search(r"/ByteRange|/SigField|adbe\.pkcs7", text)),
        "filters": sorted({m.group(1) for m in re.finditer(r"/Filter\s*/([A-Za-z0-9+#]+)", text)}),
        "xmp": "adobe:ns:meta/" in text,
        "objectCount": len(re.findall(r"\d+\s+\d+\s+obj", text)),
    }


def inspect(payload: bytes, mime: str, name: str) -> dict:
    kind = sniff(payload, mime, name)
    notes: list[str] = []
    facts: dict = {
        "kind": kind,
        "declaredType": mime or "application/octet-stream",
        "detectedType": {"pdf": "application/pdf", "jpeg": "image/jpeg", "png": "image/png"}.get(kind, mime or "unknown"),
        "typeMismatch": False,
        "exifPresent": False,
        "xmpPresent": False,
        "iccPresent": False,
        "thumbnailPresent": False,
        "restartMarkers": False,
        "incrementalUpdates": 0,
        "signed": False,
        "encrypted": False,
        "javascript": False,
        "imageObjects": 0,
        "filters": [],
        "containerNotes": notes,
        "entries": [],
    }

    if kind in {"jpeg", "png", "raster"}:
        try:
            with Image.open(io.BytesIO(payload)) as image:
                facts["width"], facts["height"] = image.size
                facts["exifPresent"] = bool(image.getexif())
                facts["iccPresent"] = "icc_profile" in image.info
                facts["entries"] = [
                    {"group": "EXIF", "key": k, "value": str(v)[:120], "source": "pillow", "flag": "ok"}
                    for k, v in list(image.getexif().items())[:24]
                ]
        except Exception:
            notes.append("Container could not be opened by Pillow; structural facts only.")
        if kind == "jpeg":
            facts["quantizationQuality"] = jpeg_quality(payload)
            notes.append(f"Quantisation-derived IJG quality ≈ {facts.get('quantizationQuality')}.")
        if kind == "png":
            png = png_facts(payload)
            notes.append(f"PNG {png['width']}×{png['height']}, {png['idatCount']} IDAT chunk(s).")
            if png["crcErrors"]:
                notes.append(f"CRC mismatch in chunk(s): {sorted(set(png['crcErrors']))}.")
            if png["trailingBytes"]:
                notes.append(f"{png['trailingBytes']} trailing byte(s) after IEND.")
    elif kind == "pdf":
        pdf = pdf_facts(payload)
        facts.update(
            width=595,
            height=842,
            pageCount=pdf["pageCount"],
            imageObjects=pdf["imageCount"],
            incrementalUpdates=pdf["incrementalUpdates"],
            signed=pdf["signed"],
            encrypted=pdf["encrypted"],
            javascript=pdf["javascript"],
            filters=pdf["filters"],
            producer=pdf["producer"],
            creatorTool=pdf["creator"],
            xmpPresent=pdf["xmp"],
        )
        notes.append(f"PDF {pdf['version']}, {pdf['pageCount']} page object(s), {pdf['objectCount']} indirect objects.")
        if pdf["incrementalUpdates"]:
            notes.append(f"{pdf['incrementalUpdates']} incremental update(s) present — document modified after creation.")
        if not pdf["signed"]:
            notes.append("No qualified signature — no cryptographic integrity anchor.")
    else:
        notes.append("Container not recognised; stream-level statistics only.")

    if (mime or "").startswith("image/") and kind == "pdf":
        facts["typeMismatch"] = True
        notes.append("Declared MIME contradicts byte structure — spoofed extension.")

    facts["detectedType"] = facts["detectedType"] or mime
    return facts


def compare(primary: dict, reference: dict, primary_size: int, reference_size: int) -> list[str]:
    notes = [
        f"Size delta {round((primary_size - reference_size) / max(1, reference_size) * 100, 2)}% "
        f"({primary_size} B vs {reference_size} B)."
    ]
    if primary.get("width") and reference.get("width"):
        same = (primary["width"], primary["height"]) == (reference["width"], reference["height"])
        notes.append(
            f"Dimensions {'match' if same else 'differ'}: "
            f"{primary['width']}×{primary['height']} vs {reference['width']}×{reference['height']}."
        )
    if primary.get("quantizationQuality") and reference.get("quantizationQuality"):
        notes.append(
            "Quantisation quality delta "
            f"{round(abs(primary['quantizationQuality'] - reference['quantizationQuality']), 2)}."
        )
    notes.append(
        f"EXIF presence changed: {'retained' if primary.get('exifPresent') else 'absent'} vs "
        f"{'retained' if reference.get('exifPresent') else 'absent'}."
    )
    if primary.get("incrementalUpdates") != reference.get("incrementalUpdates"):
        notes.append(
            f"Revision count differs: {primary.get('incrementalUpdates')} vs {reference.get('incrementalUpdates')}."
        )
    return notes
