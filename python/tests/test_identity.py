from types import SimpleNamespace

from app.forensics.identity import analyze_identity, extract_fields


def words(label, value, left=10, top=10):
    return [
        {"text": label, "left": left, "top": top, "width": 40, "height": 12, "conf": 95},
        {"text": value, "left": left + 50, "top": top, "width": 120, "height": 12, "conf": 95},
    ]


def test_fields_preserve_raw_and_normalized_text():
    field = extract_fields(words("Name:", "  A--  B  "), (100, 300))[0]
    assert field["rawText"] == "A--  B"
    assert field["normalizedText"] == "a b"


def test_registration_trailing_ocr_token_is_unreliable_not_mismatch():
    reference = SimpleNamespace(words=words("Reg.No", "R-23-0245"))
    evidence = SimpleNamespace(words=words("Reg.No", "R-23-0245 Pine"))
    result = analyze_identity(None, evidence, None, None)
    # Exercise the paired path with tiny images only when OpenCV is available.
    import numpy as np
    result = analyze_identity(np.zeros((100, 300, 3), dtype=np.uint8), evidence,
                              np.zeros((100, 300, 3), dtype=np.uint8), reference)
    finding = next(item for item in result["fieldFindings"] if item["fieldType"] == "registration_number")
    assert finding["comparisonState"] == "UNRELIABLE_OCR"
    assert finding["type"] == "OCR_FIELD_UNRELIABLE"
    assert finding["confidence"] < 0.6


def test_name_replacement_remains_direct_mismatch():
    import numpy as np
    reference = SimpleNamespace(words=words("Name", "KALEKAR ROSHANI RAJENDRA"))
    evidence = SimpleNamespace(words=words("Name", "VAIDEHI SANTOSH BHUWAD"))
    result = analyze_identity(np.zeros((100, 400, 3), dtype=np.uint8), evidence,
                              np.zeros((100, 400, 3), dtype=np.uint8), reference)
    finding = next(item for item in result["fieldFindings"] if item["fieldType"] == "name")
    assert finding["type"] == "OCR_FIELD_MISMATCH"
    assert finding["comparisonState"] == "MISMATCH"
    assert finding["referenceText"] == "KALEKAR ROSHANI RAJENDRA"
    assert finding["evidenceText"] == "VAIDEHI SANTOSH BHUWAD"


def test_split_date_of_birth_label_extracts_nearby_date():
    import numpy as np
    split = [
        {"text": "Date", "left": 10, "top": 10, "width": 35, "height": 12, "conf": 95},
        {"text": "of", "left": 50, "top": 10, "width": 15, "height": 12, "conf": 95},
        {"text": "Birth", "left": 70, "top": 10, "width": 35, "height": 12, "conf": 95},
        {"text": "29", "left": 120, "top": 10, "width": 18, "height": 12, "conf": 95},
        {"text": "/", "left": 140, "top": 10, "width": 8, "height": 12, "conf": 95},
        {"text": "12", "left": 150, "top": 10, "width": 18, "height": 12, "conf": 95},
        {"text": "/", "left": 170, "top": 10, "width": 8, "height": 12, "conf": 95},
        {"text": "2002", "left": 180, "top": 10, "width": 35, "height": 12, "conf": 95},
    ]
    field = next(item for item in extract_fields(split, (100, 300)) if item["fieldType"] == "date_of_birth")
    assert field["rawText"] == "29 / 12 / 2002"
    assert field["normalizedText"] == "29 12 2002"


def test_same_line_date_of_birth_label_extracts_date():
    field = extract_fields(words("Date of Birth", "29/12/2002"), (100, 300))[0]
    assert field["fieldType"] == "date_of_birth"
    assert field["rawText"] == "29/12/2002"
