from app.forensics.regions import aggregate_regions


def test_overlapping_detector_regions_are_one_explainable_region():
    raw = [
        {"layer": "reference", "label": "Aligned reference difference", "score": .9, "confidence": .9,
         "x": .1, "y": .2, "width": .2, "height": .3, "notes": "portrait changed"},
        {"layer": "deep-srm", "label": "Residual hotspot", "score": .55, "confidence": .6,
         "x": .11, "y": .21, "width": .19, "height": .29, "notes": "stable across scales"},
        {"layer": "pixel", "label": "ELA hotspot", "score": .5, "confidence": .5,
         "x": .1, "y": .2, "width": .2, "height": .3, "notes": "stable quality hotspot"},
    ]
    regions, findings = aggregate_regions(raw)
    assert len(regions) == 1
    assert set(regions[0]["detectors"]) == {"reference", "deep-srm", "pixel"}
    assert regions[0]["regionType"] == "portrait"
    assert len(findings) == 1
    assert "Corroborated" in findings[0]["description"]


def test_separate_regions_are_not_double_merged():
    raw = [
        {"layer": "pixel", "label": "name", "score": .6, "confidence": .7,
         "x": .4, "y": .2, "width": .12, "height": .04},
        {"layer": "qr-barcode", "label": "QR", "score": .8, "confidence": .9,
         "x": .8, "y": .8, "width": .1, "height": .1},
    ]
    regions, _ = aggregate_regions(raw)
    assert len(regions) == 2
    assert {r["regionType"] for r in regions} == {"name", "QR"}
