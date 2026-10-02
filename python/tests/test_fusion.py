from app.forensics.fusion import fuse


def layer(layer_id, score, confidence=0.9, weight=0.1):
    return {"layer": layer_id, "name": layer_id, "score": score, "confidence": confidence, "weight": weight, "status": "alert" if score >= .5 else "pass"}


def test_correlated_residual_detectors_do_not_stack_as_independent_evidence():
    residual = fuse([layer("pixel", .95), layer("deep-tamper-srm", .95), layer("ml-classifier", .95)], [])
    independent = fuse([layer("layout", .9)], [{"code": "OCR_FIELD_MISMATCH", "severity": "high"}, {"code": "REF-FIELD", "severity": "high"}])
    assert residual["familyEvidence"][0]["family"] == "pixel/residual"
    assert len([x for x in residual["familyEvidence"] if x["score"] > 0]) == 1
    assert residual["riskScore"] < 45
    assert independent["riskScore"] > residual["riskScore"]


def test_cross_family_evidence_increases_confidence():
    one_family = fuse([layer("pixel", .8)], [])
    cross_family = fuse(
        [layer("pixel", .8), layer("layout", .8), layer("qr-barcode", .8)],
        [{"code": "OCR_FIELD_MISMATCH", "severity": "high"}, {"code": "QR_REFERENCE_MISMATCH", "severity": "high"}],
    )
    assert cross_family["confidence"] > one_family["confidence"]
    assert cross_family["riskScore"] > one_family["riskScore"]


def test_reference_layer_and_field_findings_reach_their_families():
    result = fuse(
        [layer("reference", .86), layer("pixel", .98), layer("deep-tamper-srm", .20)],
        [{"code": "REF-FIELD", "severity": "high"}, {"code": "REF-TEXT", "severity": "high"}, {"code": "REF-QR", "severity": "critical"}],
    )
    families = {item["family"]: item for item in result["familyEvidence"]}
    assert families["structural/reference"]["score"] > 0
    assert families["semantic"]["findingCount"] == 2
    assert families["encoded-data"]["findingCount"] == 1
