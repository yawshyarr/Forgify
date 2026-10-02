from app.forensics.evaluation import (
    AUTHENTIC_CASES,
    MANIPULATED_CASES,
    EvaluationCase,
    evaluate_cases,
    pair_regression,
)


def test_identity_suite_contains_requested_categories():
    assert len(AUTHENTIC_CASES) == 8
    assert len(MANIPULATED_CASES) == 10
    assert "replaced QR" in MANIPULATED_CASES
    assert "scanned/reprinted ID" in AUTHENTIC_CASES


def test_metrics_record_detector_family_and_errors_without_tuning():
    reports = {
        "clean": {"verdict": {"riskScore": 20}, "layers": [{"layer": "pixel", "score": .2}],
                  "fusion": {"familyEvidence": [{"family": "pixel/residual", "score": .2}]}},
        "tamper": {"verdict": {"riskScore": 80}, "layers": [{"layer": "layout", "score": .8}],
                   "fusion": {"familyEvidence": [{"family": "semantic", "score": .8}]},
                   "unifiedRegions": [{"regionType": "name"}]},
    }
    cases = [EvaluationCase("auth-1", "original photograph", False, "clean"),
             EvaluationCase("man-1", "changed name", True, "tamper")]
    result = evaluate_cases(cases, lambda case: reports[case.evidence_path], threshold=50)
    assert result["counts"] == {"TP": 1, "TN": 1, "FP": 0, "FN": 0}
    assert result["metrics"] == {"precision": 1.0, "recall": 1.0, "F1": 1.0, "falsePositiveRate": 0.0, "falseNegativeRate": 0.0}
    assert result["cases"][1]["suspiciousRegions"] == [{"regionType": "name"}]


def test_pair_regression_checks_ordering_not_filenames_or_fixed_scores():
    original = {"verdict": {"riskScore": 21}, "referenceComparison": {"aligned": True},
                "fusion": {"familyEvidence": [{"score": .2}]}, "unifiedRegions": []}
    manipulated = {"verdict": {"riskScore": 27}, "referenceComparison": {"aligned": True},
                   "fusion": {"familyEvidence": [{"score": .7}, {"score": .6}]},
                   "unifiedRegions": [{"regionType": "name"}]}
    result = pair_regression(original, manipulated)
    assert result["manipulatedStronger"] is True
    assert result["hasIndependentEvidence"] is True
