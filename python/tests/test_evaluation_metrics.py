import numpy as np

from evaluation.identity_card import binary_metrics, mask_from_regions, overlap_metrics, auc, _localization_sources


def test_confusion_and_classification_metrics():
    result = binary_metrics([True, True, False, False], [True, False, True, False])
    assert result["confusionMatrix"] == {"tp": 1, "tn": 1, "fp": 1, "fn": 1}
    assert result["precision"] == result["recall"] == result["f1"] == 0.5
    assert result["fpr"] == result["fnr"] == 0.5


def test_iou_dice_and_empty_mask_semantics():
    truth = np.array([[1, 1], [0, 0]], dtype=bool)
    predicted = np.array([[1, 0], [0, 0]], dtype=bool)
    iou, dice = overlap_metrics(predicted, truth)
    assert round(iou, 4) == 0.5
    assert round(dice, 4) == 0.6667
    assert overlap_metrics(np.zeros((2, 2), bool), truth) == (0.0, 0.0)
    assert overlap_metrics(np.zeros((2, 2), bool), np.zeros((2, 2), bool)) == (1.0, 1.0)


def test_malformed_regions_are_ignored_and_auc_is_deterministic():
    mask = mask_from_regions([{"bbox": {"x": .1, "y": .1, "width": .2, "height": .2}}, {"bad": True}], (10, 10))
    assert int(mask.sum()) > 0
    assert auc([True, False], [.9, .1]) == 1.0


def test_reference_assisted_prefers_existing_reference_regions():
    report = {"unifiedRegions": [{"bbox": {"x": 0, "y": 0, "width": 1, "height": 1}}],
              "regions": [], "referenceComparison": {"changedRegions": [{"bbox": {"x": .2, "y": .3, "width": .1, "height": .1}}]}, "identityFindings": []}
    selected, audit = _localization_sources(report, True)
    assert audit["sources"] == ["referenceComparison.changedRegions"]
    assert selected[0]["bbox"]["x"] == .2


def test_reference_free_does_not_consume_reference_regions():
    report = {"unifiedRegions": [{"bbox": {"x": .1, "y": .1, "width": .2, "height": .2}}],
              "referenceComparison": {"changedRegions": [{"bbox": {"x": .8, "y": .8, "width": .1, "height": .1}}]}}
    selected, audit = _localization_sources(report, False)
    assert audit["sources"] == ["unifiedRegions"]
    assert selected[0]["bbox"]["x"] == .1
