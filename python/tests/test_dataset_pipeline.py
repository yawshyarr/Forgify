import json
from pathlib import Path

from PIL import Image


DATASET_ROOT = Path(__file__).resolve().parents[2] / "documents" / "dataset"
ROOT = DATASET_ROOT / "pilot"


def _manifest():
    path = ROOT / "manifest.json"
    if not path.exists():
        import pytest
        pytest.skip("pilot dataset has not been generated")
    return json.loads(path.read_text(encoding="utf-8"))


def test_pilot_manifest_has_identity_and_benign_cases():
    samples = _manifest()["samples"]
    assert len(samples) == 25
    assert sum(s["expectedDocumentStatus"] == "manipulated" for s in samples) == 15
    assert sum(s["expectedDocumentStatus"] == "genuine" for s in samples) == 10
    assert {s["manipulation"] for s in samples} >= {"name_replacement", "dob_replacement", "registration_replacement", "jpeg_recompression", "resize"}


def test_manipulated_pilot_masks_and_field_metadata_are_valid():
    for sample in _manifest()["samples"]:
        if sample["expectedDocumentStatus"] != "manipulated":
            continue
        mask = Image.open(DATASET_ROOT / sample["mask_path"])
        evidence = Image.open(DATASET_ROOT / sample["evidenceImage"])
        assert mask.size == evidence.size
        assert sample["fieldsChanged"]
        assert sample["region"]["field"] in sample["fieldsChanged"]
        assert mask.getbbox() is not None


def test_genuine_pilot_cases_have_no_forgery_masks():
    for sample in _manifest()["samples"]:
        if sample["expectedDocumentStatus"] == "genuine":
            assert sample["fieldsChanged"] == []
            assert sample["mask_path"] is None


def test_manifest_paths_are_relative_to_dataset_root():
    for sample in _manifest()["samples"]:
        assert not Path(sample["referenceImage"]).is_absolute()
        assert not Path(sample["evidenceImage"]).is_absolute()
