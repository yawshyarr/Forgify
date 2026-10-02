"""Train and evaluate the binary image-forensics classifier."""

from __future__ import annotations

import csv
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    precision_recall_fscore_support,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.calibration import CalibratedClassifierCV


FEATURE_NAMES = (
    "ocr_confidence",
    "ela_score",
    "copy_move_score",
    "noise_anomaly",
    "text_inconsistency",
)
LABEL_COLUMN = "label"
CLASS_LABELS = ("genuine", "forged")
FORGERY_TYPE_COLUMN = "forgery_type"
FORGERY_TYPE_CLASS_LABELS = ("genuine", "copy_move", "text_replace")
FORGERY_TYPE_ALIASES = {
    "none": "genuine",
    "copy_move": "copy_move",
    "text_replace": "text_replace",
}
LABEL_ALIASES = {
    "0": "genuine",
    "1": "forged",
    "genuine": "genuine",
    "forged": "forged",
}
RANDOM_STATE = 42
DATASET_PATH = Path(__file__).resolve().parents[3] / "dataset" / "features.csv"
MODEL_PATH = Path(__file__).resolve().parent / "models" / "binary_classifier.pkl"
FORGERY_TYPE_MODEL_PATH = (
    Path(__file__).resolve().parent / "models" / "forgery_type_classifier.pkl"
)


def _groups_for_dataset(dataset_path: Path, feature_count: int) -> np.ndarray:
    """Group all variants of one source/template together to prevent leakage."""
    groups = []
    with dataset_path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            sample_id = (row.get("sample_id") or "unknown").strip()
            # Synthetic IDs use *_none, *_text_replace, etc.; future datasets
            # can provide an explicit template_id column.
            template = row.get("template_id") or sample_id.rsplit("_", 1)[0]
            try:
                values = [float(row[name]) for name in FEATURE_NAMES]
            except (TypeError, ValueError):
                continue
            if np.isfinite(values).all():
                groups.append(template)
    if len(groups) != feature_count:
        raise ValueError(f"Group count {len(groups)} does not match feature rows {feature_count}")
    return np.asarray(groups)


def _report_metrics(y_true, predictions, probabilities) -> dict[str, float]:
    """Report operational metrics, including both error directions."""
    matrix = confusion_matrix(y_true, predictions, labels=CLASS_LABELS)
    tn, fp, fn, tp = matrix.ravel()
    return {
        "precision": float(precision_score(y_true, predictions, pos_label="forged", zero_division=0)),
        "recall": float(recall_score(y_true, predictions, pos_label="forged", zero_division=0)),
        "f1": float(f1_score(y_true, predictions, pos_label="forged", zero_division=0)),
        "false_positive_rate": float(fp / max(1, fp + tn)),
        "false_negative_rate": float(fn / max(1, fn + tp)),
        "roc_auc": float(roc_auc_score((y_true == "forged").astype(int), probabilities)),
    }


def load_training_data(dataset_path: Path) -> tuple[np.ndarray, np.ndarray, int]:
    """Load CSV features, discarding rows with missing or non-finite features."""
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    feature_rows: list[list[float]] = []
    labels: list[str] = []
    dropped_rows = 0

    with dataset_path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        expected_columns = set(FEATURE_NAMES) | {LABEL_COLUMN}
        available_columns = set(reader.fieldnames or ())
        missing_columns = expected_columns - available_columns
        if missing_columns:
            raise ValueError(
                "Dataset is missing required columns: "
                + ", ".join(sorted(missing_columns))
            )

        for row_number, row in enumerate(reader, start=2):
            try:
                features = [float(row[feature]) for feature in FEATURE_NAMES]
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Row {row_number} contains a non-numeric feature value."
                ) from error

            if not np.isfinite(features).all():
                dropped_rows += 1
                continue

            raw_label = (row[LABEL_COLUMN] or "").strip().lower()
            label = LABEL_ALIASES.get(raw_label)
            if label is None:
                raise ValueError(
                    f"Row {row_number} has an invalid label {raw_label!r}; "
                    "expected genuine/forged or 0/1."
                )

            feature_rows.append(features)
            labels.append(label)

    features_array = np.asarray(feature_rows, dtype=float)
    labels_array = np.asarray(labels)
    if len(features_array) == 0:
        raise ValueError("No training rows remain after dropping invalid features.")
    if set(labels_array) != set(CLASS_LABELS):
        raise ValueError(f"Both classes are required; found {sorted(set(labels_array))}.")

    return features_array, labels_array, dropped_rows


def load_forgery_type_training_data(
    dataset_path: Path,
) -> tuple[np.ndarray, np.ndarray, int]:
    """Load only the supported forgery types and discard invalid feature rows."""
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {dataset_path}")

    feature_rows: list[list[float]] = []
    labels: list[str] = []
    dropped_rows = 0

    with dataset_path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        expected_columns = set(FEATURE_NAMES) | {FORGERY_TYPE_COLUMN}
        available_columns = set(reader.fieldnames or ())
        missing_columns = expected_columns - available_columns
        if missing_columns:
            raise ValueError(
                "Dataset is missing required columns: "
                + ", ".join(sorted(missing_columns))
            )

        for row_number, row in enumerate(reader, start=2):
            raw_forgery_type = (row[FORGERY_TYPE_COLUMN] or "").strip().lower()
            label = FORGERY_TYPE_ALIASES.get(raw_forgery_type)
            if label is None:
                continue

            try:
                features = [float(row[feature]) for feature in FEATURE_NAMES]
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Row {row_number} contains a non-numeric feature value."
                ) from error

            if not np.isfinite(features).all():
                dropped_rows += 1
                continue

            feature_rows.append(features)
            labels.append(label)

    features_array = np.asarray(feature_rows, dtype=float)
    labels_array = np.asarray(labels)
    if len(features_array) == 0:
        raise ValueError("No training rows remain after dropping invalid features.")
    if set(labels_array) != set(FORGERY_TYPE_CLASS_LABELS):
        raise ValueError(
            "All supported forgery-type classes are required; found "
            f"{sorted(set(labels_array))}."
        )

    return features_array, labels_array, dropped_rows


def main() -> None:
    features, labels, dropped_rows = load_training_data(DATASET_PATH)
    groups = _groups_for_dataset(DATASET_PATH, len(features))
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)
    train_indices, test_indices = next(splitter.split(features, labels, groups))
    x_train, x_test = features[train_indices], features[test_indices]
    y_train, y_test = labels[train_indices], labels[test_indices]

    classifier = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    calibrated = CalibratedClassifierCV(classifier, method="sigmoid", cv=3)
    calibrated.fit(x_train, y_train)
    predictions = calibrated.predict(x_test)
    probabilities = calibrated.predict_proba(x_test)[:, list(calibrated.classes_).index("forged")]

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, pos_label="forged", zero_division=0)
    recall = recall_score(y_test, predictions, pos_label="forged", zero_division=0)
    f1 = f1_score(y_test, predictions, pos_label="forged", zero_division=0)
    matrix = confusion_matrix(y_test, predictions, labels=CLASS_LABELS)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(calibrated, MODEL_PATH)

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows used: {len(features)}")
    print(f"Rows dropped for NaN/non-finite features: {dropped_rows}")
    print(f"Train samples: {len(x_train)}")
    print(f"Test samples: {len(x_test)}")
    print("\nHeld-out test metrics (positive class: forged)")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1: {f1:.4f}")
    print("Operational metrics:", _report_metrics(y_test, predictions, probabilities))
    print("Split: GroupShuffleSplit by template/source ID; probabilities calibrated with held-out group split + sigmoid CV.")
    print("Confusion matrix (rows=true, columns=predicted; labels=[genuine, forged]):")
    print(matrix)
    print("\nFeature importances:")
    fitted_forest = calibrated.calibrated_classifiers_[0].estimator
    for feature_name, importance in zip(FEATURE_NAMES, fitted_forest.feature_importances_):
        print(f"{feature_name}: {importance:.4f}")
    print(f"\nModel saved to: {MODEL_PATH}")

    forgery_features, forgery_labels, forgery_dropped_rows = (
        load_forgery_type_training_data(DATASET_PATH)
    )
    x_train, x_test, y_train, y_test = train_test_split(
        forgery_features,
        forgery_labels,
        test_size=0.2,
        stratify=forgery_labels,
        random_state=RANDOM_STATE,
    )
    forgery_classifier = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    forgery_classifier.fit(x_train, y_train)
    predictions = forgery_classifier.predict(x_test)
    precision, recall, _, support = precision_recall_fscore_support(
        y_test,
        predictions,
        labels=FORGERY_TYPE_CLASS_LABELS,
        zero_division=0,
    )
    matrix = confusion_matrix(y_test, predictions, labels=FORGERY_TYPE_CLASS_LABELS)

    joblib.dump(forgery_classifier, FORGERY_TYPE_MODEL_PATH)

    print("\nThree-class forgery-type held-out test metrics")
    print(f"Rows used: {len(forgery_features)}")
    print(f"Rows dropped for NaN/non-finite features: {forgery_dropped_rows}")
    print(f"Train samples: {len(x_train)}")
    print(f"Test samples: {len(x_test)}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print("Per-class precision and recall:")
    for class_name, class_precision, class_recall, class_support in zip(
        FORGERY_TYPE_CLASS_LABELS, precision, recall, support
    ):
        print(
            f"{class_name}: precision={class_precision:.4f}, "
            f"recall={class_recall:.4f}, support={class_support}"
        )
    print(
        "Confusion matrix (rows=true, columns=predicted; "
        "labels=[genuine, copy_move, text_replace]):"
    )
    print(matrix)
    print(f"Model saved to: {FORGERY_TYPE_MODEL_PATH}")
    print(
        "Currently implemented forgery classes: 3 (genuine, copy-move, "
        "text-replacement). Whiteout detection is handled separately by the "
        "rule-based pixel/ELA layer and is not yet part of the trained classifier."
    )


if __name__ == "__main__":
    main()
