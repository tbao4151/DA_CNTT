"""Paired, offline Zeek research port-feature ablation on identical fixed splits.

Not an UNSW benchmark, deployed detector, operational alert, or evidence that
operator-supplied labels / VMware isolation are authentic. Both variants fit
preprocessing on TRAIN and select their own threshold on VALIDATION only.
"""
from __future__ import annotations

from collections.abc import Mapping

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from .features import LAB_FEATURE_COLUMNS, LAB_FEATURE_SCHEMA_VERSION
from .labeled_dataset import LabeledLabDataset, SPLITS
from .host_variability import summarize_host_variability
from .paired_disagreement import summarize_paired_zeek_test
from .offline_baseline import (
    CATEGORICAL, NUMERIC, THRESHOLDS, _frame, _scores, _validate_dataset,
    make_zeek_research_pipeline,
)

PORT_FEATURES = frozenset({"src_port", "dst_port"})
PORTLESS_NUMERIC = tuple(field for field in NUMERIC if field not in PORT_FEATURES)
PORTLESS_COLUMNS = tuple(field for field in LAB_FEATURE_COLUMNS if field not in PORT_FEATURES)


def _portless_pipeline() -> Pipeline:
    """Actually DROP both port columns at the transformer, not mask their values."""
    return Pipeline([
        ("preprocessing", ColumnTransformer(
            transformers=[
                ("categorical", OneHotEncoder(handle_unknown="ignore", max_categories=32), list(CATEGORICAL)),
                ("numeric", Pipeline([
                    ("imputer", SimpleImputer(strategy="median")),
                    ("scale", StandardScaler()),
                ]), list(PORTLESS_NUMERIC)),
            ],
            remainder="drop",
            sparse_threshold=1.0,
        )),
        ("classifier", LogisticRegression(
            class_weight="balanced", max_iter=2000, random_state=42,
        )),
    ])


def _fit_one(dataset: LabeledLabDataset, model: Pipeline, columns: tuple[str, ...]) -> tuple[dict[str, object], list[bool]]:
    train = _frame(dataset.features["train"])
    model.fit(train, dataset.labels["train"])
    classes = list(model.named_steps["classifier"].classes_)
    if classes != [0, 1]:
        raise ValueError("Expected binary Zeek research classes")
    validation = model.predict_proba(_frame(dataset.features["validation"]))[:, classes.index(1)]
    candidates = {
        threshold: _scores(dataset.labels["validation"], validation, threshold)
        for threshold in THRESHOLDS
    }
    selected = max(THRESHOLDS, key=lambda t: (
        candidates[t]["f1"], -candidates[t]["fp"], t,
    ))
    # TEST is consulted only after fitting and validation threshold selection.
    test = model.predict_proba(_frame(dataset.features["test"]))[:, classes.index(1)]
    return {
        "used_feature_columns": list(columns),
        "selected_validation_threshold": selected,
        "validation_metrics": candidates[selected],
        "test_metrics": _scores(dataset.labels["test"], test, selected),
        "validation_host_variability": summarize_host_variability(
            dataset.labels["validation"], validation,
            [p["host_group"] for p in dataset.provenance["validation"]], selected,
            suppress_small_groups=True,
        ),
        "test_host_variability": summarize_host_variability(
            dataset.labels["test"], test,
            [p["host_group"] for p in dataset.provenance["test"]], selected,
            suppress_small_groups=True,
        ),
    }, [bool(probability >= selected) for probability in test]


def evaluate_zeek_port_ablation(dataset: LabeledLabDataset) -> dict[str, object]:
    """Compare full nine-column model with a true two-port-column exclusion.

    Fixed predeclared variants only; do not pick a winner using TEST metrics.
    Both variants see the same TRAIN/VALIDATION/TEST rows and supplied labels.
    """
    _validate_dataset(dataset)
    full, full_predictions = _fit_one(dataset, make_zeek_research_pipeline(), LAB_FEATURE_COLUMNS)
    portless, portless_predictions = _fit_one(dataset, _portless_pipeline(), PORTLESS_COLUMNS)
    paired = summarize_paired_zeek_test(
        dataset.labels["test"], full_predictions, portless_predictions,
        host_groups=[p["host_group"] for p in dataset.provenance["test"]],
    )
    deltas = {
        name: portless["test_metrics"][name] - full["test_metrics"][name]
        for name in ("precision", "recall", "f1", "false_positive_rate")
    }
    sources = {
        split: {
            "flows": len(dataset.labels[split]),
            "source_sha256": sorted({p["source_sha256"] for p in dataset.provenance[split]}),
            "host_groups": len({p["host_group"] for p in dataset.provenance[split]}),
            "sessions": len({p["session_id"] for p in dataset.provenance[split]}),
        }
        for split in SPLITS
    }
    return {
        "report_version": 2,
        "mode": "offline_zeek_port_feature_ablation_research_only",
        "feature_schema_version": LAB_FEATURE_SCHEMA_VERSION,
        "label_authenticity": "operator_supplied_not_verified",
        "split_policy": "identical_operator_declared_host_session_disjoint_splits",
        "model": "LogisticRegression(class_weight=balanced,random_state=42)",
        "threshold_selection": "each_variant_validation_max_f1_tiebreak_min_fp_then_higher_threshold",
        "excluded_port_features": sorted(PORT_FEATURES),
        "variants": {"full": full, "without_ports": portless},
        "test_delta_without_ports_minus_full": deltas,
        "paired_test_correctness": paired,
        "provenance": sources,
        "test_metrics_used_for_model_selection": False,
        "causal_feature_effect_established": False,
        "host_group_variability_is_descriptive_only": True,
        "host_only_isolation_verified": False,
        "independent_ground_truth_verified": False,
        "live_capture": False,
        "automated_alerts": False,
        "soc_cases_created": False,
        "interpretation": (
            "Paired software-only sensitivity analysis of two prespecified models. "
            "TEST is evaluated once per variant after validation threshold selection; "
            "differences and paired correctness counts are descriptive, not causal, "
            "and must not be used to select "
            "a deployed variant on held-out TEST. Supplied labels and physical lab "
            "isolation require independent verification."
        ),
    }
