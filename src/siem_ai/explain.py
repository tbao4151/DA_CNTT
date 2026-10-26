"""Global Random Forest impurity importances grouped by original UNSW features.

This is a descriptive model diagnostic, NOT a per-flow causal explanation.
No ground-truth labels, record IDs, or current test labels are used.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .core import LABEL_FIELDS


def global_feature_importance(model, top_n: int | None = None) -> pd.DataFrame:
    """Map fitted one-hot and numeric dimensions back to raw model features.

    Supports this project's fitted ColumnTransformer (numeric SimpleImputer
    and categorical SimpleImputer -> OneHotEncoder without infrequent/drop).
    Fail closed on incompatible preprocessing instead of mislabeling bars.
    """
    if top_n is not None and (type(top_n) is not int or top_n < 1):
        raise ValueError("top_n must be a positive integer or None")

    try:
        pre = model.named_steps["preprocess"]
        forest = model.named_steps["forest"]
        raw_names = [str(x) for x in pre.feature_names_in_]
        scores = np.asarray(forest.feature_importances_, dtype=float)
        output_indices = pre.output_indices_
    except (AttributeError, KeyError, TypeError) as exc:
        raise ValueError("Expected a fitted DA005 RandomForest pipeline") from exc

    if any(name in LABEL_FIELDS for name in raw_names):
        raise ValueError("Trained features must exclude ground-truth labels and IDs")
    if len(set(raw_names)) != len(raw_names):
        raise ValueError("Duplicated feature names")
    if scores.ndim != 1 or len(scores) != forest.n_features_in_:
        raise ValueError("Invalid fitted forest feature importance shape")
    if not np.isfinite(scores).all() or (scores < 0).any():
        raise ValueError("Feature importance values must be finite and nonnegative")

    # Transformer slices are provided by the *fitted* ColumnTransformer.
    # Numeric imputation may drop entirely missing training columns.
    columns = {}
    numeric_columns = list(pre.transformers_[0][2])
    categorical_columns = list(pre.transformers_[1][2])
    if pre.transformers_[0][0] != "numeric" or pre.transformers_[1][0] != "categorical":
        raise ValueError("Unsupported preprocessing structure")
    if set(numeric_columns + categorical_columns) != set(raw_names):
        raise ValueError("Feature mapping does not cover original input columns")

    num_slice = output_indices["numeric"]
    cat_slice = output_indices["categorical"]
    numeric_imputer = pre.named_transformers_["numeric"]
    kept_numeric = list(numeric_imputer.get_feature_names_out(numeric_columns))
    if len(kept_numeric) != num_slice.stop - num_slice.start:
        raise ValueError("Cannot map numerical dimensions")
    for i, name in enumerate(kept_numeric):
        columns[name] = (float(scores[num_slice.start + i]), 1)

    cat_pipeline = pre.named_transformers_["categorical"]
    imputed_categorical = list(cat_pipeline.named_steps["impute"].get_feature_names_out(categorical_columns))
    encoder = cat_pipeline.named_steps["encode"]
    if encoder.drop is not None or encoder.min_frequency is not None or encoder.max_categories is not None:
        raise ValueError("Unsupported one-hot categories configuration")

    pos = cat_slice.start
    if len(imputed_categorical) != len(encoder.categories_):
        raise ValueError("Cannot match categorical columns to encoder")
    for name, values in zip(imputed_categorical, encoder.categories_):
        width = len(values)
        if width == 0 or pos + width > cat_slice.stop:
            raise ValueError("Invalid one-hot output width")
        columns[name] = (float(scores[pos:pos + width].sum()), width)
        pos += width
    if pos != cat_slice.stop:
        raise ValueError("One-hot width does not match fitted transformer")

    # All preprocessing dimensions should be accounted for.
    if num_slice.start != 0 or num_slice.stop != cat_slice.start or cat_slice.stop != len(scores):
        raise ValueError("Preprocessing output contains unmapped dimensions")

    total = float(sum(v[0] for v in columns.values()))
    output = pd.DataFrame([
        {"feature": name, "importance": columns.get(name, (0., 0))[0],
         "encoded_dimensions": columns.get(name, (0., 0))[1]}
        for name in raw_names
    ])
    output["importance_percent"] = output["importance"] / total * 100 if total else 0.
    output = output.sort_values(["importance", "feature"], ascending=[False, True], kind="stable").reset_index(drop=True)
    return output.head(top_n).copy() if top_n is not None else output
