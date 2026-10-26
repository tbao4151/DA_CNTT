"""Global RandomForest attribution mapping and misuse protection."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.explain import global_feature_importance
from siem_ai.model import fit_and_evaluate


def fixture_frame():
    rows = []
    for i in range(30):
        rows.append({
            "id": i + 1, "proto": ["tcp", "udp", "icmp"][i % 3],
            "service": ["http", "dns", "ssl_tls"][i % 3],
            "state": ["FIN", "CON", "INT"][i % 3],
            "dur": i / 8, "sbytes": i * 12, "dbytes": i * 5,
            "spkts": i % 5 + 1, "dpkts": i % 4 + 1,
            "label": i % 2, "attack_cat": "Exploits" if i % 2 else "Normal",
        })
    return pd.DataFrame(rows)


def fitted():
    data = fixture_frame()
    return fit_and_evaluate(data.iloc[:22], data.iloc[22:])[0]


def test_one_hot_does_not_appear_as_misleading_independent_features():
    model = fitted()
    result = global_feature_importance(model)
    expected = set(model.named_steps["preprocess"].feature_names_in_)
    assert set(result["feature"]) == expected
    assert not {"id", "label", "attack_cat"} & set(result["feature"])
    assert (result["importance"] >= 0).all()
    assert result["importance_percent"].sum() == pytest.approx(100)
    assert result["importance"].sum() == pytest.approx(1)
    assert result["encoded_dimensions"].sum() == model.named_steps["forest"].n_features_in_
    assert (result["encoded_dimensions"] > 1).any()


def test_ranking_and_display_limits():
    model = fitted()
    all_scores = global_feature_importance(model)
    top = global_feature_importance(model, top_n=3)
    assert len(top) == 3
    assert top["feature"].tolist() == all_scores["feature"].head(3).tolist()
    assert np.all(np.diff(all_scores["importance"].to_numpy()) <= 1e-12)
    assert "id" not in top["feature"].values


@pytest.mark.parametrize("top", [0, -2, 1.0, True])
def test_invalid_top_n(top):
    with pytest.raises(ValueError, match="top_n"):
        global_feature_importance(fitted(), top_n=top)


def test_rejects_malformed_model():
    with pytest.raises(ValueError, match="pipeline"):
        global_feature_importance(object())
