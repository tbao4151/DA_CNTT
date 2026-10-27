"""Unit test for ML reproducibility and label-leakage prevention."""
import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.model import fit_and_evaluate, model_artifact_signature, predict_batch

def fixtures():
    rows=[]
    for i in range(24):
        rows.append(dict(
          id=i+1,proto="tcp" if i%2 else "udp",
          service="http" if i%2 else "dns",state="FIN" if i%2 else "CON",
          dur=i/10,sbytes=12*i,dbytes=3*i+1,spkts=1+i%3,
          dpkts=1+i%4,rate=float(8+i*13),
          label=i%2,attack_cat="Exploits" if i%2 else "Normal"))
    return pd.DataFrame(rows)

def test_training_and_inference_without_ground_truth():
    df=fixtures()
    model,report=fit_and_evaluate(df.iloc[:16],df.iloc[16:])
    features=set(model.named_steps["preprocess"].feature_names_in_)
    assert not features.intersection({"id","attack_cat","label"})
    predictions=predict_batch(model,df.iloc[16:].drop(columns=["label","attack_cat","id"]))
    assert len(predictions)==8
    assert predictions["attack_probability"].between(0,1).all()
    assert report["test_size"]==8
    assert len(report["confusion_matrix_0_1"])==2

def test_missing_label_is_error():
    df=fixtures()
    with pytest.raises(ValueError,match="label"):
        fit_and_evaluate(df.drop(columns=["label"]),df)


@pytest.mark.parametrize("split", ["train", "test"])
@pytest.mark.parametrize("invalid_label", [float("nan"), 2, "1"])
def test_training_rejects_missing_or_nonbinary_labels(split, invalid_label):
    df = fixtures()
    train = df.iloc[:16].copy()
    test = df.iloc[16:].copy()
    target = train if split == "train" else test
    target.loc[target.index[0], "label"] = invalid_label
    with pytest.raises(ValueError, match="complete binary 0/1 labels"):
        fit_and_evaluate(train, test)


def test_training_excludes_predictions_and_view_fields():
    df = fixtures()
    # A dataframe previously processed by the dashboard must not leak
    # predicted labels/probabilities or UI flow references into retraining.
    df["AI_verdict"] = df["label"].map({0: "Normal", 1: "Attack"})
    df["AI_attack_probability"] = df["label"].astype(float)
    df["flow_ref"] = df.index.astype(str)
    model, report = fit_and_evaluate(df.iloc[:16], df.iloc[16:])
    trained_features = set(model.named_steps["preprocess"].feature_names_in_)
    assert not trained_features.intersection({
        "id", "label", "attack_cat", "AI_verdict",
        "AI_attack_probability", "flow_ref",
    })
    assert set(report["features"]) == trained_features
    assert len(predict_batch(model, df.iloc[16:])) == 8


def test_model_cache_signature_changes_when_artifact_replaced(tmp_path):
    artifact = tmp_path / "unsw_binary_rf.joblib"
    artifact.write_bytes(b"first")
    original = model_artifact_signature(artifact)
    assert original[1] == 5

    # A new artifact at the same path must generate a different Streamlit
    # cache key even if the original model was already loaded.
    artifact.write_bytes(b"new-model-content")
    assert model_artifact_signature(artifact) != original

    # Rewrites with unchanged file size must also invalidate the key.
    same_size = artifact.stat().st_size
    old_mtime = artifact.stat().st_mtime_ns
    artifact.write_bytes(b"x" * same_size)
    os.utime(artifact, ns=(old_mtime + 2_000_000_000, old_mtime + 2_000_000_000))
    assert model_artifact_signature(artifact) != (old_mtime, same_size)


def test_model_cache_signature_missing_artifact(tmp_path):
    with pytest.raises(FileNotFoundError):
        model_artifact_signature(tmp_path / "missing.joblib")


def test_training_requires_both_classes():
    df = fixtures()
    only_normal = df.loc[df["label"] == 0]
    with pytest.raises(ValueError, match="both Normal.*Attack"):
        fit_and_evaluate(only_normal, df.iloc[16:])


def test_predict_batch_uses_attack_label_not_fixed_column_position():
    df = fixtures()
    model, _ = fit_and_evaluate(df.iloc[:16], df.iloc[16:])
    sample = df.iloc[16:]
    expected = predict_batch(model, sample)

    class ReorderedClassModel:
        classes_ = np.array([1, 0])
        feature_names_in_ = model.named_steps["preprocess"].feature_names_in_

        def predict_proba(self, rows):
            return model.predict_proba(rows)[:, ::-1]

    actual = predict_batch(ReorderedClassModel(), sample)
    pd.testing.assert_frame_equal(actual, expected)


@pytest.mark.parametrize("classes", [[1], [0, 2], ["0", "1"]])
def test_predict_batch_rejects_incompatible_model_classes(classes):
    df = fixtures()
    model, _ = fit_and_evaluate(df.iloc[:16], df.iloc[16:])

    class IncompatibleModel:
        classes_ = np.array(classes)
        feature_names_in_ = model.named_steps["preprocess"].feature_names_in_

        def predict_proba(self, rows):
            return np.ones((len(rows), len(classes)))

    with pytest.raises(ValueError, match="binary classes"):
        predict_batch(IncompatibleModel(), df.iloc[16:])


@pytest.mark.parametrize("invalid_score", [float("nan"), float("inf"), -0.1, 1.1])
def test_predict_batch_rejects_invalid_attack_probabilities(invalid_score):
    df = fixtures()
    model, _ = fit_and_evaluate(df.iloc[:16], df.iloc[16:])

    class InvalidProbabilityModel:
        classes_ = np.array([0, 1])
        feature_names_in_ = model.named_steps["preprocess"].feature_names_in_

        def predict_proba(self, rows):
            return np.tile([0.5, invalid_score], (len(rows), 1))

    with pytest.raises(ValueError, match="invalid Attack probabilities"):
        predict_batch(InvalidProbabilityModel(), df.iloc[16:])


def test_predict_batch_rejects_wrong_probability_matrix_shape():
    df = fixtures()
    model, _ = fit_and_evaluate(df.iloc[:16], df.iloc[16:])

    class WrongShapeModel:
        classes_ = np.array([0, 1])
        feature_names_in_ = model.named_steps["preprocess"].feature_names_in_

        def predict_proba(self, rows):
            return np.ones((len(rows), 1))

    with pytest.raises(ValueError, match="invalid probability matrix"):
        predict_batch(WrongShapeModel(), df.iloc[16:])
