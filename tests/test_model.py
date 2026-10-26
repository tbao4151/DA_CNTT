"""Unit test for ML reproducibility and label-leakage prevention."""
import sys
from pathlib import Path
import pandas as pd
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.model import fit_and_evaluate, predict_batch

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
