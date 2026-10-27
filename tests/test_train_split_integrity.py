"""Regression tests for official-split integrity gate before training.

Small synthetic CSVs only; no official model training or network access.
"""
import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.train_siem import load_verified_split


TRAIN = "UNSW_NB15_training-set.csv"
TEST = "UNSW_NB15_testing-set.csv"


def make_split(tmp_path):
    contents = {
        TRAIN: b"dur,label\n1,0\n2,1\n",
        TEST: b"dur,label\n3,1\n",
    }
    expected = {}
    for name, content in contents.items():
        (tmp_path / name).write_bytes(content)
        expected[name] = (len(content.decode().splitlines()) - 1, hashlib.sha256(content).hexdigest())
    return expected


def test_verified_split_accepts_matching_hashes_and_rows(tmp_path):
    expected = make_split(tmp_path)
    train, test = load_verified_split(tmp_path, expected_files=expected)
    assert len(train) == 2 and len(test) == 1
    assert train["label"].tolist() == [0, 1]


@pytest.mark.parametrize("filename", [TRAIN, TEST])
def test_verified_split_rejects_modified_csv_before_training(tmp_path, filename):
    expected = make_split(tmp_path)
    path = tmp_path / filename
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        load_verified_split(tmp_path, expected_files=expected)


@pytest.mark.parametrize("filename", [TRAIN, TEST])
def test_verified_split_rejects_missing_csv(tmp_path, filename):
    expected = make_split(tmp_path)
    (tmp_path / filename).unlink()
    with pytest.raises(FileNotFoundError):
        load_verified_split(tmp_path, expected_files=expected)


def test_verified_split_rejects_row_count_even_with_matching_hash(tmp_path):
    expected = make_split(tmp_path)
    expected[TRAIN] = (3, expected[TRAIN][1])
    with pytest.raises(ValueError, match="expected 3 rows"):
        load_verified_split(tmp_path, expected_files=expected)
