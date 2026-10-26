"""Offline, synthetic-fixture tests; no dataset download required."""
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from src.da005.dataset import DatasetValidationError, SPLITS, load_split, summarize, validate_frame


class DatasetTests(unittest.TestCase):
    def setUp(self):
        self.frame = pd.DataFrame({
            "id": [1, 2, 3],
            "label": [0, 1, 1],
            "attack_cat": ["Normal", "Exploits", "DoS"],
            "dur": [0.1, 1.0, 2.0],
        })

    def test_valid_summary(self):
        self.assertEqual(summarize(self.frame)["attack"], 2)
        self.assertEqual(summarize(self.frame)["normal"], 1)

    def test_missing_column_rejected(self):
        with self.assertRaises(DatasetValidationError):
            validate_frame(self.frame.drop(columns=["attack_cat"]))

    def test_invalid_label_rejected(self):
        bad = self.frame.copy()
        bad.loc[1, "label"] = 2
        with self.assertRaises(DatasetValidationError):
            validate_frame(bad)

    def test_inconsistent_ground_truth_rejected(self):
        bad = self.frame.copy()
        bad.loc[0, "attack_cat"] = "DoS"
        with self.assertRaises(DatasetValidationError):
            validate_frame(bad)

    def test_empty_rejected(self):
        with self.assertRaises(DatasetValidationError):
            validate_frame(self.frame.iloc[0:0])

    def test_allowlist_and_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            self.frame.to_csv(Path(directory) / SPLITS["test"], index=False)
            self.assertEqual(len(load_split("test", 2, Path(directory))), 2)
            with self.assertRaises(ValueError):
                load_split("../../etc/passwd", data_dir=Path(directory))
            with self.assertRaises(ValueError):
                load_split("test", 0, Path(directory))

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                load_split("train", data_dir=Path(directory))


if __name__ == "__main__":
    unittest.main()
