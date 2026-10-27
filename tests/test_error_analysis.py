"""Synthetic-only tests for aggregated held-out error analysis."""
import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from siem_ai.error_analysis import summarize_group_errors


def test_grouped_errors_count_each_confusion_matrix_cell():
    actual = [0, 0, 1, 1, 1, 0, 1, 0]
    predicted = [0, 1, 1, 0, 0, 0, 1, 1]
    groups = ["Normal", "Normal", "Exploits", "Exploits", "Fuzzers", "Normal", "Fuzzers", None]
    rows = summarize_group_errors(actual, predicted, groups)
    by_name = {row["group"]: row for row in rows}
    assert set(by_name) == {"Normal", "Exploits", "Fuzzers", "(missing)"}
    assert by_name["Normal"]["fp"] == 1
    assert by_name["Normal"]["tn"] == 2
    assert by_name["Normal"]["attack_recall"] is None
    assert by_name["Normal"]["normal_false_positive_rate"] == pytest.approx(1 / 3)
    assert by_name["Exploits"]["attack_recall"] == 0.5
    assert by_name["(missing)"]["fp"] == 1
    assert [sum(row[key] for row in rows) for key in ("tp", "fp", "tn", "fn")] == [2, 2, 2, 2]


def test_grouped_errors_handle_empty_and_null_groups():
    rows = summarize_group_errors([1, 0, 1], [0, 0, 1], pd.Series([None, "", "tcp"]))
    assert [r["group"] for r in rows] == ["(missing)", "tcp"]
    assert rows[0]["fn"] == 1 and rows[0]["tn"] == 1
    assert rows[1]["attack_recall"] == 1.0


@pytest.mark.parametrize("actual,predicted,groups", [
    ([1], [], ["x"]),
    ([1], [1], []),
    ([2], [1], ["x"]),
    ([1], [-1], ["x"]),
])
def test_grouped_errors_reject_mismatched_lengths_and_nonbinary(actual, predicted, groups):
    with pytest.raises(ValueError):
        summarize_group_errors(actual, predicted, groups)
