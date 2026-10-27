import pytest
from .run_evaluation import calculate_metrics

def test_perfect_predictions():
    """If all predictions are correct, precision/recall/f1 = 1.0."""
    preds = ["malicious", "malicious", "benign", "benign"]
    actuals = ["malicious", "malicious", "benign", "benign"]
    result = calculate_metrics(preds, actuals)
    assert result["tp"] == 2
    assert result["tn"] == 2
    assert result["fp"] == 0
    assert result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0

def test_all_false_positives():
    """If we predict malicious for benign data, precision = 0."""
    preds = ["malicious", "malicious"]
    actuals = ["benign", "benign"]
    result = calculate_metrics(preds, actuals)
    assert result["tp"] == 0
    assert result["fp"] == 2
    assert result["precision"] == 0.0

def test_all_false_negatives():
    """If we predict benign for malicious data, recall = 0."""
    preds = ["benign", "benign"]
    actuals = ["malicious", "malicious"]
    result = calculate_metrics(preds, actuals)
    assert result["fn"] == 2
    assert result["recall"] == 0.0