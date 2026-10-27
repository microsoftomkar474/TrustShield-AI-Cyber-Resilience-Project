"""
TrustShield AI — F5 Evaluation Framework

Runs the URL and Message analyzers against labelled datasets
and calculates Precision, Recall, and F1 Score.

IMPORTANT: This dataset is synthetic. The metrics demonstrate
methodology, not real-world accuracy.
"""

import json
import os
import sys

# Ensure backend package is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.url_analyzer import URLAnalyzer
from app.services.message_analyzer import MessageAnalyzer
from app.services.risk_assessment import RiskAssessor


def load_json(filename: str):
    path = os.path.join(os.path.dirname(__file__), filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def calculate_metrics(predictions, actuals):
    tp = sum(1 for p, a in zip(predictions, actuals) if p == "malicious" and a == "malicious")
    tn = sum(1 for p, a in zip(predictions, actuals) if p == "benign" and a == "benign")
    fp = sum(1 for p, a in zip(predictions, actuals) if p == "malicious" and a == "benign")
    fn = sum(1 for p, a in zip(predictions, actuals) if p == "benign" and a == "malicious")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def print_metrics(name: str, metrics: dict):
    print(f"\n{'='*50}")
    print(f"  {name} EVALUATION RESULTS")
    print(f"{'='*50}")
    print(f"  True Positives  (TP): {metrics['tp']}")
    print(f"  True Negatives  (TN): {metrics['tn']}")
    print(f"  False Positives (FP): {metrics['fp']}")
    print(f"  False Negatives (FN): {metrics['fn']}")
    print(f"  -------------------------------------------")
    print(f"  Precision: {metrics['precision']*100:.1f}%")
    print(f"  Recall:    {metrics['recall']*100:.1f}%")
    print(f"  F1 Score:  {metrics['f1']*100:.1f}%")
    print(f"{'='*50}")


def run_url_evaluation():
    analyzer = URLAnalyzer()
    assessor = RiskAssessor()
    data = load_json("dataset_urls.json")
    
    predictions = []
    actuals = []
    
    for item in data:
        indicators, _ = analyzer.analyse(item["url"])
        # Fixed: correct parameter name is threat_intel_confirmed
        label, _ = assessor.assess_url(indicators, threat_intel_confirmed=False)
        predicted = "malicious" if label.value in ("MEDIUM", "HIGH") else "benign"
        predictions.append(predicted)
        actuals.append(item["label"])
    
    metrics = calculate_metrics(predictions, actuals)
    print_metrics("URL ANALYZER", metrics)
    return metrics


def run_message_evaluation():
    analyzer = MessageAnalyzer()
    assessor = RiskAssessor()
    data = load_json("dataset_messages.json")

    predictions = []
    actuals = []

    for item in data:
        # FIX: analyse() returns a tuple (indicators, urls)
        indicators, _ = analyzer.analyse(item["message"])
        # FIX: pass indicators list and empty url_labels list
        label, _ = assessor.assess_message(indicators, url_labels=[])
        predicted = "malicious" if label.value in ("MEDIUM", "HIGH") else "benign"
        predictions.append(predicted)
        actuals.append(item["label"])

    metrics = calculate_metrics(predictions, actuals)
    print_metrics("MESSAGE ANALYZER", metrics)
    return metrics


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  TRUSTSHIELD AI — F5 EVALUATION FRAMEWORK")
    print("="*50)
    print("  Dataset: Synthetic (for methodology demonstration only)")
    print("  Note: These metrics do not represent real-world accuracy.")
    print("="*50)
    
    run_url_evaluation()
    run_message_evaluation()
    
    print("\n" + "="*50)
    print("  EVALUATION COMPLETE")
    print("="*50 + "\n")