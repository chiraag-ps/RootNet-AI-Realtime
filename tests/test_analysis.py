import pandas as pd
from analysis import analyze_dataframe, recommendation_for, severity_for


def test_recommendation_is_actionable():
    text = recommendation_for("PortScan", 60)
    assert "ports" in text.lower() or "scan" in text.lower()


def test_severity_is_bounded():
    assert 0 <= severity_for("BENIGN", 0.8, 99, True) <= 100
    assert 0 <= severity_for("DDoS", 0.9, 90, True) <= 100


def test_unlabeled_data_uses_anomaly_detection():
    frame = pd.DataFrame({
        "Flow Duration": [10, 11, 12, 12, 11, 50000, 13, 12],
        "Total Fwd Packets": [2, 3, 2, 2, 3, 5000, 2, 3],
        "Total Backward Packets": [1, 1, 2, 1, 1, 4000, 1, 1],
    })
    result = analyze_dataframe(frame)
    assert result["summary"]["detection_mode"] == "unsupervised_anomaly_detection"
    assert len(result["incidents"]) == len(frame)
    assert result["summary"]["accuracy"] is None


def test_labeled_data_returns_heldout_metrics():
    frame = pd.DataFrame({
        "Flow Duration": list(range(1, 21)),
        "Total Fwd Packets": [1, 2] * 10,
        "Total Backward Packets": [2, 1] * 10,
        "Label": ["BENIGN"] * 10 + ["DoS Hulk"] * 10,
    })
    result = analyze_dataframe(frame)
    assert result["summary"]["accuracy"] is not None
    assert 0 <= result["summary"]["accuracy"] <= 1
    assert result["summary"]["f1"] is not None
    assert len(result["incidents"]) == len(frame)
