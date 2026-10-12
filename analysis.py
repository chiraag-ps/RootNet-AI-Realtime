"""Understandable batch analysis pipeline for RootNet AI.

This is an educational project, not a production intrusion prevention system.
Metrics are computed on a held-out test split when the uploaded data has labels.
"""
import re
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

MAX_ROWS = 20000
LABEL_NAMES = {"label", "attack", "class", "target", "traffic_label"}
SOURCE_NAMES = {"source ip", "src ip", "src_ip", "source_ip", "src"}
DEST_NAMES = {"destination ip", "dst ip", "dst_ip", "destination_ip", "dst"}
TIME_NAMES = {"timestamp", "time", "datetime", "flow start", "flow start time"}


def normalized_name(name):
    return re.sub(r"[_\-]+", " ", str(name).strip().lower())


def find_column(columns, choices):
    for col in columns:
        if normalized_name(col) in {normalized_name(x) for x in choices}:
            return col
    return None


def recommendation_for(label, severity):
    text = str(label).lower()
    if "benign" in text or text == "normal":
        if severity >= 70:
            return "Review the unusual traffic pattern and verify whether it is expected."
        return "No immediate action. Continue monitoring and compare with the normal baseline."
    if "ddos" in text or text.startswith("dos"):
        return "Check request/packet rates and destination service health. Apply rate limits only after validating the source."
    if "brute" in text:
        return "Review authentication logs, check repeated failures, and consider rate limiting or MFA."
    if "portscan" in text or "port scan" in text:
        return "Review the source and destination ports. Confirm whether the scan is authorized."
    if "web" in text or "sql" in text or "xss" in text:
        return "Inspect web server and application logs for the related requests before blocking traffic."
    if "bot" in text or "infiltration" in text:
        return "Isolate the affected test host if appropriate and investigate related connections and endpoint logs."
    if "anomaly" in text:
        return "Compare this flow with the usual baseline and inspect related traffic before taking action."
    return "Review the flow metadata and related logs. Validate the alert before taking action."


def severity_for(label, confidence, anomaly_score, supervised):
    label_text = str(label).lower()
    if not supervised:
        return 85 if anomaly_score >= 80 else 65 if anomaly_score >= 60 else 15
    if "benign" in label_text or label_text == "normal":
        return int(min(45, anomaly_score * 0.45))
    if "ddos" in label_text or label_text.startswith("dos"):
        base = 85
    elif "web" in label_text or "sql" in label_text or "xss" in label_text:
        base = 75
    elif "bot" in label_text or "infiltration" in label_text or "heartbleed" in label_text:
        base = 85
    elif "brute" in label_text:
        base = 70
    elif "portscan" in label_text or "port scan" in label_text:
        base = 55
    else:
        base = 65
    # Confidence and anomaly are supporting signals, not calibrated risk probabilities.
    return int(np.clip(0.65 * base + 0.20 * confidence * 100 + 0.15 * anomaly_score, 0, 100))


def analyze_dataframe(frame):
    if frame is None or frame.empty:
        raise ValueError("The uploaded CSV contains no rows.")
    if len(frame) < 2:
        raise ValueError("Upload at least two rows so the data can be analyzed.")

    frame = frame.copy().replace([np.inf, -np.inf], np.nan)
    frame.columns = [str(c).strip() for c in frame.columns]
    label_col = find_column(frame.columns, LABEL_NAMES)
    src_col = find_column(frame.columns, SOURCE_NAMES)
    dst_col = find_column(frame.columns, DEST_NAMES)
    time_col = find_column(frame.columns, TIME_NAMES)

    excluded = {c for c in [label_col, src_col, dst_col, time_col] if c is not None}
    excluded.update(c for c in frame.columns if normalized_name(c) in {"flow id", "id"})
    feature_frame = frame.drop(columns=list(excluded), errors="ignore")
    numeric = feature_frame.apply(pd.to_numeric, errors="coerce")
    numeric = numeric.dropna(axis=1, how="all")
    numeric = numeric.loc[:, numeric.nunique(dropna=True) > 1]
    if numeric.shape[1] < 1:
        raise ValueError("No usable numeric traffic features were found. Upload a numeric network-flow CSV.")

    # A simple row cap keeps a laptop-friendly demo responsive.
    if len(numeric) > MAX_ROWS:
        keep = np.linspace(0, len(numeric) - 1, MAX_ROWS).astype(int)
        frame = frame.iloc[keep].reset_index(drop=True)
        numeric = numeric.iloc[keep].reset_index(drop=True)

    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    numeric = numeric.fillna(numeric.median(numeric_only=True)).fillna(0)
    numeric = numeric.clip(lower=-1e12, upper=1e12)

    actual = None
    if label_col:
        actual = frame[label_col].astype(str).str.strip()
        valid = actual.notna() & (actual != "") & (actual.str.lower() != "nan")
        frame = frame.loc[valid].reset_index(drop=True)
        numeric = numeric.loc[valid].reset_index(drop=True)
        actual = actual.loc[valid].reset_index(drop=True)

    if len(numeric) < 2:
        raise ValueError("Not enough valid rows remain after cleaning the CSV.")

    supervised = bool(actual is not None and actual.nunique() >= 2 and actual.value_counts().min() >= 2)
    model = None
    confidence_values = np.zeros(len(numeric), dtype=float)
    metrics = {"accuracy": None, "precision": None, "recall": None, "f1": None}
    metrics_note = "No usable Label column with at least two examples per class was found. Evaluation metrics are unavailable; anomaly detection was used."
    top_features = []
    if supervised:
        X_train, X_test, y_train, y_test = train_test_split(
            numeric, actual, test_size=0.25, random_state=42, stratify=actual
        )
        model = Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("classifier", RandomForestClassifier(
                n_estimators=100, class_weight="balanced_subsample",
                random_state=42, n_jobs=-1, min_samples_leaf=2
            ))
        ])
        model.fit(X_train, y_train)
        test_pred = model.predict(X_test)
        metrics = {
            "accuracy": round(float(accuracy_score(y_test, test_pred)), 4),
            "precision": round(float(precision_score(y_test, test_pred, average="weighted", zero_division=0)), 4),
            "recall": round(float(recall_score(y_test, test_pred, average="weighted", zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, test_pred, average="weighted", zero_division=0)), 4)
        }
        metrics_note = "Metrics are computed on a held-out test split. Predictions shown for individual rows come from the model trained on the training split; this is a project demo, not a production-validated detector."
        predictions = model.predict(numeric)
        if hasattr(model.named_steps["classifier"], "predict_proba"):
            confidence_values = model.predict_proba(numeric).max(axis=1)
        importances = model.named_steps["classifier"].feature_importances_
        ranked = sorted(zip(numeric.columns, importances), key=lambda x: x[1], reverse=True)[:8]
        top_features = [{"feature": str(name), "importance": round(float(score), 4)} for name, score in ranked]
    else:
        # IsolationForest is an approachable unsupervised baseline for unlabeled traffic.
        model = IsolationForest(n_estimators=100, contamination="auto", random_state=42, n_jobs=-1)
        model.fit(numeric)
        raw = -model.decision_function(numeric)
        lo, hi = float(np.min(raw)), float(np.max(raw))
        anomaly_scores = np.zeros(len(raw)) if hi - lo < 1e-9 else (raw - lo) / (hi - lo) * 100
        predictions = np.where(anomaly_scores >= 70, "ANOMALY", "BENIGN")
        confidence_values = np.zeros(len(numeric), dtype=float)
        top_features = [{"feature": str(c), "importance": None} for c in numeric.columns[:8]]

    # A normalized anomaly score is a relative score within this upload, not a probability.
    if supervised:
        anomaly_model = IsolationForest(n_estimators=80, contamination="auto", random_state=42, n_jobs=-1)
        anomaly_model.fit(numeric)
        raw = -anomaly_model.decision_function(numeric)
        lo, hi = float(np.min(raw)), float(np.max(raw))
        anomaly_scores = np.zeros(len(raw)) if hi - lo < 1e-9 else (raw - lo) / (hi - lo) * 100

    incidents = []
    for i, pred in enumerate(predictions):
        label = str(pred)
        conf = float(confidence_values[i]) if supervised else None
        anomaly = float(anomaly_scores[i])
        severity = severity_for(label, conf or 0.0, anomaly, supervised)
        src = str(frame.iloc[i][src_col]) if src_col and pd.notna(frame.iloc[i][src_col]) else None
        dst = str(frame.iloc[i][dst_col]) if dst_col and pd.notna(frame.iloc[i][dst_col]) else None
        event_time = str(frame.iloc[i][time_col]) if time_col and pd.notna(frame.iloc[i][time_col]) else None
        correlation_key = f"{src}->{dst}" if src and dst else f"{label}:severity-{severity // 20}"
        actual_label = str(actual.iloc[i]) if actual is not None else None
        feature_note = ", ".join(x["feature"] for x in top_features[:3]) or "numeric traffic features"
        if supervised:
            explanation = (
                f"Predicted class: {label}; model confidence: {conf:.0%}. "
                f"Relative anomaly score: {anomaly:.0f}/100. Globally important model features include: {feature_note}. "
                "Feature importance is global and does not prove the cause of this individual flow."
            )
        else:
            explanation = (
                f"Unsupervised anomaly score: {anomaly:.0f}/100. "
                "The score is relative to this upload and is not a probability or proof of malicious activity."
            )
        incidents.append({
            "flow_number": i + 1,
            "predicted_label": label,
            "actual_label": actual_label,
            "severity_score": severity,
            "confidence": round(conf, 4) if conf is not None else None,
            "anomaly_score": round(anomaly, 2),
            "source_ip": src,
            "destination_ip": dst,
            "event_time": event_time,
            "correlation_key": correlation_key,
            "explanation": explanation,
            "recommendation": recommendation_for(label, severity)
        })

    attacks = sum(1 for row in incidents if row["predicted_label"].lower() not in {"benign", "normal"})
    severities = [row["severity_score"] for row in incidents]
    summary = {
        "total_flows": len(incidents),
        "attacks_detected": attacks,
        "high_severity": sum(s >= 70 for s in severities),
        "average_severity": round(float(np.mean(severities)), 2) if severities else 0,
        "detection_mode": "supervised_classifier_plus_anomaly_score" if supervised else "unsupervised_anomaly_detection",
        **metrics
    }
    return {"summary": summary, "incidents": incidents, "metrics_note": metrics_note, "top_features": top_features}
