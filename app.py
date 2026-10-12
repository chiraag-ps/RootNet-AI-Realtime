import io
import json
import os
import sqlite3
import hashlib
from datetime import timedelta
from datetime import datetime, timezone

import pandas as pd
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename

from analysis import analyze_dataframe, MAX_ROWS
from zeek_monitor import ZeekLogMonitor, normalize_event_time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "rootnet.db")
SAMPLE_LOG = os.path.join(BASE_DIR, "sample_data", "conn.log")
MONITOR_INTERVAL = 5
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB total request size
ALLOWED_EXTENSIONS = {".csv"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}})


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                filenames TEXT NOT NULL,
                total_flows INTEGER NOT NULL,
                attacks_detected INTEGER NOT NULL,
                high_severity INTEGER NOT NULL,
                average_severity REAL NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                detection_mode TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                flow_number INTEGER NOT NULL,
                predicted_label TEXT NOT NULL,
                actual_label TEXT,
                severity_score INTEGER NOT NULL,
                confidence REAL,
                anomaly_score REAL NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                event_time TEXT,
                correlation_key TEXT NOT NULL,
                explanation TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                FOREIGN KEY(analysis_id) REFERENCES analyses(id)
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_analysis ON incidents(analysis_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity_score)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_label ON incidents(predicted_label)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS live_connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_key TEXT NOT NULL UNIQUE,
                uid TEXT,
                event_time TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT,
                service TEXT,
                duration REAL,
                orig_bytes INTEGER NOT NULL DEFAULT 0,
                resp_bytes INTEGER NOT NULL DEFAULT 0,
                conn_state TEXT,
                orig_pkts INTEGER NOT NULL DEFAULT 0,
                resp_pkts INTEGER NOT NULL DEFAULT 0,
                anomaly_score INTEGER NOT NULL DEFAULT 0,
                is_alert INTEGER NOT NULL DEFAULT 0,
                severity TEXT NOT NULL DEFAULT 'Low',
                alert_reason TEXT,
                alert_status TEXT NOT NULL DEFAULT 'Open',
                source_file TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_live_event_time ON live_connections(event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_live_src_time ON live_connections(src_ip, event_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_live_alert_status ON live_connections(is_alert, alert_status)")


def as_dict(row):
    return dict(row) if row is not None else None


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def store_live_record(record, source_path):
    """Store one Zeek flow and apply explainable rule-based anomaly indicators."""
    event_time = normalize_event_time(record.get("ts")) or _utc_now()
    ingested_at = _utc_now()
    src_ip = str(record.get("src_ip") or "unknown")
    dst_ip = str(record.get("dst_ip") or "unknown")
    src_port = int(record.get("src_port") or 0)
    dst_port = int(record.get("dst_port") or 0)
    conn_state = str(record.get("conn_state") or "unknown").upper()
    orig_bytes = int(record.get("orig_bytes") or 0)
    resp_bytes = int(record.get("resp_bytes") or 0)
    uid = record.get("uid")

    identity = "|".join(str(v) for v in (
        uid or "", record.get("ts") or "", src_ip, src_port,
        dst_ip, dst_port, record.get("protocol") or ""
    ))
    event_key = hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest()

    # Zeek's event timestamp—not the time a historical log is imported—drives the
    # 60-second behavior window. This avoids treating a large old log as live traffic.
    try:
        parsed_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        if parsed_time.tzinfo is None:
            parsed_time = parsed_time.replace(tzinfo=timezone.utc)
        cutoff = (parsed_time - timedelta(seconds=60)).isoformat(timespec="milliseconds")
    except ValueError:
        cutoff = event_time

    suspicious_ports = {23, 2323, 4444, 5555, 6667, 31337}
    failed_states = {"S0", "REJ", "RSTOS0", "SH", "RSTRH"}
    reasons = []
    score = 0

    with get_db() as conn:
        recent = conn.execute(
            "SELECT dst_port, conn_state FROM live_connections "
            "WHERE src_ip = ? AND event_time >= ? AND event_time <= ?",
            (src_ip, cutoff, event_time)
        ).fetchall()
        recent_ports = {row["dst_port"] for row in recent if row["dst_port"] is not None}
        recent_count = len(recent)
        recent_failed = sum(1 for row in recent if row["conn_state"] in failed_states)

        if conn_state in failed_states:
            score += 30
            reasons.append(f"Connection ended with state {conn_state}")
            if recent_failed >= 4:
                score += 20
                reasons.append("Repeated failed connection attempts within 60 seconds")
        if dst_port in suspicious_ports:
            score += 25
            reasons.append(f"Connection targets a commonly scrutinized port ({dst_port})")
        if len(recent_ports | {dst_port}) >= 8:
            score += 55
            reasons.append("Source contacted 8 or more destination ports within 60 seconds (possible port scan)")
        if recent_count >= 29:
            score += 25
            reasons.append("High connection volume from the same source within 60 seconds")
        if orig_bytes >= 50 * 1024 * 1024 and resp_bytes <= 10 * 1024:
            score += 45
            reasons.append("Large one-way outbound transfer; verify whether it is expected")

        score = min(score, 100)
        is_alert = int(score >= 50)
        severity = "High" if score >= 75 else "Medium" if score >= 50 else "Low"
        reason = "; ".join(reasons) if reasons else "No configured heuristic was triggered"
        cursor = conn.execute("""
            INSERT OR IGNORE INTO live_connections (
                event_key, uid, event_time, ingested_at, src_ip, src_port, dst_ip, dst_port,
                protocol, service, duration, orig_bytes, resp_bytes, conn_state, orig_pkts,
                resp_pkts, anomaly_score, is_alert, severity, alert_reason, source_file
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_key, uid, event_time, ingested_at, src_ip, src_port, dst_ip, dst_port,
            record.get("protocol"), record.get("service"), float(record.get("duration") or 0),
            orig_bytes, resp_bytes, conn_state, int(record.get("orig_pkts") or 0),
            int(record.get("resp_pkts") or 0), score, is_alert, severity, reason, source_path
        ))
        return cursor.rowcount > 0


monitor = ZeekLogMonitor(store_live_record, interval=MONITOR_INTERVAL)


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Upload too large. Keep the total request below 50 MB."}), 413


@app.get("/")
def home():
    return jsonify({
        "name": "RootNet AI Enhanced",
        "message": "Network threat analysis API is running.",
        "docs": "See README.md for available endpoints."
    })


@app.get("/api/status")
def status():
    return jsonify({"status": "running", "database": "SQLite", "mode": "CSV batch + Zeek log monitoring"})


@app.post("/api/analyze")
def analyze_upload():
    uploads = request.files.getlist("files")
    uploads = [f for f in uploads if f and f.filename]

    if not uploads:
        return jsonify({"error": "Select at least one CSV file."}), 400
    if len(uploads) > 8:
        return jsonify({"error": "Upload at most 8 CSV files per analysis."}), 400

    frames = []
    filenames = []
    for upload in uploads:
        filename = secure_filename(upload.filename)
        if not filename or os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Only CSV files are supported: {upload.filename}"}), 400
        try:
            frame = pd.read_csv(upload.stream, low_memory=False, nrows=MAX_ROWS)
        except Exception as exc:
            return jsonify({"error": f"Could not read {filename}: {exc}"}), 400
        if frame.empty:
            continue
        frame.columns = [str(c).strip() for c in frame.columns]
        frames.append(frame)
        filenames.append(filename)

    if not frames:
        return jsonify({"error": "The uploaded CSV files were empty."}), 400

    data = pd.concat(frames, ignore_index=True, sort=False)
    if len(data) > MAX_ROWS:
        data = data.sample(n=MAX_ROWS, random_state=42).reset_index(drop=True)

    try:
        result = analyze_dataframe(data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Analysis failed")
        return jsonify({"error": f"Analysis failed: {exc}"}), 500

    summary = result["summary"]
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_db() as conn:
        cur = conn.execute("""
            INSERT INTO analyses
            (created_at, filenames, total_flows, attacks_detected, high_severity,
             average_severity, accuracy, precision_score, recall_score, f1_score, detection_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            created_at, json.dumps(filenames), summary["total_flows"],
            summary["attacks_detected"], summary["high_severity"],
            summary["average_severity"], summary.get("accuracy"),
            summary.get("precision"), summary.get("recall"), summary.get("f1"),
            summary["detection_mode"]
        ))
        analysis_id = cur.lastrowid

        rows = result["incidents"]
        conn.executemany("""
            INSERT INTO incidents
            (analysis_id, flow_number, predicted_label, actual_label, severity_score,
             confidence, anomaly_score, source_ip, destination_ip, event_time,
             correlation_key, explanation, recommendation, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open')
        """, [(
            analysis_id, r["flow_number"], r["predicted_label"], r.get("actual_label"),
            r["severity_score"], r.get("confidence"), r["anomaly_score"],
            r.get("source_ip"), r.get("destination_ip"), r.get("event_time"),
            r["correlation_key"], r["explanation"], r["recommendation"]
        ) for r in rows])

    return jsonify({
        "analysis_id": analysis_id,
        "created_at": created_at,
        "filenames": filenames,
        "summary": summary,
        "metrics_note": result["metrics_note"],
        "top_features": result["top_features"],
        "incidents": result["incidents"][:200]
    }), 201


@app.get("/api/summary")
def summary():
    with get_db() as conn:
        latest = conn.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT 1").fetchone()
        total_analyses = conn.execute("SELECT COUNT(*) AS n FROM analyses").fetchone()["n"]
        open_incidents = conn.execute("SELECT COUNT(*) AS n FROM incidents WHERE status != 'Resolved'").fetchone()["n"]
        high = conn.execute("SELECT COUNT(*) AS n FROM incidents WHERE severity_score >= 70 AND status != 'Resolved'").fetchone()["n"]
    return jsonify({
        "latest_analysis": as_dict(latest),
        "total_analyses": total_analyses,
        "open_incidents": open_incidents,
        "high_severity_open": high
    })


@app.get("/api/history")
def history():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM analyses ORDER BY id DESC LIMIT 50").fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["filenames"] = json.loads(item["filenames"])
        except Exception:
            item["filenames"] = []
        out.append(item)
    return jsonify(out)


@app.get("/api/incidents")
def incidents():
    q = request.args.get("q", "").strip()[:100]
    severity = request.args.get("severity", "all")
    status_filter = request.args.get("status", "all")
    analysis_id = request.args.get("analysis_id", "").strip()
    limit = min(max(int(request.args.get("limit", 200)), 1), 1000)

    sql = "SELECT * FROM incidents WHERE 1=1"
    args = []
    if q:
        sql += """ AND (predicted_label LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ?
                    OR recommendation LIKE ? OR correlation_key LIKE ?)"""
        args.extend([f"%{q}%"] * 5)
    if severity == "high":
        sql += " AND severity_score >= 70"
    elif severity == "medium":
        sql += " AND severity_score >= 40 AND severity_score < 70"
    elif severity == "low":
        sql += " AND severity_score < 40"
    if status_filter in {"Open", "Investigating", "Resolved"}:
        sql += " AND status = ?"
        args.append(status_filter)
    if analysis_id.isdigit():
        sql += " AND analysis_id = ?"
        args.append(int(analysis_id))
    sql += " ORDER BY severity_score DESC, id DESC LIMIT ?"
    args.append(limit)

    with get_db() as conn:
        rows = conn.execute(sql, args).fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/incidents/<int:incident_id>")
def update_incident(incident_id):
    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if new_status not in {"Open", "Investigating", "Resolved"}:
        return jsonify({"error": "Status must be Open, Investigating, or Resolved."}), 400
    with get_db() as conn:
        cur = conn.execute("UPDATE incidents SET status = ? WHERE id = ?", (new_status, incident_id))
        if cur.rowcount == 0:
            return jsonify({"error": "Incident not found."}), 404
    return jsonify({"id": incident_id, "status": new_status})


@app.get("/api/monitor/status")
def monitor_status():
    return jsonify(monitor.get_status())


@app.post("/api/monitor/start")
def start_monitor():
    body = request.get_json(silent=True) or {}
    raw_path = str(body.get("path") or os.environ.get("ZEEK_CONN_LOG") or SAMPLE_LOG).strip()
    if not raw_path:
        return jsonify({"error": "Enter a path to a Zeek conn.log file."}), 400
    path = os.path.abspath(os.path.expandvars(os.path.expanduser(raw_path)))
    sample_mode = os.path.normcase(path) == os.path.normcase(os.path.abspath(SAMPLE_LOG))
    try:
        status = monitor.start(path, source_mode="DEMO SAMPLE" if sample_mode else "ZEEK CONN.LOG", start_at_end=not sample_mode)
        return jsonify(status)
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Could not start Zeek log monitor")
        return jsonify({"error": str(exc)}), 500


@app.post("/api/monitor/stop")
def stop_monitor():
    monitor.stop()
    return jsonify(monitor.get_status())


@app.get("/api/live/summary")
def live_summary():
    with get_db() as conn:
        all_rows = conn.execute("""
            SELECT COUNT(*) AS total,
                   COALESCE(SUM(is_alert), 0) AS alerts,
                   COALESCE(SUM(CASE WHEN is_alert = 1 AND severity = 'High' THEN 1 ELSE 0 END), 0) AS high_alerts,
                   COALESCE(SUM(CASE WHEN is_alert = 1 AND alert_status != 'Resolved' THEN 1 ELSE 0 END), 0) AS open_alerts,
                   MAX(ingested_at) AS last_seen
            FROM live_connections
        """).fetchone()
    return jsonify({**dict(all_rows), "monitor": monitor.get_status()})


def _live_limit():
    try:
        return min(max(int(request.args.get("limit", 200)), 1), 1000)
    except (TypeError, ValueError):
        return 200


@app.get("/api/live/connections")
def live_connections():
    limit = _live_limit()
    q = request.args.get("q", "").strip()[:100]
    sql = "SELECT * FROM live_connections WHERE 1=1"
    args = []
    if q:
        sql += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR protocol LIKE ? OR service LIKE ? OR conn_state LIKE ?)"
        args.extend([f"%{q}%"] * 5)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, args).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/live/alerts")
def live_alerts():
    limit = _live_limit()
    status_filter = request.args.get("status", "all")
    sql = "SELECT * FROM live_connections WHERE is_alert = 1"
    args = []
    if status_filter in {"Open", "Investigating", "Resolved"}:
        sql += " AND alert_status = ?"
        args.append(status_filter)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with get_db() as conn:
        rows = conn.execute(sql, args).fetchall()
    return jsonify([dict(row) for row in rows])


@app.get("/api/live/history")
def live_history():
    limit = min(_live_limit(), 500)
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM live_connections ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.patch("/api/live/connections/<int:connection_id>")
def update_live_alert(connection_id):
    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if new_status not in {"Open", "Investigating", "Resolved"}:
        return jsonify({"error": "Status must be Open, Investigating, or Resolved."}), 400
    with get_db() as conn:
        cursor = conn.execute(
            "UPDATE live_connections SET alert_status = ? WHERE id = ? AND is_alert = 1",
            (new_status, connection_id)
        )
        if cursor.rowcount == 0:
            return jsonify({"error": "Alert not found."}), 404
    return jsonify({"id": connection_id, "status": new_status})


@app.get("/api/live/report.csv")
def live_report():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM live_connections WHERE is_alert = 1 ORDER BY id DESC"
        ).fetchall()
    output = io.StringIO()
    pd.DataFrame([dict(row) for row in rows]).to_csv(output, index=False)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv",
        as_attachment=True, download_name="rootnet_live_alerts.csv"
    )


@app.get("/api/analyses/<int:analysis_id>/report.csv")
def download_report(analysis_id):
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM incidents WHERE analysis_id = ? ORDER BY id", (analysis_id,)).fetchall()
    if not rows:
        return jsonify({"error": "No incidents found for that analysis."}), 404
    output = io.StringIO()
    pd.DataFrame([dict(row) for row in rows]).to_csv(output, index=False)
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"rootnet_analysis_{analysis_id}.csv"
    )


if __name__ == "__main__":
    init_db()
    configured_log = os.environ.get("ZEEK_CONN_LOG", "").strip()
    startup_path = configured_log or SAMPLE_LOG
    sample_mode = not configured_log or os.path.normcase(os.path.abspath(startup_path)) == os.path.normcase(os.path.abspath(SAMPLE_LOG))
    try:
        monitor.start(startup_path, source_mode="DEMO SAMPLE" if sample_mode else "ZEEK CONN.LOG", start_at_end=not sample_mode)
        print(f"RootNet monitor started: {startup_path} (polling every {MONITOR_INTERVAL}s)")
    except FileNotFoundError as exc:
        print(f"RootNet monitor did not start: {exc}")
        print("Use the dashboard to choose an existing Zeek conn.log file.")
    # Disable Flask's reloader so it does not create two monitor threads.
    try:
        app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
    finally:
        monitor.stop()
