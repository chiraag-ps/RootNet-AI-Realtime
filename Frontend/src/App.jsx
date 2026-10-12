import React, { useEffect, useMemo, useState } from "react";

const API = "http://127.0.0.1:5000/api";

async function apiJson(url, options = {}) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
  return payload;
}

function Metric({ label, value, note, accent = "" }) {
  return <article className={`metric ${accent}`}>
    <span className="muted">{label}</span>
    <strong>{value ?? "—"}</strong>
    {note && <small>{note}</small>}
  </article>;
}

function fmtBytes(value) {
  const n = Number(value || 0);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

function fmtTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function Severity({ row }) {
  const level = row.severity || (row.anomaly_score >= 75 ? "High" : row.anomaly_score >= 50 ? "Medium" : "Low");
  return <span className={`severity ${String(level).toLowerCase()}`}>{level} · {row.anomaly_score}/100</span>;
}

export default function App() {
  const [apiStatus, setApiStatus] = useState("Connecting to backend…");
  const [monitor, setMonitor] = useState(null);
  const [logPath, setLogPath] = useState("");
  const [liveSummary, setLiveSummary] = useState(null);
  const [connections, setConnections] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [liveHistory, setLiveHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("connections");
  const [search, setSearch] = useState("");
  const [monitorBusy, setMonitorBusy] = useState(false);
  const [error, setError] = useState("");
  const [files, setFiles] = useState([]);
  const [batchBusy, setBatchBusy] = useState(false);
  const [batchResult, setBatchResult] = useState(null);
  const [batchError, setBatchError] = useState("");
  const [batchHistory, setBatchHistory] = useState([]);

  async function refreshLive() {
    try {
      const [status, summary, liveConnections, liveAlerts, history] = await Promise.all([
        apiJson(`${API}/monitor/status`),
        apiJson(`${API}/live/summary`),
        apiJson(`${API}/live/connections?limit=250`),
        apiJson(`${API}/live/alerts?limit=250`),
        apiJson(`${API}/live/history?limit=100`),
      ]);
      setMonitor(status);
      setLiveSummary(summary);
      setConnections(liveConnections);
      setAlerts(liveAlerts);
      setLiveHistory(history);
      setApiStatus("API connected");
      if (status.path && !logPath) setLogPath(status.path);
      return true;
    } catch (e) {
      setApiStatus("Backend offline");
      setError(e.message || "Could not reach the Flask API.");
      return false;
    }
  }

  async function refreshBatchHistory() {
    try {
      setBatchHistory(await apiJson(`${API.replace("/api", "")}/api/history`));
    } catch {
      // Live monitoring can continue even if batch history is unavailable.
    }
  }

  useEffect(() => {
    refreshLive();
    refreshBatchHistory();
    const timer = window.setInterval(() => {
      refreshLive();
      refreshBatchHistory();
    }, 5000);
    return () => window.clearInterval(timer);
    // Initial polling is intentionally mounted once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function startMonitoring(event) {
    event.preventDefault();
    setError("");
    setMonitorBusy(true);
    try {
      const status = await apiJson(`${API}/monitor/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: logPath.trim() }),
      });
      setMonitor(status);
      await refreshLive();
    } catch (e) {
      setError(e.message || "Could not start the monitor.");
    } finally {
      setMonitorBusy(false);
    }
  }

  async function stopMonitoring() {
    setError("");
    setMonitorBusy(true);
    try {
      setMonitor(await apiJson(`${API}/monitor/stop`, { method: "POST" }));
    } catch (e) {
      setError(e.message || "Could not stop the monitor.");
    } finally {
      setMonitorBusy(false);
    }
  }

  async function updateAlert(id, status) {
    try {
      await apiJson(`${API}/live/connections/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      await refreshLive();
    } catch (e) {
      setError(e.message || "Could not update alert status.");
    }
  }

  async function runBatchAnalysis(event) {
    event.preventDefault();
    setBatchError("");
    setBatchResult(null);
    if (!files.length) {
      setBatchError("Choose at least one CSV file first.");
      return;
    }
    const form = new FormData();
    files.forEach(file => form.append("files", file));
    setBatchBusy(true);
    try {
      const result = await apiJson(`${API}/analyze`, { method: "POST", body: form });
      setBatchResult(result);
      await refreshBatchHistory();
    } catch (e) {
      setBatchError(e.message || "Batch analysis failed.");
    } finally {
      setBatchBusy(false);
    }
  }

  const activeRows = useMemo(() => {
    const q = search.trim().toLowerCase();
    const rows = activeTab === "alerts" ? alerts : activeTab === "history" ? liveHistory : connections;
    if (!q) return rows;
    return rows.filter(row => [
      row.src_ip, row.dst_ip, row.protocol, row.service, row.conn_state,
      row.alert_reason, row.uid, row.src_port, row.dst_port,
    ].some(value => String(value ?? "").toLowerCase().includes(q)));
  }, [activeTab, alerts, connections, liveHistory, search]);

  const latest = batchResult?.summary;
  const sourceMode = monitor?.source_mode || "not selected";

  return <main className="shell">
    <header className="topbar">
      <div className="brand"><div className="brand-icon">RN</div><div>
        <h1>RootNet <span>AI</span></h1><p>Explainable network-flow monitoring</p>
      </div></div>
      <div className={`connection ${apiStatus === "API connected" ? "online" : ""}`}><i />{apiStatus}</div>
    </header>

    <section className="hero">
      <div>
        <p className="eyebrow">REAL-TIME SECURITY WORKSPACE</p>
        <h2>Watch network connections.<br/><span>Prioritize what needs a closer look.</span></h2>
        <p className="hero-copy">RootNet reads Zeek connection logs, applies small explainable heuristics, stores connections and alerts, and refreshes this dashboard every five seconds.</p>
      </div>
      <div className="hero-mark">⌁</div>
    </section>

    <section className="panel monitor-panel">
      <div className="panel-heading"><div><p className="eyebrow">01 / DATA SOURCE</p><h3>Connection log monitor</h3></div>
        <span className={`pill ${monitor?.running ? "pill-on" : ""}`}>{monitor?.running ? "Monitoring active" : "Monitoring stopped"}</span>
      </div>
      <form onSubmit={startMonitoring} className="monitor-form">
        <label className="path-field"><span>Path to Zeek conn.log</span><input value={logPath} onChange={e => setLogPath(e.target.value)} placeholder="sample_data/conn.log or full path to conn.log"/></label>
        <div className="monitor-actions"><button className="primary" disabled={monitorBusy}>{monitorBusy ? "Please wait…" : "Start / switch log"}</button><button type="button" className="secondary-btn" onClick={stopMonitoring} disabled={monitorBusy || !monitor?.running}>Stop monitoring</button></div>
      </form>
      <div className="monitor-meta">
        <span><b>Source mode</b> {sourceMode}</span><span><b>Poll interval</b> 5 seconds</span><span><b>Last poll</b> {fmtTime(monitor?.last_poll)}</span><span><b>Log lines read</b> {monitor?.lines_seen ?? 0}</span><span><b>New records stored</b> {monitor?.records_added ?? 0}</span>
      </div>
      {monitor?.last_error && <div className="error">Monitor note: {monitor.last_error}</div>}
      {sourceMode === "DEMO SAMPLE" && <div className="notice"><strong>Demo mode:</strong> This is a synthetic Zeek-format log using documentation IP addresses. To monitor your own authorized environment, paste the absolute path to its live <code>conn.log</code> above and click <b>Start / switch log</b>.</div>}
      {sourceMode === "ZEEK CONN.LOG" && <div className="notice"><strong>Live mode:</strong> RootNet starts at the end of the selected log to avoid replaying old connections. It stores new rows as Zeek appends them.</div>}
      {error && <div className="error">{error}</div>}
    </section>

    <section className="metrics">
      <Metric label="Connections stored" value={liveSummary?.total ?? 0} note="All ingested Zeek flows"/>
      <Metric label="Anomaly alerts" value={liveSummary?.alerts ?? 0} note="Score ≥ 50" accent="warn"/>
      <Metric label="High severity alerts" value={liveSummary?.high_alerts ?? 0} note="Score ≥ 75" accent="danger"/>
      <Metric label="Unresolved alerts" value={liveSummary?.open_alerts ?? 0} note="Open or investigating"/>
    </section>

    <section className="panel">
      <div className="panel-heading main-heading"><div><p className="eyebrow">02 / LIVE FLOW EXPLORER</p><h3>Connections and anomaly alerts</h3></div>
        <a className="secondary-btn" href={`${API}/live/report.csv`}>Export alerts CSV ↓</a>
      </div>
      <div className="table-toolbar">
        <div className="tabs">
          <button className={activeTab === "connections" ? "tab active" : "tab"} onClick={() => setActiveTab("connections")}>Connections ({connections.length})</button>
          <button className={activeTab === "alerts" ? "tab active" : "tab"} onClick={() => setActiveTab("alerts")}>Alerts ({alerts.length})</button>
          <button className={activeTab === "history" ? "tab active" : "tab"} onClick={() => setActiveTab("history")}>Recent history</button>
          <button className={activeTab === "batch" ? "tab active" : "tab"} onClick={() => setActiveTab("batch")}>CSV analysis</button>
        </div>
        {activeTab !== "batch" && <input className="search" aria-label="Search connections" placeholder="Filter IP, port, protocol…" value={search} onChange={e => setSearch(e.target.value)}/>}
      </div>

      {activeTab === "batch" ? <div className="batch-area">
        <form onSubmit={runBatchAnalysis}>
          <label className="dropzone"><span className="upload-icon">↑</span><strong>{files.length ? `${files.length} CSV file(s) selected` : "Choose labelled network-flow CSV files"}</strong><span className="muted">Optional offline analysis is kept separate from Zeek live monitoring.</span><input type="file" accept=".csv,text/csv" multiple onChange={e => setFiles(Array.from(e.target.files || []))}/></label>
          {files.length > 0 && <div className="file-list">{files.map(file => <span className="file-chip" key={`${file.name}-${file.size}`}>{file.name}</span>)}</div>}
          <div className="form-actions"><p className="muted">For labelled datasets, reported metrics are measured on a held-out split.</p><button className="primary" disabled={batchBusy}>{batchBusy ? "Analyzing…" : "Run CSV analysis →"}</button></div>
        </form>
        {batchError && <div className="error">{batchError}</div>}
        {latest && <div className="batch-result"><h4>Analysis #{batchResult.analysis_id}</h4><div className="metrics compact">
          <Metric label="Flows" value={latest.total_flows}/><Metric label="Predicted attacks" value={latest.attacks_detected}/><Metric label="Accuracy" value={latest.accuracy == null ? "N/A" : `${(latest.accuracy * 100).toFixed(1)}%`}/><Metric label="F1-score" value={latest.f1 == null ? "N/A" : `${(latest.f1 * 100).toFixed(1)}%`}/>
        </div><p className="note">{batchResult.metrics_note}</p><a href={`${API}/analyses/${batchResult.analysis_id}/report.csv`} className="secondary-btn">Download batch report ↓</a></div>}
        <div className="batch-history"><h4>Previous CSV analyses</h4>{batchHistory.slice(0, 8).map(item => <div className="history-row" key={item.id}><div><strong>Analysis #{item.id}</strong><p className="muted">{fmtTime(item.created_at)} · {item.filenames?.join(", ")}</p></div><div className="history-stats"><span>{item.total_flows} flows</span><span>{item.attacks_detected} predicted attacks</span><a href={`${API}/analyses/${item.id}/report.csv`}>Report ↓</a></div></div>)}{!batchHistory.length && <p className="muted">No batch analyses yet.</p>}</div>
      </div> : <div className="table-wrap">
        {activeTab === "connections" && <table><thead><tr><th>Event time</th><th>Source</th><th>Destination</th><th>Protocol / service</th><th>State</th><th>Bytes sent / received</th><th>Heuristic score</th></tr></thead><tbody>
          {activeRows.map(row => <tr key={row.id}><td className="time-cell">{fmtTime(row.event_time)}</td><td className="mono">{row.src_ip}:{row.src_port}</td><td className="mono">{row.dst_ip}:{row.dst_port}</td><td>{row.protocol || "—"}<small className="muted block">{row.service || "unknown service"}</small></td><td><span className="state-tag">{row.conn_state}</span></td><td>{fmtBytes(row.orig_bytes)} / {fmtBytes(row.resp_bytes)}</td><td><Severity row={row}/></td></tr>)}
        </tbody></table>}
        {activeTab === "alerts" && <table><thead><tr><th>Detected at</th><th>Severity</th><th>Source → destination</th><th>Reason</th><th>Status</th></tr></thead><tbody>
          {activeRows.map(row => <tr key={row.id}><td className="time-cell">{fmtTime(row.ingested_at)}</td><td><Severity row={row}/></td><td className="mono">{row.src_ip}:{row.src_port}<br/><span className="muted">→ {row.dst_ip}:{row.dst_port}</span></td><td className="reason-cell">{row.alert_reason}</td><td><select className="status-select" value={row.alert_status} onChange={e => updateAlert(row.id, e.target.value)}><option>Open</option><option>Investigating</option><option>Resolved</option></select></td></tr>)}
        </tbody></table>}
        {activeTab === "history" && <table><thead><tr><th>#</th><th>Event time</th><th>Connection</th><th>Protocol</th><th>State</th><th>Bytes</th><th>Result</th></tr></thead><tbody>
          {activeRows.map(row => <tr key={row.id}><td className="mono">{row.id}</td><td className="time-cell">{fmtTime(row.event_time)}</td><td className="mono">{row.src_ip}:{row.src_port}<br/><span className="muted">→ {row.dst_ip}:{row.dst_port}</span></td><td>{row.protocol}</td><td>{row.conn_state}</td><td>{fmtBytes(row.orig_bytes)} / {fmtBytes(row.resp_bytes)}</td><td>{row.is_alert ? <Severity row={row}/> : <span className="normal-tag">No rule triggered</span>}</td></tr>)}
        </tbody></table>}
        {!activeRows.length && <div className="empty">No records match this view yet. Confirm the monitor is running and the selected log contains Zeek connection entries.</div>}
      </div>}
      {activeTab !== "batch" && <p className="table-foot muted">The UI refreshes every 5 seconds. Scores come from simple, explainable heuristics—not a trained model or proof of malicious activity. Display is limited to the newest records.</p>}
    </section>

    <section className="panel explanation-panel"><p className="eyebrow">HOW THE LIVE DETECTOR WORKS</p><h3>Simple rules you can explain</h3><div className="rule-grid">
      <div><strong>Possible port scan</strong><p>A source contacts 8 or more distinct destination ports within a 60-second event-time window.</p></div>
      <div><strong>Failed connection pattern</strong><p>Connection states such as <code>S0</code> or <code>REJ</code> increase the score, especially when repeated.</p></div>
      <div><strong>Review-worthy destination</strong><p>A small configured list of commonly scrutinized ports adds a modest signal; it does not prove compromise.</p></div>
      <div><strong>One-way large transfer</strong><p>A large outbound byte count with almost no reply bytes is flagged for human review.</p></div>
    </div><p className="note">Zeek provides connection metadata from traffic that Zeek can observe. RootNet does not inspect full packet payloads, block traffic, or guarantee attack detection. The demo log is synthetic; real monitoring needs Zeek producing conn.log for a network you are authorized to monitor.</p></section>

    <footer><span>RootNet AI · Educational network-flow monitor</span><span>Flask REST API · React polling · SQLite · Zeek conn.log</span></footer>
  </main>;
}
