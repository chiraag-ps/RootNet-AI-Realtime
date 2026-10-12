# RootNet AI Enhanced — Zeek Live Monitor

RootNet AI is an educational network-flow analysis dashboard. It combines a Flask API, a React frontend, SQLite history, CSV-based ML experiments, and an optional live reader for Zeek `conn.log` files.

## New in this version

- Polls a Zeek `conn.log` file every 5 seconds and processes appended records automatically.
- Accepts standard Zeek TSV logs and Zeek JSON-lines logs.
- Stores connection metadata and alert status in SQLite.
- Displays recent connections, anomaly alerts, searchable history and live counters.
- Lets an analyst change alert status to Open, Investigating or Resolved.
- Exports live alerts to CSV.
- Includes a small synthetic Zeek-format log so the UI can be tried before connecting real logs.
- Retains the separate CSV batch analysis feature and its held-out evaluation metrics.

## Important limitations

- **Zeek must be running separately and producing the log file.** RootNet tails the log; it does not capture packets or launch Zeek itself.
- The live detector uses simple, visible heuristics (for example, many destination ports from one source within 60 seconds, repeated failed connection states, a short list of commonly scrutinized ports, or a large one-way transfer). These heuristics create review signals; they are not a trained model, not calibrated probabilities, and not proof that a connection is malicious.
- Zeek connection logs contain metadata, not full packet payloads. RootNet does not block connections.
- The included `sample_data/conn.log` is synthetic test data using documentation-only example IP addresses. It intentionally contains port-scan-like behavior so you can see test alerts.
- A live Zeek flow is **not** fed into the CICIDS2017 batch classifier: the field sets differ. The CSV model and live heuristic detector remain separate to avoid misleading predictions.
- This project is for learning and authorized monitoring. Do not monitor networks without permission.

## Requirements

- Python 3.10+
- Node.js 18+
- A local Zeek `conn.log` file for real monitoring (optional; demo mode works without Zeek installed)

## 1. Start the Flask backend (Windows PowerShell)

Open a terminal in the project root, `RootNet-AI-Enhanced`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

The backend runs at `http://127.0.0.1:5000`. It automatically starts reading `sample_data/conn.log` in demo mode. Keep the terminal open.

If PowerShell blocks activation, you can run the environment's Python directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## 2. Start the React frontend

Open a **second** terminal in VS Code:

```powershell
cd Frontend
npm install
npm run dev
```

Open the URL printed by Vite, usually `http://127.0.0.1:5173`.

Keep both terminals running. The browser dashboard polls the API every 5 seconds; the backend reader separately checks the Zeek log every 5 seconds.

## 3. Connect your real Zeek log

Start Zeek on a machine or sensor that you are authorized to monitor, and confirm that it is writing a connection log named `conn.log`. The file must be accessible from the computer running this Flask backend.

In RootNet's **Connection log monitor** panel:

1. Paste the full path to the real `conn.log` file into **Path to Zeek conn.log**.
2. Click **Start / switch log**.
3. Watch the source mode change from `DEMO SAMPLE` to `ZEEK CONN.LOG`.

Examples of paths (your actual installation can differ):

- Windows: `C:\some\folder\conn.log`
- WSL or Linux: `/opt/zeek/logs/current/conn.log`

If using a WSL/Linux path, make sure the backend can access it. When starting Zeek, choose the correct network interface and follow Zeek's installation/setup instructions for your platform. Zeek often requires elevated capture permissions. Do not point it at a third-party network without authorization.

You can instead set the path before starting Flask. PowerShell example:

```powershell
$env:ZEEK_CONN_LOG = "C:\some\folder\conn.log"
python app.py
```

The included demo file is read from the beginning to seed example connections. For a real `conn.log`, RootNet reads its header and starts at the end of the file so it does not replay old connections; it stores rows appended after monitoring starts. If Zeek has not written a new line yet, the live table will remain unchanged until it does.

## How live alert scores are calculated

Scores are generated with transparent rules:

- A connection state such as `S0` or `REJ` adds points.
- Repeated failed attempts from a source add more points.
- Contacting 8 or more distinct destination ports within 60 seconds adds a strong possible-port-scan signal.
- A small list of commonly scrutinized destination ports adds a modest signal.
- A very large one-way outbound transfer adds points for investigation.

Scores are capped at 100. Scores of 50 or above appear as alerts; 75 or above are marked High. These are project rules chosen for demonstration, not security standards. Tune and evaluate them against traffic from your own lab before drawing conclusions.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/status` | Backend status |
| GET | `/api/monitor/status` | Log reader state and last poll |
| POST | `/api/monitor/start` | Start/switch log; JSON body `{ "path": "C:\\path\\conn.log" }` |
| POST | `/api/monitor/stop` | Stop log reader |
| GET | `/api/live/summary` | Live counters |
| GET | `/api/live/connections?limit=200` | Recent connections |
| GET | `/api/live/alerts?limit=200` | Recent alerts |
| GET | `/api/live/history?limit=100` | Recent connection history |
| PATCH | `/api/live/connections/<id>` | Change alert status |
| GET | `/api/live/report.csv` | Download live alerts |
| POST | `/api/analyze` | Analyze one or more CSV files for batch ML analysis |
| GET | `/api/history` | Batch analysis history |

## Run tests

From the project root with the venv activated:

```powershell
python -m pytest -q
```

## Beginner-friendly interview explanation

1. Zeek writes one line for each network connection it observes.
2. A background Python thread checks the log file every five seconds and parses new rows.
3. RootNet calculates a rule-based anomaly score and stores the connection and alert in SQLite.
4. Flask exposes the records through REST endpoints.
5. React calls the endpoints every five seconds and refreshes the tables and counters.
6. The analyst can search records, update alert status and download a report.

This is polling, not true packet-by-packet real-time capture. New rows appear after Zeek writes them and the next polling cycle runs.
