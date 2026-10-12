"""Small polling reader for Zeek conn.log (TSV or JSON-lines format).

This reads Zeek's connection metadata logs; it does not capture packets itself.
"""
import json
import os
import threading
import time
from datetime import datetime, timezone

DEFAULT_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]
MAX_LINES_PER_POLL = 2500


def _separator_from_directive(line):
    """Convert Zeek separator directives such as '#separator \\x09'."""
    value = line.strip().split(maxsplit=1)
    if len(value) < 2:
        return "\t"
    encoded = value[1]
    try:
        return bytes(encoded, "utf-8").decode("unicode_escape")
    except Exception:
        return "\t"


def _clean(value):
    if value is None or value == "-" or value == "(empty)":
        return None
    return value


def _as_int(value, default=0):
    value = _clean(value)
    try:
        return int(float(value)) if value is not None else default
    except (TypeError, ValueError, OverflowError):
        return default


def _as_float(value, default=0.0):
    value = _clean(value)
    try:
        result = float(value) if value is not None else default
        return result if result == result and abs(result) != float("inf") else default
    except (TypeError, ValueError, OverflowError):
        return default


def normalize_event_time(value):
    """Return a sortable UTC ISO timestamp for a Zeek epoch or timestamp string."""
    value = _clean(value)
    if value is None:
        return None
    try:
        # Zeek's default conn.log timestamp is Unix epoch seconds.
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat(timespec="milliseconds")
    except (ValueError, TypeError, OverflowError, OSError):
        pass
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except ValueError:
        return None


def parse_zeek_record(line, fields=None, separator="\t"):
    """Parse one data row. Header/directive processing is handled by the reader."""
    line = line.strip("\r\n")
    if not line or line.startswith("#"):
        return None
    if line.lstrip().startswith("{"):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return None
    else:
        active_fields = fields or DEFAULT_FIELDS
        values = line.split(separator)
        if len(values) != len(active_fields):
            # Some Zeek builds may use a tab header while a row has escaped separators;
            # skip malformed lines instead of guessing the field mapping.
            return None
        raw = dict(zip(active_fields, values))

    # JSON logging uses the same default field names; normalize the fields we need.
    return {
        "ts": _clean(raw.get("ts", raw.get("timestamp"))),
        "uid": _clean(raw.get("uid")),
        "src_ip": _clean(raw.get("id.orig_h", raw.get("orig_h", raw.get("src_ip")))),
        "src_port": _as_int(raw.get("id.orig_p", raw.get("orig_p", raw.get("src_port")))),
        "dst_ip": _clean(raw.get("id.resp_h", raw.get("resp_h", raw.get("dst_ip")))),
        "dst_port": _as_int(raw.get("id.resp_p", raw.get("resp_p", raw.get("dst_port")))),
        "protocol": str(_clean(raw.get("proto", raw.get("protocol"))) or "unknown").upper(),
        "service": _clean(raw.get("service")),
        "duration": _as_float(raw.get("duration")),
        "orig_bytes": _as_int(raw.get("orig_bytes")),
        "resp_bytes": _as_int(raw.get("resp_bytes")),
        "conn_state": str(_clean(raw.get("conn_state")) or "unknown").upper(),
        "orig_pkts": _as_int(raw.get("orig_pkts")),
        "resp_pkts": _as_int(raw.get("resp_pkts")),
    }


class ZeekLogMonitor:
    """Tail a Zeek conn.log with a straightforward background thread."""

    def __init__(self, on_record, interval=5):
        self.on_record = on_record
        self.interval = max(1, int(interval))
        self.path = None
        self.source_mode = "unknown"
        self._offset = 0
        self._fields = list(DEFAULT_FIELDS)
        self._separator = "\t"
        self._thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._last_poll = None
        self._last_error = None
        self._lines_seen = 0
        self._records_added = 0

    def start(self, path, source_mode="zeek", start_at_end=False):
        path = os.path.abspath(os.path.expandvars(os.path.expanduser(path)))
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Log file does not exist: {path}")
        self.stop()
        fields = list(DEFAULT_FIELDS)
        separator = "\t"
        offset = 0
        if start_at_end:
            # Real monitoring should watch new events instead of replaying an entire
            # possibly huge log. Read the header first so custom TSV field ordering works.
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as header_file:
                for _ in range(200):
                    header_line = header_file.readline()
                    if not header_line:
                        break
                    header_line = header_line.rstrip("\r\n")
                    if header_line.startswith("#separator"):
                        separator = _separator_from_directive(header_line)
                    elif header_line.startswith("#fields"):
                        split_header = header_line.split(separator)
                        fields = split_header[1:] if len(split_header) > 1 else list(DEFAULT_FIELDS)
                        break
                    elif header_line and not header_line.startswith("#"):
                        break
            offset = os.path.getsize(path)
        with self._lock:
            self.path = path
            self.source_mode = source_mode
            self._offset = offset
            self._fields = fields
            self._separator = separator
            self._last_error = None
            self._last_poll = None
            self._lines_seen = 0
            self._records_added = 0
            self._stop_event = threading.Event()
            self._running = True
            self._thread = threading.Thread(target=self._run, name="rootnet-zeek-tail", daemon=True)
            self._thread.start()
        return self.get_status()

    def stop(self):
        with self._lock:
            thread = self._thread
            if thread and thread.is_alive():
                self._stop_event.set()
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            self._running = False
            self._thread = None

    def get_status(self):
        with self._lock:
            return {
                "running": self._running,
                "path": self.path,
                "source_mode": self.source_mode,
                "interval_seconds": self.interval,
                "last_poll": self._last_poll,
                "last_error": self._last_error,
                "lines_seen": self._lines_seen,
                "records_added": self._records_added,
            }

    def _run(self):
        while not self._stop_event.is_set():
            self._poll_once()
            self._stop_event.wait(self.interval)
        with self._lock:
            self._running = False

    def _poll_once(self):
        path = self.path
        if not path:
            return
        try:
            size = os.path.getsize(path)
            if size < self._offset:  # Handle a truncated/recreated log file.
                self._offset = 0
                self._fields = list(DEFAULT_FIELDS)
                self._separator = "\t"
            rows = 0
            with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
                handle.seek(self._offset)
                while rows < MAX_LINES_PER_POLL and not self._stop_event.is_set():
                    line = handle.readline()
                    if not line:
                        break
                    self._offset = handle.tell()
                    rows += 1
                    self._lines_seen += 1
                    stripped = line.rstrip("\r\n")
                    if stripped.startswith("#separator"):
                        self._separator = _separator_from_directive(stripped)
                        continue
                    if stripped.startswith("#fields"):
                        header = stripped.split(self._separator)
                        self._fields = header[1:] if len(header) > 1 else list(DEFAULT_FIELDS)
                        continue
                    if stripped.startswith("#") or not stripped:
                        continue
                    record = parse_zeek_record(stripped, self._fields, self._separator)
                    if record is None or not record.get("src_ip") or not record.get("dst_ip"):
                        continue
                    try:
                        inserted = self.on_record(record, path)
                        if inserted:
                            self._records_added += 1
                    except Exception as exc:  # Keep monitoring even if one line is malformed.
                        with self._lock:
                            self._last_error = f"Could not process one record: {exc}"
            with self._lock:
                self._last_poll = datetime.now(timezone.utc).isoformat(timespec="seconds")
                if rows or not self._last_error:
                    self._last_error = None
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
                self._last_poll = datetime.now(timezone.utc).isoformat(timespec="seconds")
