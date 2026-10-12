from pathlib import Path
from zeek_monitor import DEFAULT_FIELDS, _separator_from_directive, normalize_event_time, parse_zeek_record


def test_zeek_tsv_row_is_parsed():
    separator = _separator_from_directive(r"#separator \x09")
    assert separator == "\t"
    sample = "1791849600.0\tC_test\t192.0.2.1\t50000\t198.51.100.2\t443\ttcp\tssl\t0.5\t100\t200\tSF\tF\tF\t0\tShADadFf\t2\t180\t3\t320\t(empty)"
    row = parse_zeek_record(sample, DEFAULT_FIELDS, separator)
    assert row["src_ip"] == "192.0.2.1"
    assert row["dst_port"] == 443
    assert row["conn_state"] == "SF"
    assert row["orig_bytes"] == 100


def test_json_zeek_row_is_parsed():
    row = parse_zeek_record('{"ts": 1791849600.0, "uid": "C_test", "id.orig_h": "192.0.2.4", "id.orig_p": 1234, "id.resp_h": "198.51.100.4", "id.resp_p": 80, "proto": "tcp", "conn_state": "SF"}')
    assert row["src_ip"] == "192.0.2.4"
    assert row["dst_port"] == 80
    assert row["protocol"] == "TCP"


def test_event_timestamp_is_normalized():
    result = normalize_event_time("1791849600.0")
    assert result is not None
    assert result.endswith("+00:00")


def test_included_demo_log_has_connection_rows():
    log_path = Path(__file__).resolve().parents[1] / "sample_data" / "conn.log"
    assert log_path.exists()
    rows = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
    assert len(rows) >= 8
