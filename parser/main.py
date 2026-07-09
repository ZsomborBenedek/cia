import os
import re
import time
import json
from datetime import datetime
from datetime import timezone


SOURCE_DIRECTORY = os.environ.get("SOURCE_DIRECTORY")
JOBS_DIRECTORY = os.environ.get("JOBS_DIRECTORY")

missing = [
    name
    for name, value in {
        "SOURCE_DIRECTORY": SOURCE_DIRECTORY,
        "JOBS_DIRECTORY": JOBS_DIRECTORY,
    }.items()
    if not value
]
if missing:
    raise SystemExit(f"[parser] Missing required environment variables: {', '.join(missing)}")

# Ensure results directory exists
os.makedirs(JOBS_DIRECTORY, exist_ok=True)

print(f"[parser] Starting parser...")
print(f"[parser] Source: {SOURCE_DIRECTORY}")
print(f"[parser] Jobs: {JOBS_DIRECTORY}")

# Track processed *unknown connections* to avoid duplicate alerts
# Keyed by client IP
processed_unknown_client_ips = set()

 # In-memory connection table
connections = {}

_ts_re = re.compile(r"^\[(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]\s*(?P<rest>.*)$")
_kv_re = re.compile(r"(?P<k>[a-zA-Z_]+)=(?P<v>[^|]+)")
_cli_srv_re = re.compile(
    r"cli=(?P<cli_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<cli_port>\d+)\|srv=(?P<srv_ip>\d{1,3}(?:\.\d{1,3}){3})/(?P<srv_port>\d+)"
)


def parse_p0f_line(line: str) -> dict | None:
    """Parse a single p0f log line into a dict.

    We parse what we can; partial parsing is OK as long as we can split/track connections.
    """
    entry = line.strip()
    if not entry:
        return None

    m_ts = _ts_re.match(entry)
    if not m_ts:
        return None

    ts_str = m_ts.group("ts")
    rest = m_ts.group("rest")

    # Parse timestamp in the log (local time from p0f output). We store ISO string for alerts.
    try:
        ts = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    # Extract cli/srv first (stable connection key)
    m_endpoints = _cli_srv_re.search(rest)
    if not m_endpoints:
        return None

    rec = {
        "timestamp": ts,
        "raw": entry,
        "cli_ip": m_endpoints.group("cli_ip"),
        "cli_port": m_endpoints.group("cli_port"),
        "srv_ip": m_endpoints.group("srv_ip"),
        "srv_port": m_endpoints.group("srv_port"),
    }

    # Parse key=value pairs separated by |
    for m in _kv_re.finditer(rest):
        k = m.group("k")
        v = m.group("v")
        rec[k] = v

    return rec


def conn_key(rec: dict) -> tuple:
    return (rec.get("cli_ip"), rec.get("cli_port"), rec.get("srv_ip"), rec.get("srv_port"))


def merge_record(conn: dict, rec: dict) -> None:
    ts = rec.get("timestamp")
    if ts:
        conn["first_seen"] = min(conn.get("first_seen", ts), ts)
        conn["last_seen"] = max(conn.get("last_seen", ts), ts)

    # Track mods we've seen (syn/mtu/host change/etc.)
    mod = rec.get("mod")
    if mod:
        conn.setdefault("mods_seen", set()).add(mod)

    # Merge fields: prefer real values over placeholders/empties
    for k, v in rec.items():
        if k in ("timestamp", "raw"):
            continue
        if v is None:
            continue
        cur = conn.get(k)
        if cur in (None, "", "-", "???") and v not in (None, "", "-"):
            conn[k] = v
        elif k not in conn:
            conn[k] = v

    # Always keep latest raw line for debugging
    conn["last_raw"] = rec.get("raw")


def _safe_filename(s: str) -> str:
    # conservative filename sanitizer
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def build_connection_id(conn: dict) -> str:
    cli_ip = conn.get("cli_ip", "-")
    cli_port = conn.get("cli_port", "-")
    srv_ip = conn.get("srv_ip", "-")
    srv_port = conn.get("srv_port", "-")
    return f"{cli_ip}:{cli_port}-{srv_ip}:{srv_port}"


def atomic_write_json(path: str, payload: dict) -> None:
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(payload, f, indent=2, sort_keys=True, default=str)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def maybe_emit_unknown_alert(conn: dict) -> None:
    """Step 2: identify unknown OS connections and emit exactly one alert per connection."""
    os_val = conn.get("os")
    if not os_val or os_val.strip() != "???":
        return

    cli_ip = conn.get("cli_ip")
    if not cli_ip:
        return

    # if cli_ip in processed_unknown_client_ips:
    #     return

    # processed_unknown_client_ips.add(cli_ip)

    # Snapshot a JSON-serializable view of the connection
    mods_seen = sorted(list(conn.get("mods_seen", set())))

    conn_id = build_connection_id(conn)
    timestamp = conn.get("last_seen", datetime.now(timezone.utc)).isoformat()

    # Prefer raw_sig if present, otherwise fall back to the last raw line
    signature = conn.get("raw_sig") or conn.get("last_raw") or "-"

    job = {
        "event": "UNKNOWN_OS",
        "dedup_scope": "client_ip",
        "timestamp": timestamp,
        "connection_id": conn_id,
        "cli_ip": conn.get("cli_ip"),
        "cli_port": conn.get("cli_port"),
        "srv_ip": conn.get("srv_ip"),
        "srv_port": conn.get("srv_port"),
        "p0f": {
            # Core p0f fields we commonly use
            "os": conn.get("os"),
            "subj": conn.get("subj"),
            "dist": conn.get("dist"),
            "params": conn.get("params"),
            "raw_sig": conn.get("raw_sig"),
            "signature": signature,
            "link": conn.get("link"),
            "raw_mtu": conn.get("raw_mtu"),
            "mods_seen": mods_seen,
            "first_seen": conn.get("first_seen"),
            "last_seen": conn.get("last_seen"),
            "last_raw": conn.get("last_raw"),
        },
    }

    # Write one JSON job per unknown-OS connection
    # Since we dedup per client IP, name the job per client IP.
    filename = _safe_filename(f"unknown_os_{cli_ip}") + ".json"
    job_path = os.path.join(JOBS_DIRECTORY, filename)

    atomic_write_json(job_path, job)

    print(f"[parser] Wrote job: {job_path}")


def process_line(line: str) -> None:
    """Step 1+2 pipeline for one line: parse -> split/merge connection -> identify unknown."""
    rec = parse_p0f_line(line)
    if not rec:
        return

    key = conn_key(rec)
    conn = connections.get(key)
    if conn is None:
        conn = {
            "cli_ip": rec.get("cli_ip"),
            "cli_port": rec.get("cli_port"),
            "srv_ip": rec.get("srv_ip"),
            "srv_port": rec.get("srv_port"),
            "first_seen": rec.get("timestamp"),
            "last_seen": rec.get("timestamp"),
            "mods_seen": set(),
        }
        connections[key] = conn

    merge_record(conn, rec)
    maybe_emit_unknown_alert(conn)

# Phase 1: Process all existing log files from beginning
print("[parser] Phase 1: Processing existing logs...")
for root, dirs, files in os.walk(SOURCE_DIRECTORY):
    for file in files:
        if file.endswith(".log"):
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        process_line(line)
            except Exception as e:
                print(f"[parser] Error reading {file_path}: {e}")

print(f"[parser] Phase 1 complete. Unknown client IPs jobbed: {len(processed_unknown_client_ips)}")

# Phase 2: Poll for new entries in real-time
print("[parser] Phase 2: Monitoring for new entries...")
file_positions = {}

# Initialize positions to EOF for logs that already exist (Phase 1 handled historical content)
for root, dirs, files in os.walk(SOURCE_DIRECTORY):
    for file in files:
        if file.endswith(".log"):
            file_path = os.path.join(root, file)
            try:
                file_positions[file_path] = os.path.getsize(file_path)
            except OSError:
                file_positions[file_path] = 0

while True:
    # Discover log files
    for root, dirs, files in os.walk(SOURCE_DIRECTORY):
        for file in files:
            print(f"Scanning {file}")
            if file.endswith(".log"):
                file_path = os.path.join(root, file)

                # Initialize position if not tracked
                if file_path not in file_positions:
                    file_positions[file_path] = 0

                try:
                    with open(file_path, "r") as f:
                        current_size = os.path.getsize(file_path)
                        last_pos = file_positions.get(file_path, 0)
                        if last_pos > current_size:
                            last_pos = 0
                            file_positions[file_path] = 0

                        # Seek to last known position
                        f.seek(last_pos)

                        for line in f:
                            process_line(line)

                        # Update position
                        file_positions[file_path] = f.tell()

                except FileNotFoundError:
                    # File was rotated/deleted; reset position
                    file_positions[file_path] = 0

    time.sleep(1)  # Poll every 1 second