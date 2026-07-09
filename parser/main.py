import os
import re
import time
from datetime import datetime
from datetime import timezone
from jinja2 import Template

SOURCE_DIRECTORY = os.environ.get("SOURCE_DIRECTORY")
DESTINATION_DIRECTORY = os.environ.get("DESTINATION_DIRECTORY")
ALERT_TEMPLATE = os.environ.get("ALERT_TEMPLATE")

missing = [
    name
    for name, value in {
        "SOURCE_DIRECTORY": SOURCE_DIRECTORY,
        "DESTINATION_DIRECTORY": DESTINATION_DIRECTORY,
        "ALERT_TEMPLATE": ALERT_TEMPLATE,
    }.items()
    if not value
]
if missing:
    raise SystemExit(f"[parser] Missing required environment variables: {', '.join(missing)}")

# Ensure results directory exists
os.makedirs(DESTINATION_DIRECTORY, exist_ok=True)

# Load Jinja2 alert template (defines macros: summary() and detailed())
with open(ALERT_TEMPLATE, "r") as tmpl_file:
    alert_template = Template(tmpl_file.read())

print(f"[parser] Starting parser...")
print(f"[parser] Source: {SOURCE_DIRECTORY}")
print(f"[parser] Destination: {DESTINATION_DIRECTORY}")

# Track processed entries to avoid duplicates
processed_entries = set()
alerts_file = os.path.join(DESTINATION_DIRECTORY, "alerts.log")

# Remove old alerts file on startup (rewrite instead of append)
if os.path.exists(alerts_file):
    print(f"[parser] Removing old alerts file: {alerts_file}")
    os.remove(alerts_file)

def process_line(line):
    """Process a single log line if it matches os=??? and not already processed"""
    entry = line.strip()
    
    if not entry or not re.search("os=\?\?\?", entry, re.IGNORECASE):
        return
    
    # Skip if already processed
    if entry in processed_entries:
        return
    
    processed_entries.add(entry)
    
    # Extract source/destination IPs and ports
    src_ip = dst_ip = src_port = dst_port = "-"
    m = re.search(
        r"cli=(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\|srv=(\d{1,3}(?:\.\d{1,3}){3})/(\d+)",
        entry,
    )
    if m:
        src_ip, src_port, dst_ip, dst_port = m.group(1), m.group(2), m.group(3), m.group(4)
    
    timestamp = datetime.now(timezone.utc).isoformat()
    signature = entry
    
    # Render alert
    alert_message = alert_template.module.summary(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        signature=signature,
    )
    
    # Write alert
    with open(alerts_file, "a") as out_f:
        out_f.write(alert_message + "\n")
    
    print(f"[parser] Alert: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# Phase 1: Process all existing log files from beginning
print("[parser] Phase 1: Processing existing logs...")
for root, dirs, files in os.walk(SOURCE_DIRECTORY):
    for file in files:
        if file.endswith(".log"):
            file_path = os.path.join(root, file)
            print(f"[parser] Reading {file_path}")
            try:
                with open(file_path, "r") as f:
                    for line in f:
                        process_line(line)
            except Exception as e:
                print(f"[parser] Error reading {file_path}: {e}")

print(f"[parser] Phase 1 complete. Processed {len(processed_entries)} unique entries.")

# Phase 2: Poll for new entries in real-time
print("[parser] Phase 2: Monitoring for new entries...")
file_positions = {}

while True:
    # Discover log files
    for root, dirs, files in os.walk(SOURCE_DIRECTORY):
        for file in files:
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
