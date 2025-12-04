import os
import re
from datetime import datetime
from jinja2 import Template

SOURCE_DIRECTORY = os.environ.get("SOURCE_DIRECTORY")
DESTINATION_DIRECTORY = os.environ.get("DESTINATION_DIRECTORY")
ALERT_TEMPLATE = os.environ.get("ALERT_TEMPLATE")

# Ensure results directory exists
os.makedirs(DESTINATION_DIRECTORY, exist_ok=True)

# Load Jinja2 alert template (defines macros: summary() and detailed())
with open(ALERT_TEMPLATE, "r") as tmpl_file:
    alert_template = Template(tmpl_file.read())


for root, dirs, files in os.walk(SOURCE_DIRECTORY):
    for file in files:
        if file.endswith(".log"):
            file_path = os.path.join(root, file)
            with open(file_path, "r") as f:
                entries = f.readlines()

                for entry in entries:
                    entry = entry.strip()

                    if re.search("os=\?\?\?", entry, re.IGNORECASE):

                        # Try to extract source/destination IPs and ports from the p0f entry
                        src_ip = dst_ip = src_port = dst_port = "-"
                        m = re.search(
                            r"cli=(\d{1,3}(?:\.\d{1,3}){3})/(\d+)\|srv=(\d{1,3}(?:\.\d{1,3}){3})/(\d+)",
                            entry,
                        )
                        if m:
                            src_ip, src_port, dst_ip, dst_port = m.group(1), m.group(2), m.group(3), m.group(4)

                        timestamp = datetime.utcnow().isoformat()

                        # Use the entire entry as the raw signature string
                        signature = entry

                        # Render the summary alert using the Jinja2 macro defined in alert.tmpl
                        alert_message = alert_template.module.summary(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            signature=signature,
                        )

                        with open(os.path.join(DESTINATION_DIRECTORY, "alerts.log"), "a") as out_f:
                            out_f.write(alert_message + "\n")
