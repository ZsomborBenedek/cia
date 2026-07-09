#!/usr/bin/env python3

"""nmap_runner.py

Consumes UNKNOWN_OS job files produced by the p0f parser, enriches them with an active
Nmap OS guess, renders an email using a Jinja2 template, and writes it to an emailbox directory.

Directories (env vars):
- JOBS_DIRECTORY: where the parser writes job JSON files (default: ./jobs)
- EMAILBOX_DIRECTORY: where rendered email files are written (default: ./emailbox)
- EMAIL_TEMPLATE_PATH: Jinja2 template used to render the email (default: ./email.tmpl)
- INFLIGHT_DIRECTORY: internal folder used to claim jobs atomically (default: ./jobs_inflight)
- DONE_DIRECTORY: where processed job files are moved (default: ./jobs_done)

Usage:
  main.py                 # continuously watch and process jobs
  main.py --once          # process current jobs and exit

Notes:
- Requires local `nmap` installed and accessible in PATH
- Runs OS detection using: -O --osscan-guess
- Uses atomic rename to claim jobs so multiple consumers won't double-process
"""

from __future__ import annotations

import json
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone

import shutil
import subprocess
import xml.etree.ElementTree as ET
from jinja2 import Template

DEFAULT_NMAP_ARGS: list[str] = [
    "-O",
    "--osscan-guess",
    "-Pn",
    "-n",
    "-sS",
    "--top-ports",
    "300",
    "--max-retries",
    "2",
    "--host-timeout",
    "180s",
    "-oX",
    "-",
]

JOBS_DIRECTORY = Path(os.environ.get("JOBS_DIRECTORY", "./jobs/todo"))
INFLIGHT_DIRECTORY = Path(os.environ.get("INFLIGHT_DIRECTORY", "./jobs/inflight"))
DONE_DIRECTORY = Path(os.environ.get("DONE_DIRECTORY", "./jobs/done"))

# Rendered email files are written here for the email-sender service to consume
EMAILBOX_DIRECTORY = Path(os.environ.get("EMAILBOX_DIRECTORY", "./emailbox"))

# Jinja2 template file used to render the email contents
EMAIL_TEMPLATE_PATH = Path(os.environ.get("EMAIL_TEMPLATE_PATH", "./email.tmpl"))

POLL_INTERVAL_S = float(os.environ.get("POLL_INTERVAL_S", "5"))


def ensure_dirs() -> None:
    for d in [JOBS_DIRECTORY,INFLIGHT_DIRECTORY, DONE_DIRECTORY, EMAILBOX_DIRECTORY]:
        d.mkdir(parents=True, exist_ok=True)


def safe_filename(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ".-_/" else "_" for ch in s).replace("/", "_")


def load_job(path: Path) -> dict:
    with path.open("r") as f:
        return json.load(f)


def load_email_template() -> Template:
    with open(EMAIL_TEMPLATE_PATH, "r") as f:
        return Template(f.read())


def render_email(tmpl: Template, *, job: dict, nmap: dict) -> str:
    p0f = job.get("p0f", {}) or {}

    ctx = {
        # Template expects this
        "timestamp": job.get("timestamp") or datetime.now(timezone.utc).isoformat(),

        # Connection fields (template names)
        "src_ip": job.get("cli_ip"),
        "src_port": job.get("cli_port"),
        "dst_ip": job.get("srv_ip"),
        "dst_port": job.get("srv_port"),

        # p0f fields (template names)
        "subj": p0f.get("subj"),
        "dist": p0f.get("dist"),
        "params": p0f.get("params"),
        "link": p0f.get("link"),
        "raw_mtu": p0f.get("raw_mtu"),
        "mods_seen": p0f.get("mods_seen"),

        # Signature line used by template
        "p0f_signature": p0f.get("signature") or p0f.get("raw_sig") or "-",

        # nmap fields (template names)
        "nmap_os_name": nmap.get("os_name"),
        "nmap_accuracy": nmap.get("accuracy"),
        "nmap_raw": nmap.get("raw_xml") or nmap.get("raw") or "-",
    }

    return tmpl.render(**ctx)


def run_nmap_local(ip: str, args: list[str] | None = None) -> str:
    """Run local nmap and return stdout.

    Raises RuntimeError if nmap is missing or returns a non-zero exit code.
    """
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        raise RuntimeError("nmap binary not found in PATH")

    args_to_use = args if args is not None else DEFAULT_NMAP_ARGS

    # Compose command. We always append the target IP last.
    cmd = [nmap_path] + list(args_to_use) + [ip]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode != 0:
        # Nmap prints useful info to stderr; include it for debugging.
        raise RuntimeError(
            "nmap failed with exit code "
            f"{proc.returncode}: {proc.stderr.strip() or '(no stderr)'}"
        )

    return proc.stdout


def extract_os_guess_from_xml(xml_text: str) -> dict[str, object | None]:
    """Parse Nmap XML output and return the best osmatch."""
    try:
        root = ET.fromstring(xml_text)
    except Exception as e:
        return {"os_name": None, "accuracy": None, "raw_xml": xml_text, "error": str(e)}

    best_name = None
    best_acc: int | None = None

    # Iterate hosts -> os -> osmatch
    for host in root.findall("host"):
        os_el = host.find("os")
        if os_el is None:
            continue
        for m in os_el.findall("osmatch"):
            name = m.get("name")
            try:
                acc = int(m.get("accuracy", "0"))
            except Exception:
                acc = 0

            if best_acc is None or acc > best_acc:
                best_name = name
                best_acc = acc

    return {"os_name": best_name, "accuracy": best_acc, "raw_xml": xml_text}


def process_job_file(job_path: Path) -> None:
    """Claim a job, run nmap, and write enriched output."""

    # Claim the job by moving it into INFLIGHT_DIRECTORY (atomic on same filesystem)
    print(f"Starting job {job_path}")
    inflight_path = INFLIGHT_DIRECTORY / job_path.name
    try:
        job_path.replace(inflight_path)
    except FileNotFoundError:
        return
    except Exception:
        # If we cannot claim it, skip (another worker may have it)
        return

    job = load_job(inflight_path)

    cli_ip = job.get("cli_ip") or (job.get("p0f") or {}).get("cli_ip")
    if not cli_ip:
        # Bad job; move to done to avoid infinite retries
        print(f"Bad job: {job}")
        inflight_path.replace(DONE_DIRECTORY / inflight_path.name)
        return

    # Run nmap and parse OS guess
    nmap_error = None
    try:
        xml_out = run_nmap_local(cli_ip)
        guess = extract_os_guess_from_xml(xml_out)
    except Exception as e:
        guess = {"os_name": None, "accuracy": None, "raw_xml": None}
        nmap_error = str(e)
        print(e)

    # Optional: avoid gigantic emails
    raw_xml = guess.get("raw_xml")
    if isinstance(raw_xml, str) and len(raw_xml) > 8000:
        raw_xml = raw_xml[:8000] + "\n... (truncated) ...\n"

    nmap_ctx = {
        "target": cli_ip,
        "os_name": guess.get("os_name"),
        "accuracy": guess.get("accuracy"),
        "error": nmap_error,
        "raw_xml": raw_xml,
    }

    tmpl = load_email_template()
    email_body = render_email(tmpl, job=job, nmap=nmap_ctx)

    base = job.get("connection_id") or f"unknown_os_{cli_ip}"
    email_name = safe_filename(base) + ".email.txt"
    email_path = EMAILBOX_DIRECTORY / email_name

    tmp = email_path.with_suffix(email_path.suffix + ".tmp")
    with tmp.open("w") as f:
        f.write(email_body)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(email_path)

    # Move job to DONE_DIRECTORY
    inflight_path.replace(DONE_DIRECTORY / inflight_path.name)


def main(argv: list[str]) -> int:
    ensure_dirs()

    once = "--once" in argv[1:]

    def scan_once() -> None:
        print(f"Scanning {JOBS_DIRECTORY} for jobs...")
        for job_path in sorted(JOBS_DIRECTORY.glob("*.json")):
            process_job_file(job_path)

    if once:
        scan_once()
        return 0

    # Watch loop
    while True:
        scan_once()
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
