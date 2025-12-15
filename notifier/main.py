import os
import time
import smtplib
import hashlib
from pathlib import Path
from collections import deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

MAIL_SERVER = os.environ.get("MAIL_SERVER", "mail.os3.nl")
MAIL_PORT = int(os.environ.get("MAIL_PORT", 25))
MAIL_FROM = os.environ.get("MAIL_FROM", "p0f@cia.local")
MAIL_TO = [addr.strip() for addr in os.environ.get("MAIL_TO", "admin@os3.nl").split(",")]

SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 10))
MAX_EMAILS_PER_MINUTE = int(os.environ.get("MAX_EMAILS_PER_MINUTE", 3))

# Folder that contains one email per file (produced by nmap_runner)
EMAILBOX_DIRECTORY = Path(os.environ.get("EMAILBOX_DIRECTORY", "/app/emailbox"))

# Subfolders for safe processing
INFLIGHT_DIR = EMAILBOX_DIRECTORY / "inflight"
SENT_DIR = EMAILBOX_DIRECTORY / "sent"
FAILED_DIR = EMAILBOX_DIRECTORY / "failed"

# Persistent state to avoid duplicates across restarts
sent_ids_file = Path(os.environ.get("SENT_IDS_FILE", "/app/state/sent_ids.txt"))
sent_ids_file.parent.mkdir(parents=True, exist_ok=True)

# Rate limiting timestamps
email_send_times = deque(maxlen=MAX_EMAILS_PER_MINUTE)


def ensure_dirs() -> None:
    EMAILBOX_DIRECTORY.mkdir(parents=True, exist_ok=True)
    INFLIGHT_DIR.mkdir(parents=True, exist_ok=True)
    SENT_DIR.mkdir(parents=True, exist_ok=True)
    FAILED_DIR.mkdir(parents=True, exist_ok=True)


def load_sent_ids() -> set[str]:
    if sent_ids_file.exists():
        with sent_ids_file.open("r") as f:
            return {line.strip() for line in f if line.strip()}
    return set()


def save_sent_id(sent_id: str) -> None:
    with sent_ids_file.open("a") as f:
        f.write(sent_id + "\n")


def can_send_email() -> bool:
    now = datetime.now()
    while email_send_times and (now - email_send_times[0]) > timedelta(minutes=1):
        email_send_times.popleft()
    return len(email_send_times) < MAX_EMAILS_PER_MINUTE


def record_email_sent() -> None:
    email_send_times.append(datetime.now())


def file_id(path: Path) -> str:
    """
    Deterministic ID based on file contents.
    This makes dedup robust even if the same message is re-written.
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_subject(body: str) -> str:
    """
    Use the first non-empty line as subject; fallback to a generic one.
    Your template starts with: [timestamp] Unknown OS traffic detected...
    """
    for line in body.splitlines():
        line = line.strip()
        if line:
            # keep subject reasonable length
            return line[:200]
    return "[CIA] Unknown OS traffic detected"


def send_email(subject: str, body: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"] = MAIL_FROM
        msg["To"] = ", ".join(MAIL_TO)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        print(f"[mail] Connecting to {MAIL_SERVER}:{MAIL_PORT}...")
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=10)
        server.sendmail(MAIL_FROM, MAIL_TO, msg.as_string())
        server.quit()

        print(f"[mail] Email sent to {', '.join(MAIL_TO)}: {subject}")
        record_email_sent()
        return True
    except Exception as e:
        print(f"[mail] ERROR sending email: {e}")
        return False


def claim_file(p: Path) -> Path | None:
    """
    Atomically claim a job file by moving it to inflight.
    If another notifier instance grabbed it, this will fail.
    """
    inflight = INFLIGHT_DIR / p.name
    try:
        p.replace(inflight)
        return inflight
    except FileNotFoundError:
        return None
    except Exception:
        return None


def process_one_file(path_inflight: Path, sent_ids: set[str]) -> None:
    # compute ID after claim (file is stable now)
    try:
        sid = file_id(path_inflight)
    except Exception as e:
        print(f"[mail] ERROR hashing {path_inflight.name}: {e}")
        # move to failed so we don't loop forever
        path_inflight.replace(FAILED_DIR / path_inflight.name)
        return

    if sid in sent_ids:
        # already sent previously (restart scenario)
        print(f"[mail] Already sent (dedup): {path_inflight.name}")
        path_inflight.replace(SENT_DIR / path_inflight.name)
        return

    try:
        body = path_inflight.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[mail] ERROR reading {path_inflight.name}: {e}")
        path_inflight.replace(FAILED_DIR / path_inflight.name)
        return

    subject = extract_subject(body)

    if not can_send_email():
        print(f"[mail] Rate limit reached ({MAX_EMAILS_PER_MINUTE}/min). Keeping inflight for retry...")
        # Put it back to todo by moving it back (so it will retry next loop)
        path_inflight.replace(EMAILBOX_DIRECTORY / path_inflight.name)
        return

    if send_email(subject, body):
        sent_ids.add(sid)
        save_sent_id(sid)
        path_inflight.replace(SENT_DIR / path_inflight.name)
    else:
        print("[mail] Send failed; will retry later.")
        path_inflight.replace(EMAILBOX_DIRECTORY / path_inflight.name)


def monitor_emailbox() -> None:
    ensure_dirs()
    sent_ids = load_sent_ids()

    print("[mail] Starting mail notifier (per-file mode)")
    print(f"[mail] Emailbox: {EMAILBOX_DIRECTORY}")
    print(f"[mail] Mail server: {MAIL_SERVER}:{MAIL_PORT}")
    print(f"[mail] From: {MAIL_FROM}")
    print(f"[mail] To: {', '.join(MAIL_TO)}")
    print(f"[mail] Rate limit: {MAX_EMAILS_PER_MINUTE} emails per minute")

    while True:
        try:
            # Process only plain text email files produced by nmap_runner
            files = sorted(EMAILBOX_DIRECTORY.glob("*.email.txt"), key=lambda p: p.stat().st_mtime)

            if not files:
                time.sleep(SCAN_INTERVAL)
                continue

            for p in files:
                inflight = claim_file(p)
                if not inflight:
                    continue
                process_one_file(inflight, sent_ids)

            time.sleep(SCAN_INTERVAL)

        except Exception as e:
            print(f"[mail] ERROR in monitor loop: {e}")
            time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    monitor_emailbox()