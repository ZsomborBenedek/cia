import os
import re
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from collections import deque
from datetime import datetime, timedelta

ALERTS_FILE = os.environ.get("ALERTS_FILE", "/app/alerts/alerts.log")
MAIL_SERVER = os.environ.get("MAIL_SERVER", "mail.os3.nl")
MAIL_PORT = int(os.environ.get("MAIL_PORT", 25))
MAIL_FROM = os.environ.get("MAIL_FROM", "p0f@cia.local")
# Parse comma-separated recipients
MAIL_TO = [addr.strip() for addr in os.environ.get("MAIL_TO", "zbenedek@os3.nl").split(",")]
SCAN_INTERVAL = int(os.environ.get("SCAN_INTERVAL", 10))
MAX_EMAILS_PER_MINUTE = int(os.environ.get("MAX_EMAILS_PER_MINUTE", 3))

# Track sent alerts by their signature (hash of the alert line)
sent_alerts_file = Path("/app/state/sent_alerts.txt")
sent_alerts_file.parent.mkdir(parents=True, exist_ok=True)

# Track email send times for rate limiting (last N timestamps)
email_send_times = deque(maxlen=MAX_EMAILS_PER_MINUTE)

def load_sent_alerts():
    """Load list of already-sent alert hashes"""
    if sent_alerts_file.exists():
        with open(sent_alerts_file, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_sent_alert(alert_hash):
    """Record that an alert has been sent"""
    with open(sent_alerts_file, "a") as f:
        f.write(alert_hash + "\n")

def alert_hash(line):
    """Create a hash of alert line to track if already sent"""
    return str(hash(line.strip()))

def can_send_email():
    """Check if we can send an email (rate limiting)"""
    now = datetime.now()
    
    # Remove timestamps older than 1 minute
    while email_send_times and (now - email_send_times[0]) > timedelta(minutes=1):
        email_send_times.popleft()
    
    # If we've sent less than MAX_EMAILS_PER_MINUTE in the last minute, we can send
    if len(email_send_times) < MAX_EMAILS_PER_MINUTE:
        return True
    
    return False

def record_email_sent():
    """Record that an email was sent"""
    email_send_times.append(datetime.now())

def send_email(subject, body):
    """Send email via SMTP to all recipients"""
    try:
        msg = MIMEMultipart()
        msg["From"] = MAIL_FROM
        msg["To"] = ", ".join(MAIL_TO)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        
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

def monitor_alerts():
    """Monitor alerts.log and send mail for new alerts"""
    sent_alerts = load_sent_alerts()
    last_position = 0
    
    print(f"[mail] Starting mail notifier")
    print(f"[mail] Alerts file: {ALERTS_FILE}")
    print(f"[mail] Mail server: {MAIL_SERVER}:{MAIL_PORT}")
    print(f"[mail] From: {MAIL_FROM}")
    print(f"[mail] To: {', '.join(MAIL_TO)}")
    print(f"[mail] Rate limit: {MAX_EMAILS_PER_MINUTE} emails per minute")
    
    while True:
        try:
            if not Path(ALERTS_FILE).exists():
                time.sleep(SCAN_INTERVAL)
                continue
            
            with open(ALERTS_FILE, "r") as f:
                f.seek(last_position)
                lines = f.readlines()
                last_position = f.tell()
            
            for line in lines:
                if not line.strip():
                    continue
                
                line_hash = alert_hash(line)
                
                if line_hash in sent_alerts:
                    continue
                
                # Check rate limit
                if not can_send_email():
                    print(f"[mail] Rate limit reached ({MAX_EMAILS_PER_MINUTE}/min). Queuing alert...")
                    continue
                
                # Extract alert details
                match = re.search(r"SRC=(\S+)\s+DST=(\S+)\s+SPORT=(\S+)\s+DPORT=(\S+)", line)
                if match:
                    src_ip, dst_ip, src_port, dst_port = match.groups()
                    subject = f"[P0F ALERT] Unknown OS: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    body = line.strip()
                    
                    if send_email(subject, body):
                        sent_alerts.add(line_hash)
                        save_sent_alert(line_hash)
                        print(f"[mail] Alert recorded as sent ({len(email_send_times)}/{MAX_EMAILS_PER_MINUTE} this minute)")
                    else:
                        print(f"[mail] Failed to send, will retry")
            
            time.sleep(SCAN_INTERVAL)
        
        except Exception as e:
            print(f"[mail] ERROR in monitor loop: {e}")
            time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    monitor_alerts()