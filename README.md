# Hybrid OS Fingerprinting & Spoof Detection

*OS3 — CIA (Classical Internet Applications) course project*

A monitoring pipeline that combines **passive** OS fingerprinting ([p0f](https://lcamtuf.coredump.cx/p0f3/)) with **active** fingerprinting ([Nmap](https://nmap.org/) `-O`) to identify the operating system behind incoming connections — and to flag hosts that p0f cannot classify or that appear to be **spoofing** their TCP/IP stack.

The core idea: p0f watches traffic silently and cheaply, but it fails on unknown or forged signatures. Whenever p0f reports an unknown OS (`os=???`), the pipeline raises an alert and queues an active Nmap scan of that host. The passive and active results are then correlated and scored against ground truth.

## Pipeline

```
                 ┌──────────────┐
   live traffic  │ p0f (passive)│──► p0f_logs/*.log ──┐
  ──────────────►│  + tcpdump   │──► raw_logs/*.pcap  │
   (per-host     └──────────────┘                     │
    BPF filters)                                      ▼
                                              ┌────────────────┐
                                              │     parser     │  detects UNKNOWN_OS,
                                              │                │  writes alerts + jobs
                                              └───────┬────────┘
                                                      │ scan job (unknown / spoofed host)
                                                      ▼
                                              ┌────────────────┐
                                              │  nmap runner   │  active Nmap -O scan
                                              │ (active_scan)  │  → scan JSON + email
                                              └───────┬────────┘
                                                      │
                                                      ▼
                                          correlate p0f + Nmap, then
                                          score vs. ground truth (plotting/)
```

1. **Passive capture** — `docker-compose.yml` runs one `p0f` container per host of interest, each with its own BPF filter, plus a matching `tcpdump` container that records the same traffic to a `.pcap` for later analysis.
2. **Parsing & alerting** — the parser tails the p0f logs, extracts per-connection signatures, and emits an alert + a scan job whenever p0f cannot identify the OS (`os=???`).
3. **Active scanning** — the Nmap runner picks up queued jobs and runs OS detection against the target, producing a structured result and an email notification.
4. **Correlation & evaluation** — passive and active guesses are merged per host and compared against `plotting/ground_truth.csv` to measure how much active scanning improves accuracy over passive-only.

## Repository layout

| Path | Purpose |
|------|---------|
| `docker-compose.yml` | Passive monitoring stack: per-host `p0f` + `tcpdump` capture containers |
| `parser/` | Parses p0f logs, detects unknown-OS events, produces alerts and scan jobs |
| `nmap_runner/` | Job queue (`jobs/{todo,inflight,done,outbox}`) and email outbox for active scans |
| `nmap/` | `active_scan.sh` — repeated Nmap `-O` runs |
| `results/` | Pipeline output: `scans/` (job states) and `emailbox/` (alert emails) |
| `p0f_logs/` | Passive fingerprint logs written at runtime, one per monitored host |
| `raw_logs/` | Raw packet captures (`.pcap`) mirroring the p0f filters, written at runtime |
| `plotting/` | Ground truth, combined results (`combined.csv`) and evaluation plots |
| `postfix/` | Mail delivery configuration for alert emails |

## Configuration

Copy the example environment file and set the interface and per-host filters:

```bash
cp .example.env .env
```

```dotenv
# Capture interface
P0F_INTERFACE=eth0

HOST_UID=1000
HOST_GID=1000

# One BPF filter per monitored host
WINDOWS_FILTER="host x.x.x.x and tcp"
LINUX_FILTER="host x.x.x.x and not port 22"
IOT_FILTER="host x.x.x.x and port 22"
OTHER_FILTER="host x.x.x.x and (tcp or icmp)"
SPOOFED_FILTER="host x.x.x.x and port 80"
```

Each filter isolates the traffic of a single host so its passive fingerprint lands in a dedicated log.

## Running

**1. Start passive monitoring** (p0f + tcpdump, requires `NET_ADMIN`/`NET_RAW`):

```bash
docker compose up -d
# logs appear in p0f_logs/, captures in raw_logs/
```

**2. Run the parser** to turn p0f logs into alerts and scan jobs. It reads from `p0f_logs/` and writes alerts and scan jobs into `results/`.

**3. Trigger an active scan** against an unknown or suspected-spoofed host:

```bash
sudo ./nmap/active_scan.sh <target-ip> <iterations> <output-file>
# e.g. sudo ./nmap/active_scan.sh 192.168.1.100 5 nmap/active_logs/host.log
```

> Nmap OS detection (`-O`) requires root.

**4. Correlate and evaluate** — combine the passive/active guesses and compare against ground truth. The current results live in `plotting/combined.csv` and the generated charts (`confusion_matrices.png`, `improvement.png`, `automated_*.png`).

## Results

`plotting/combined.csv` records, per host, the real OS, the passive (p0f) guess, the active (Nmap) guess, the correlated verdict, and accuracy scores. Spoofed hosts are the interesting cases: p0f reports `???`, while the active scan recovers a plausible OS family — showing where active fingerprinting adds value over passive-only monitoring.

## Notes

- Only scan hosts you are authorized to scan.
