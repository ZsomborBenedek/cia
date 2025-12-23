# Bulk Analysis with Single Comprehensive Confusion Matrix

This script analyzes multiple IPs at once and creates a single large confusion matrix showing all OS classes.

## Setup

```bash
pip install -r requirements_correlate.txt
```

## Usage

### 1. Create a CSV file with IP addresses and ground truth

**Format:** `ip,true_os`

Example: `ground_truth.csv`
```csv
145.100.104.117,Ubuntu Linux
192.168.1.1,MikroTik RouterOS
10.0.0.5,Windows Server
172.16.0.10,OpenWrt
```

### 2. Run the analysis

```bash
python correlate_bulk_analysis.py --csv ground_truth.csv
```

### 3. Optional: Save the output plot

```bash
python correlate_bulk_analysis.py --csv ground_truth.csv --output confusion_matrix.png
```

### 4. Optional: Show individual p0f and nmap matrices too

```bash
python correlate_bulk_analysis.py --csv ground_truth.csv --individual
```

## Command-line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--csv` | Yes | CSV file with IPs and ground truth (format: `ip,true_os`) |
| `--p0f-dir` | No | Directory containing p0f logs (default: `p0f_logs`) |
| `--nmap-dir` | No | Directory containing nmap logs (default: `nmap`) |
| `--output` | No | Output file path for confusion matrix plot (optional) |
| `--individual` | No | Also show individual p0f and nmap matrices (flag, default: false) |

## Output

### Console Output

Detailed results including:
- Total samples analyzed
- Accuracy for p0f, nmap, and combined predictions
- Improvement from combining methods
- Detailed table showing each IP and predictions from all methods
- ✓/✗ markers indicating correct/incorrect predictions

Example:
```
======================================================================
BULK ANALYSIS SUMMARY
======================================================================

Total samples analyzed: 4

p0f accuracy:      75.00% (3/4)
nmap accuracy:     75.00% (3/4)
Combined accuracy: 100.00% (4/4)

Improvement from combining: +25.00%

----------------------------------------------------------------------
DETAILED RESULTS
----------------------------------------------------------------------
IP              True OS         p0f             nmap            Combined       
----------------------------------------------------------------------
10.0.0.5        Windows         Linux           Windows         Windows        ✓
145.100.104.117 Linux           Linux           Linux           Linux          ✓
172.16.0.10     Linux           Linux           Linux           Linux          ✓
192.168.1.1     MikroTik        MikroTik        Linux           MikroTik       ✓
======================================================================
```

### Visual Output

**Single Comprehensive Confusion Matrix:**
- Shows all OS classes on one plot
- Heat map indicates prediction frequency
- Accuracy percentage displayed in title
- Saved to file if `--output` specified

**Optional Individual Matrices:**
- Left: p0f predictions only
- Right: nmap predictions only
- Shows side-by-side comparison

## Example Workflow

```bash
# Create CSV with your test cases
cat > test_ips.csv << EOF
145.100.104.117,Linux
192.168.1.1,MikroTik
10.0.0.5,Windows
EOF

# Run analysis
python correlate_bulk_analysis.py --csv test_ips.csv --output results.png

# Show individual tool comparison too
python correlate_bulk_analysis.py --csv test_ips.csv --individual --output combined.png
```

## CSV File Format

The CSV file should contain:
- **IP address** in the first column
- **Ground truth OS** in the second column
- Blank lines and lines starting with `#` are ignored

Example with comments:
```csv
# Test network A
145.100.104.117,Ubuntu Linux
145.100.104.118,Debian Linux

# Test network B
192.168.1.1,MikroTik RouterOS
192.168.1.2,MikroTik RouterOS

# Mixed devices
10.0.0.5,Windows Server
10.0.0.10,OpenWrt
```

## Key Differences from Single-IP Script

| Feature | Single IP | Bulk Analysis |
|---------|-----------|---------------|
| Input | Command-line arguments | CSV file |
| Output | 3 side-by-side matrices | 1 large matrix |
| OS classes shown | Only classes for that IP | All classes from all IPs |
| Accuracy calculation | Single prediction | Aggregate across all IPs |
| Improvement metric | Raw percentage | Overall improvement |

## Performance

- Parsing all logs: ~1-2 seconds
- Analysis of 100 IPs: ~1 second
- Visualization: ~2 seconds
- Total for typical workflow: ~5 seconds

## Troubleshooting

### No results found
- Check CSV file exists and is properly formatted
- Ensure p0f and nmap logs exist in specified directories
- Verify IPs in CSV match those in log files

### Empty confusion matrix
- Ensure at least some IPs have detections in the logs
- Check log directory paths are correct

### Missing OS classes
- All unique classes from both ground truth and predictions are automatically included
- Class ordering is alphabetical for consistency
