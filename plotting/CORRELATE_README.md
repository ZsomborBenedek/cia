# p0f & nmap Correlation & Detection Accuracy Analyzer

This script correlates OS detections from p0f logs and nmap outputs to measure how much combining both detection methods improves accuracy.

## Features

- **Parses p0f logs**: Extracts OS predictions from p0f passive OS fingerprinting
- **Parses nmap logs**: Extracts OS guesses from nmap's aggressive OS scanning
- **Correlates predictions**: Combines predictions from both tools
- **Generates confusion matrices**: Visualizes prediction accuracy for each method
- **Calculates accuracy improvements**: Shows how much combining p0f and nmap improves detection

## Installation

```bash
pip install -r requirements_correlate.txt
```

## Usage

### Basic Usage

```bash
python correlate_and_analyze.py --ip 145.100.104.117 --true-os "Linux"
```

### With Custom Directories

```bash
python correlate_and_analyze.py \
  --ip 145.100.104.117 \
  --true-os "Ubuntu Linux" \
  --p0f-dir p0f_logs \
  --nmap-dir nmap
```

### Save Output Plot

```bash
python correlate_and_analyze.py \
  --ip 145.100.104.117 \
  --true-os "Linux" \
  --output confusion_matrices.png
```

## Command-line Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--ip` | Yes | Target IP address to analyze |
| `--true-os` | Yes | Ground truth OS (used for confusion matrix labels) |
| `--p0f-dir` | No | Directory containing p0f logs (default: `p0f_logs`) |
| `--nmap-dir` | No | Directory containing nmap logs (default: `nmap`) |
| `--output` | No | Output file path for confusion matrix plot (optional) |

## Output

The script produces:

1. **Console output** showing:
   - Raw predictions from both tools
   - Consensus predictions
   - Ground truth OS
   - Accuracy for each method
   - Accuracy improvement from combining both methods

2. **Visual output** (optionally saved to file):
   - Three confusion matrices side-by-side:
     - p0f predictions
     - nmap predictions
     - Combined predictions
   - Accuracy scores displayed on each matrix
   - Visual comparison of detection performance

## Example Output

```
=== Detection Results ===
p0f predictions:     ['Linux 2.6.32', 'Linux 4.15 - 5.19']
p0f consensus:       Linux

nmap predictions:    ['Linux 4.15 - 5.19 (97%)', 'Linux 5.0 - 5.14 (97%)']
nmap consensus:      Linux

Ground truth:        Linux
Combined consensus:  Linux

=== Accuracy Summary for 145.100.104.117 ===
p0f accuracy:     100.00%
nmap accuracy:    100.00%
Combined accuracy: 100.00%

Improvement from combination: +0.00%
```

## How It Works

### OS Family Extraction

Both p0f and nmap produce detailed OS strings (e.g., "Linux 4.15 - 5.19"). This script extracts the OS family:

- "Linux 4.15 - 5.19" → **Linux**
- "Ubuntu Linux" → **Linux**
- "OpenWrt 21.02" → **Linux**
- "MikroTik RouterOS 7.2" → **MikroTik**
- "Windows 10" → **Windows**

### Consensus Prediction

When multiple predictions are available, the script determines the most common OS family. For example:
- Predictions: ["Linux", "Linux", "Windows"] → Consensus: **Linux**

### Correlation

The combined prediction includes detections from both p0f and nmap, allowing the script to measure how much combining both improves accuracy over each tool individually.

## Files Modified

- `correlate_and_analyze.py` - Main analysis script
- `requirements_correlate.txt` - Python dependencies

## Requirements

- Python 3.8+
- numpy
- matplotlib
- seaborn
- scikit-learn

## Performance Notes

- Parse time depends on log file size (typically <1 second for moderate-sized logs)
- Visualization rendering takes ~2 seconds
- Memory usage is minimal (logs loaded entirely into memory)

## Limitations

- Requires at least one p0f log and one nmap log in the specified directories
- OS family detection is heuristic-based; custom OS strings may not be recognized
- Accuracy is only meaningful when ground truth is accurately specified
- Single IP analysis; for batch analysis, consider extending the script
