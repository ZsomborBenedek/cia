#!/usr/bin/env python3
"""
Bar chart comparison showing accuracy improvements per OS class.

This script:
1. Analyzes multiple IPs from a CSV file
2. Groups results by true OS class
3. Calculates p0f and combined accuracy for each OS
4. Creates a grouped bar chart for easy comparison
"""

import os
import re
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict, Counter

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


class P0FParser:
    """Parse p0f log files."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.detections = {}

    def parse(self) -> Dict[str, List[str]]:
        """Parse p0f log and extract OS predictions by IP."""
        if not os.path.exists(self.log_file):
            return {}

        detections = defaultdict(list)
        ts_re = re.compile(r"^\[(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\]\s*(?P<rest>.*)$")
        ip_re = re.compile(r"cli=(?P<cli_ip>\d{1,3}(?:\.\d{1,3}){3})")
        os_re = re.compile(r"os=(?P<os>[^|]+)")

        with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                m_ts = ts_re.match(line)
                if not m_ts:
                    continue

                rest = m_ts.group("rest")
                m_ip = ip_re.search(rest)
                if not m_ip:
                    continue

                ip = m_ip.group("cli_ip")
                m_os = os_re.search(rest)
                if not m_os:
                    continue

                os_pred = m_os.group("os").strip()
                if os_pred and os_pred != "Unknown":
                    detections[ip].append(os_pred)

        self.detections = dict(detections)
        return self.detections


class NmapParser:
    """Parse nmap log files."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.detections = {}

    def parse(self) -> Dict[str, List[str]]:
        """Parse nmap log and extract OS guesses."""
        if not os.path.exists(self.log_file):
            return {}

        detections = defaultdict(list)

        with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

            # Extract target IP from "Nmap scan report for" line
            target_re = re.compile(r"Nmap scan report for .* \((\d{1,3}(?:\.\d{1,3}){3})\)")
            for m_target in target_re.finditer(content):
                target_ip = m_target.group(1)

                # Find OS guesses section after this target
                search_start = m_target.end()
                next_target = target_re.search(content, search_start)
                search_end = next_target.start() if next_target else len(content)

                section = content[search_start:search_end]
                os_section_re = re.compile(
                    r"Aggressive OS guesses:\s*(.+?)(?:\nNo exact OS matches|$)", re.DOTALL
                )
                m_section = os_section_re.search(section)

                if m_section:
                    os_guesses_text = m_section.group(1)
                    guess_re = re.compile(r"([^(]+)\s*\(\d+%\)")
                    for match in guess_re.finditer(os_guesses_text):
                        os_guess = match.group(1).strip()
                        if os_guess and os_guess != "?":
                            detections[target_ip].append(os_guess)

        self.detections = dict(detections)
        return self.detections


def extract_os_family(os_string: str) -> str:
    """Extract OS family from a full OS string."""
    os_lower = os_string.lower()

    if "windows" in os_lower:
        return "Windows"
    elif "ubuntu" in os_lower or "debian" in os_lower or "openwrt" in os_lower:
        return "Linux"
    elif "macos" in os_lower or "mac os" in os_lower:
        return "macOS"
    elif "mikrotik" in os_lower or "routeros" in os_lower:
        return "MikroTik"
    elif "linux" in os_lower:
        return "Linux"
    elif "freebsd" in os_lower:
        return "FreeBSD"
    elif "ios" in os_lower or "cisco" in os_lower:
        return "Cisco IOS"
    elif "android" in os_lower:
        return "Android"
    else:
        return "Unknown"


def get_consensus_prediction(predictions: List[str]) -> str:
    """Get consensus OS family from multiple predictions."""
    if not predictions:
        return "Unknown"

    families = [extract_os_family(p) for p in predictions]
    families_filtered = [f for f in families if f != "Unknown"]

    if not families_filtered:
        return "Unknown"

    counter = Counter(families_filtered)
    return counter.most_common(1)[0][0]


def analyze_from_csv(csv_file: str, p0f_dir: str = "p0f_logs", nmap_dir: str = "nmap") -> List[Dict]:
    """Analyze multiple IPs from a CSV file."""
    results = []

    # Parse all p0f logs
    p0f_detections = {}
    if os.path.exists(p0f_dir):
        for log_file in Path(p0f_dir).glob("*.log"):
            parser = P0FParser(str(log_file))
            detections = parser.parse()
            p0f_detections.update(detections)

    # Parse all nmap logs
    nmap_detections = {}
    if os.path.exists(nmap_dir):
        for log_file in Path(nmap_dir).glob("*.log"):
            parser = NmapParser(str(log_file))
            detections = parser.parse()
            nmap_detections.update(detections)

    # Process CSV
    with open(csv_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            if len(parts) < 2:
                continue

            ip = parts[0].strip()
            true_os = parts[1].strip()
            true_family = extract_os_family(true_os)

            p0f_preds = p0f_detections.get(ip, [])
            nmap_preds = nmap_detections.get(ip, [])

            p0f_family = get_consensus_prediction(p0f_preds)
            combined_family = get_consensus_prediction(p0f_preds + nmap_preds)

            results.append({
                "ip": ip,
                "true_os": true_family,
                "p0f_prediction": p0f_family,
                "combined_prediction": combined_family,
            })

    return results


def calculate_per_os_accuracy(results: List[Dict]) -> Dict[str, Dict]:
    """Calculate accuracy metrics for each OS class.
    
    Returns:
    {
        "Linux": {
            "total": 5,
            "p0f_correct": 4,
            "combined_correct": 5,
            "p0f_accuracy": 0.80,
            "combined_accuracy": 1.00
        },
        ...
    }
    """
    os_stats = defaultdict(lambda: {"total": 0, "p0f_correct": 0, "combined_correct": 0})

    for result in results:
        true_os = result["true_os"]
        p0f_pred = result["p0f_prediction"]
        combined_pred = result["combined_prediction"]

        os_stats[true_os]["total"] += 1
        if p0f_pred == true_os:
            os_stats[true_os]["p0f_correct"] += 1
        if combined_pred == true_os:
            os_stats[true_os]["combined_correct"] += 1

    # Calculate accuracies
    for os_class in os_stats:
        total = os_stats[os_class]["total"]
        os_stats[os_class]["p0f_accuracy"] = os_stats[os_class]["p0f_correct"] / total if total > 0 else 0
        os_stats[os_class]["combined_accuracy"] = os_stats[os_class]["combined_correct"] / total if total > 0 else 0
        os_stats[os_class]["improvement"] = (
            os_stats[os_class]["combined_accuracy"] - os_stats[os_class]["p0f_accuracy"]
        )

    return dict(os_stats)


def plot_per_os_comparison(os_stats: Dict[str, Dict], output_file: str = None):
    """Create a grouped bar chart comparing p0f vs combined accuracy per OS."""
    if not os_stats:
        print("No data to plot")
        return

    # Sort by OS name
    os_classes = sorted(os_stats.keys())
    p0f_accuracies = [os_stats[os_class]["p0f_accuracy"] for os_class in os_classes]
    combined_accuracies = [os_stats[os_class]["combined_accuracy"] for os_class in os_classes]
    improvements = [os_stats[os_class]["improvement"] for os_class in os_classes]

    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))

    x = np.arange(len(os_classes))
    width = 0.35

    # Create bars
    bars1 = ax.bar(x - width / 2, p0f_accuracies, width, label="p0f Only", color="#3498db", alpha=0.8)
    bars2 = ax.bar(x + width / 2, combined_accuracies, width, label="p0f + nmap", color="#e74c3c", alpha=0.8)

    # Add value labels on bars
    def add_value_labels(bars):
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2., height,
                    f'{height:.0%}',
                    ha='center', va='bottom', fontsize=10, fontweight='bold')

    add_value_labels(bars1)
    add_value_labels(bars2)

    # Add improvement indicators
    for i, (os_class, improvement) in enumerate(zip(os_classes, improvements)):
        if improvement > 0:
            ax.text(i, max(p0f_accuracies[i], combined_accuracies[i]) + 0.08,
                   f'+{improvement:.0%}', ha='center', fontsize=9, color='green', fontweight='bold')

    # Customize plot
    ax.set_ylabel('Accuracy', fontsize=12, fontweight='bold')
    ax.set_xlabel('Operating System', fontsize=12, fontweight='bold')
    ax.set_title('Detection Accuracy by OS Class\np0f vs p0f + nmap', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(os_classes, fontsize=11)
    ax.legend(fontsize=11)
    ax.set_ylim(0, 1.15)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.set_axisbelow(True)

    plt.tight_layout()

    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        print(f"Bar chart saved to {output_file}")

    plt.show()


def print_detailed_stats(os_stats: Dict[str, Dict]):
    """Print detailed statistics for each OS class."""
    print("\n" + "="*90)
    print("PER-OS ACCURACY STATISTICS")
    print("="*90)
    print(f"{'OS Class':<15} {'Total':<8} {'p0f Correct':<15} {'Combined Correct':<18} {'p0f Acc':<12} {'Combined Acc':<14} {'Improvement':<12}")
    print("-"*90)

    for os_class in sorted(os_stats.keys()):
        stats = os_stats[os_class]
        print(f"{os_class:<15} {stats['total']:<8} {stats['p0f_correct']:<15} "
              f"{stats['combined_correct']:<18} {stats['p0f_accuracy']:<12.2%} "
              f"{stats['combined_accuracy']:<14.2%} {stats['improvement']:<+12.2%}")

    print("="*90 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate bar chart comparing p0f vs combined accuracy per OS class"
    )
    parser.add_argument("--csv", required=True, help="CSV file with IPs and ground truth (format: ip,true_os)")
    parser.add_argument("--p0f-dir", default="p0f_logs", help="Directory containing p0f logs")
    parser.add_argument("--nmap-dir", default="nmap", help="Directory containing nmap logs")
    parser.add_argument("--output", default=None, help="Output file for bar chart")

    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"Error: CSV file not found: {args.csv}")
        return

    print(f"Loading analysis from {args.csv}...")
    results = analyze_from_csv(args.csv, p0f_dir=args.p0f_dir, nmap_dir=args.nmap_dir)

    if not results:
        print("No results found. Check CSV file and log directories.")
        return

    print(f"Analyzed {len(results)} IP(s)")

    # Calculate per-OS statistics
    os_stats = calculate_per_os_accuracy(results)

    # Print detailed stats
    print_detailed_stats(os_stats)

    # Create bar chart
    plot_per_os_comparison(os_stats, output_file=args.output)


if __name__ == "__main__":
    main()
