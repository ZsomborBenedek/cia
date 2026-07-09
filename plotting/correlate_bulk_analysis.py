#!/usr/bin/env python3
"""
Bulk correlation analysis with a single comprehensive confusion matrix.

This script:
1. Analyzes multiple IPs at once
2. Correlates p0f and nmap detections
3. Generates a single confusion matrix showing all OS classes
4. Compares p0f, nmap, and combined accuracy across all IPs
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict, Counter

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
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
    """Analyze multiple IPs from a CSV file.
    
    CSV format: ip,true_os
    """
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
            nmap_family = get_consensus_prediction(nmap_preds)
            combined_family = get_consensus_prediction(p0f_preds + nmap_preds)

            results.append({
                "ip": ip,
                "true_os": true_family,
                "p0f_prediction": p0f_family,
                "nmap_prediction": nmap_family,
                "combined_prediction": combined_family,
                "p0f_raw": p0f_preds,
                "nmap_raw": nmap_preds,
            })

    return results


def create_bulk_confusion_matrix(results: List[Dict]) -> Tuple[np.ndarray, List[str]]:
    """Create a confusion matrix from multiple IP analyses."""
    if not results:
        return None, None

    # Get all unique OS families
    all_families = set()
    for result in results:
        all_families.add(result["true_os"])
        all_families.add(result["combined_prediction"])

    classes = sorted(list(all_families))
    class_to_idx = {cls: idx for idx, cls in enumerate(classes)}

    n_classes = len(classes)
    cm = np.zeros((n_classes, n_classes), dtype=int)

    for result in results:
        true_idx = class_to_idx[result["true_os"]]
        pred_idx = class_to_idx[result["combined_prediction"]]
        cm[true_idx, pred_idx] += 1

    return cm, classes


def create_individual_confusion_matrices(results: List[Dict]) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    """Create separate confusion matrices for p0f and nmap."""
    if not results:
        return None, None, None

    # Get all unique OS families
    all_families = set()
    for result in results:
        all_families.add(result["true_os"])
        all_families.add(result["p0f_prediction"])
        all_families.add(result["nmap_prediction"])

    classes = sorted(list(all_families))
    class_to_idx = {cls: idx for idx, cls in enumerate(classes)}

    n_classes = len(classes)
    cm_p0f = np.zeros((n_classes, n_classes), dtype=int)
    cm_nmap = np.zeros((n_classes, n_classes), dtype=int)

    for result in results:
        true_idx = class_to_idx[result["true_os"]]
        p0f_idx = class_to_idx[result["p0f_prediction"]]
        nmap_idx = class_to_idx[result["nmap_prediction"]]
        cm_p0f[true_idx, p0f_idx] += 1
        cm_nmap[true_idx, nmap_idx] += 1

    return cm_p0f, cm_nmap, classes


def plot_single_confusion_matrix(
    cm: np.ndarray,
    classes: List[str],
    title: str = "OS Detection Confusion Matrix",
    output_file: str = None,
):
    """Plot a single large confusion matrix."""
    fig, ax = plt.subplots(figsize=(12, 10))

    sns.heatmap(cm, annot=True, fmt="d", cmap="YlOrRd", ax=ax, xticklabels=classes,
                yticklabels=classes, cbar_kws={"label": "Count"})

    accuracy = np.trace(cm) / cm.sum() if cm.sum() > 0 else 0

    ax.set_title(f"{title}\nAccuracy: {accuracy:.2%}", fontsize=14, fontweight="bold")
    ax.set_ylabel("True OS", fontsize=12)
    ax.set_xlabel("Predicted OS", fontsize=12)

    plt.tight_layout()

    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        print(f"Confusion matrix saved to {output_file}")

    plt.show()

    return accuracy


def print_analysis_summary(results: List[Dict]):
    """Print detailed analysis summary."""
    print("\n" + "="*70)
    print("BULK ANALYSIS SUMMARY")
    print("="*70)

    # Calculate accuracies
    p0f_correct = sum(1 for r in results if r["true_os"] == r["p0f_prediction"])
    nmap_correct = sum(1 for r in results if r["true_os"] == r["nmap_prediction"])
    combined_correct = sum(1 for r in results if r["true_os"] == r["combined_prediction"])

    total = len(results)
    p0f_acc = p0f_correct / total if total > 0 else 0
    nmap_acc = nmap_correct / total if total > 0 else 0
    combined_acc = combined_correct / total if total > 0 else 0

    print(f"\nTotal samples analyzed: {total}")
    print(f"\np0f accuracy:      {p0f_acc:.2%} ({p0f_correct}/{total})")
    print(f"nmap accuracy:     {nmap_acc:.2%} ({nmap_correct}/{total})")
    print(f"Combined accuracy: {combined_acc:.2%} ({combined_correct}/{total})")

    improvement = combined_acc - max(p0f_acc, nmap_acc)
    print(f"\nImprovement from combining: {improvement:+.2%}")

    print("\n" + "-"*70)
    print("DETAILED RESULTS")
    print("-"*70)
    print(f"{'IP':<15} {'True OS':<15} {'p0f':<15} {'nmap':<15} {'Combined':<15}")
    print("-"*70)

    for result in sorted(results, key=lambda x: x["ip"]):
        ip = result["ip"]
        true_os = result["true_os"]
        p0f = result["p0f_prediction"]
        nmap = result["nmap_prediction"]
        combined = result["combined_prediction"]

        p0f_mark = "✓" if p0f == true_os else "✗"
        nmap_mark = "✓" if nmap == true_os else "✗"
        combined_mark = "✓" if combined == true_os else "✗"

        print(f"{ip:<15} {true_os:<15} {p0f:<14}{p0f_mark} {nmap:<14}{nmap_mark} {combined:<14}{combined_mark}")

    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Bulk correlation analysis with comprehensive confusion matrix"
    )
    parser.add_argument("--csv", required=True, help="CSV file with IPs and ground truth (format: ip,true_os)")
    parser.add_argument("--p0f-dir", default="p0f_logs", help="Directory containing p0f logs")
    parser.add_argument("--nmap-dir", default="nmap", help="Directory containing nmap logs")
    parser.add_argument("--output", default=None, help="Output file for confusion matrix plot")
    parser.add_argument("--individual", action="store_true", help="Also show individual p0f and nmap matrices")

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

    # Print summary
    print_analysis_summary(results)

    # Create and plot combined confusion matrix
    cm_combined, classes = create_bulk_confusion_matrix(results)
    if cm_combined is not None:
        accuracy = plot_single_confusion_matrix(
            cm_combined,
            classes,
            title="Combined p0f + nmap OS Detection",
            output_file=args.output,
        )

    # Optionally show individual matrices
    if args.individual:
        cm_p0f, cm_nmap, classes = create_individual_confusion_matrices(results)
        
        fig, axes = plt.subplots(1, 2, figsize=(16, 6))

        p0f_acc = np.trace(cm_p0f) / cm_p0f.sum() if cm_p0f.sum() > 0 else 0
        nmap_acc = np.trace(cm_nmap) / cm_nmap.sum() if cm_nmap.sum() > 0 else 0

        sns.heatmap(cm_p0f, annot=True, fmt="d", cmap="Blues", ax=axes[0], xticklabels=classes,
                    yticklabels=classes)
        axes[0].set_title(f"p0f Only\nAccuracy: {p0f_acc:.2%}", fontsize=12, fontweight="bold")
        axes[0].set_ylabel("True OS")
        axes[0].set_xlabel("Predicted OS")

        sns.heatmap(cm_nmap, annot=True, fmt="d", cmap="Greens", ax=axes[1], xticklabels=classes,
                    yticklabels=classes)
        axes[1].set_title(f"nmap Only\nAccuracy: {nmap_acc:.2%}", fontsize=12, fontweight="bold")
        axes[1].set_ylabel("True OS")
        axes[1].set_xlabel("Predicted OS")

        plt.suptitle("Individual Tool Comparison", fontsize=14, fontweight="bold")
        plt.tight_layout()
        plt.show()


if __name__ == "__main__":
    main()
