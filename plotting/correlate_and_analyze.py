#!/usr/bin/env python3
"""
Correlate p0f logs with nmap outputs and analyze detection accuracy.

This script:
1. Parses p0f logs and nmap outputs
2. Correlates OS detections for a given IP
3. Generates confusion matrices for individual and combined predictions
4. Calculates accuracy improvements
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict

import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, accuracy_score
import seaborn as sns


class P0FParser:
    """Parse p0f log files."""

    def __init__(self, log_file: str):
        self.log_file = log_file
        self.detections = {}  # ip -> list of os predictions

    def parse(self) -> Dict[str, List[str]]:
        """Parse p0f log and extract OS predictions by IP."""
        if not os.path.exists(self.log_file):
            print(f"Warning: p0f log file not found: {self.log_file}")
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

                # Extract IP
                m_ip = ip_re.search(rest)
                if not m_ip:
                    continue

                ip = m_ip.group("cli_ip")

                # Extract OS
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
        self.detections = {}  # ip -> list of os guesses

    def parse(self) -> Dict[str, List[str]]:
        """Parse nmap log and extract OS guesses."""
        if not os.path.exists(self.log_file):
            print(f"Warning: nmap log file not found: {self.log_file}")
            return {}

        detections = defaultdict(list)

        with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

            # Extract target IP from "Nmap scan report for" line
            target_re = re.compile(r"Nmap scan report for .* \((\d{1,3}(?:\.\d{1,3}){3})\)")
            m_target = target_re.search(content)
            if not m_target:
                return {}

            target_ip = m_target.group(1)

            # Extract OS guesses from "Aggressive OS guesses:" section
            os_section_re = re.compile(
                r"Aggressive OS guesses:\s*(.+?)(?:\nNo exact OS matches|$)", re.DOTALL
            )
            m_section = os_section_re.search(content)

            if m_section:
                os_guesses_text = m_section.group(1)
                # Each guess is like "Linux 4.15 - 5.19 (97%)"
                guess_re = re.compile(r"([^(]+)\s*\(\d+%\)")
                for match in guess_re.finditer(os_guesses_text):
                    os_guess = match.group(1).strip()
                    if os_guess and os_guess != "?":
                        detections[target_ip].append(os_guess)

        self.detections = dict(detections)
        return self.detections


def extract_os_family(os_string: str) -> str:
    """Extract OS family from a full OS string.
    
    Examples:
    - "Linux 4.15 - 5.19" -> "Linux"
    - "Ubuntu Linux" -> "Linux"
    - "OpenWrt 21.02" -> "Linux"
    - "MikroTik RouterOS" -> "MikroTik"
    - "Windows 10" -> "Windows"
    """
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

    # Return most common family
    from collections import Counter

    counter = Counter(families_filtered)
    return counter.most_common(1)[0][0]


def correlate_detections(
    p0f_detections: Dict[str, List[str]], nmap_detections: Dict[str, List[str]], target_ip: str
) -> Tuple[str, str, str, List[str], List[str]]:
    """Correlate p0f and nmap detections for a target IP.

    Returns:
    - p0f consensus OS
    - nmap consensus OS
    - combined consensus OS
    - p0f raw predictions
    - nmap raw predictions
    """
    p0f_preds = p0f_detections.get(target_ip, [])
    nmap_preds = nmap_detections.get(target_ip, [])

    p0f_os = get_consensus_prediction(p0f_preds)
    nmap_os = get_consensus_prediction(nmap_preds)

    # Combined: weight both sources equally
    combined_preds = p0f_preds + nmap_preds
    combined_os = get_consensus_prediction(combined_preds)

    return p0f_os, nmap_os, combined_os, p0f_preds, nmap_preds


def build_ground_truth(target_ip: str, true_os: str) -> str:
    """Return the ground truth OS for comparison."""
    return extract_os_family(true_os)


def analyze_predictions(
    target_ip: str,
    true_os: str,
    p0f_dir: str = "p0f_logs",
    nmap_dir: str = "nmap",
) -> Dict:
    """Analyze p0f and nmap predictions for a target IP."""

    results = {
        "target_ip": target_ip,
        "true_os": build_ground_truth(target_ip, true_os),
        "p0f_predictions": [],
        "nmap_predictions": [],
        "p0f_consensus": None,
        "nmap_consensus": None,
        "combined_consensus": None,
    }

    # Parse p0f logs
    p0f_detections = {}
    if os.path.exists(p0f_dir):
        for log_file in Path(p0f_dir).glob("*.log"):
            parser = P0FParser(str(log_file))
            detections = parser.parse()
            p0f_detections.update(detections)

    # Parse nmap logs
    nmap_detections = {}
    if os.path.exists(nmap_dir):
        for log_file in Path(nmap_dir).glob("*.log"):
            parser = NmapParser(str(log_file))
            detections = parser.parse()
            nmap_detections.update(detections)

    # Get predictions
    p0f_os, nmap_os, combined_os, p0f_preds, nmap_preds = correlate_detections(
        p0f_detections, nmap_detections, target_ip
    )

    results["p0f_predictions"] = p0f_preds
    results["nmap_predictions"] = nmap_preds
    results["p0f_consensus"] = p0f_os
    results["nmap_consensus"] = nmap_os
    results["combined_consensus"] = combined_os

    return results


def create_confusion_matrices(results: Dict) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Create confusion matrices for p0f, nmap, and combined predictions."""

    true_os = results["true_os"]
    p0f_pred = results["p0f_consensus"]
    nmap_pred = results["nmap_consensus"]
    combined_pred = results["combined_consensus"]

    # All possible OS classes
    classes = sorted(list(set([true_os, p0f_pred, nmap_pred, combined_pred])))
    class_to_idx = {cls: idx for idx, cls in enumerate(classes)}

    # Convert to indices
    true_idx = class_to_idx[true_os]
    p0f_idx = class_to_idx[p0f_pred]
    nmap_idx = class_to_idx[nmap_pred]
    combined_idx = class_to_idx[combined_pred]

    n_classes = len(classes)

    # Create confusion matrices
    cm_p0f = np.zeros((n_classes, n_classes))
    cm_nmap = np.zeros((n_classes, n_classes))
    cm_combined = np.zeros((n_classes, n_classes))

    cm_p0f[true_idx, p0f_idx] += 1
    cm_nmap[true_idx, nmap_idx] += 1
    cm_combined[true_idx, combined_idx] += 1

    return cm_p0f, cm_nmap, cm_combined, classes


def plot_confusion_matrices(
    cm_p0f: np.ndarray,
    cm_nmap: np.ndarray,
    cm_combined: np.ndarray,
    classes: List[str],
    target_ip: str,
    output_file: str = None,
):
    """Plot confusion matrices side by side."""

    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    # Calculate accuracies
    p0f_acc = np.trace(cm_p0f) / cm_p0f.sum() if cm_p0f.sum() > 0 else 0
    nmap_acc = np.trace(cm_nmap) / cm_nmap.sum() if cm_nmap.sum() > 0 else 0
    combined_acc = np.trace(cm_combined) / cm_combined.sum() if cm_combined.sum() > 0 else 0

    # p0f
    sns.heatmap(cm_p0f, annot=True, fmt=".0f", cmap="Blues", ax=axes[0], xticklabels=classes,
                yticklabels=classes, cbar=False)
    axes[0].set_title(f"p0f\nAccuracy: {p0f_acc:.2%}")
    axes[0].set_ylabel("True OS")
    axes[0].set_xlabel("Predicted OS")

    # nmap
    sns.heatmap(cm_nmap, annot=True, fmt=".0f", cmap="Greens", ax=axes[1], xticklabels=classes,
                yticklabels=classes, cbar=False)
    axes[1].set_title(f"nmap\nAccuracy: {nmap_acc:.2%}")
    axes[1].set_ylabel("True OS")
    axes[1].set_xlabel("Predicted OS")

    # combined
    sns.heatmap(cm_combined, annot=True, fmt=".0f", cmap="Oranges", ax=axes[2],
                xticklabels=classes, yticklabels=classes, cbar=False)
    axes[2].set_title(f"p0f + nmap (combined)\nAccuracy: {combined_acc:.2%}")
    axes[2].set_ylabel("True OS")
    axes[2].set_xlabel("Predicted OS")

    plt.suptitle(f"OS Detection Correlation Analysis for {target_ip}", fontsize=14, fontweight="bold")
    plt.tight_layout()

    if output_file:
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        print(f"Confusion matrices saved to {output_file}")

    plt.show()

    # Print summary
    print(f"\n=== Accuracy Summary for {target_ip} ===")
    print(f"p0f accuracy:     {p0f_acc:.2%}")
    print(f"nmap accuracy:    {nmap_acc:.2%}")
    print(f"Combined accuracy: {combined_acc:.2%}")

    improvement = combined_acc - max(p0f_acc, nmap_acc)
    print(f"\nImprovement from combination: {improvement:+.2%}")


def main():
    parser = argparse.ArgumentParser(
        description="Correlate p0f logs with nmap outputs and analyze detection accuracy"
    )
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--true-os", required=True, help="Ground truth OS (for labeling)")
    parser.add_argument("--p0f-dir", default="p0f_logs", help="Directory containing p0f logs")
    parser.add_argument("--nmap-dir", default="nmap", help="Directory containing nmap logs")
    parser.add_argument("--output", default=None, help="Output file for confusion matrix plot")

    args = parser.parse_args()

    print(f"Analyzing OS detection for {args.ip}...")
    print(f"Ground truth OS: {args.true_os}")

    # Run analysis
    results = analyze_predictions(
        target_ip=args.ip,
        true_os=args.true_os,
        p0f_dir=args.p0f_dir,
        nmap_dir=args.nmap_dir,
    )

    print("\n=== Detection Results ===")
    print(f"p0f predictions:     {results['p0f_predictions']}")
    print(f"p0f consensus:       {results['p0f_consensus']}")
    print(f"\nnmap predictions:    {results['nmap_predictions']}")
    print(f"nmap consensus:      {results['nmap_consensus']}")
    print(f"\nGround truth:        {results['true_os']}")
    print(f"Combined consensus:  {results['combined_consensus']}")

    # Create confusion matrices
    cm_p0f, cm_nmap, cm_combined, classes = create_confusion_matrices(results)

    # Plot
    plot_confusion_matrices(
        cm_p0f, cm_nmap, cm_combined, classes, args.ip, output_file=args.output
    )


if __name__ == "__main__":
    main()
