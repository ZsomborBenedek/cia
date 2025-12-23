#!/usr/bin/env python3
"""
Plot accuracy improvement from correlated fingerprinting using plotting/combined.csv.

Expected CSV columns now include precomputed accuracies:
- ip, real_family, real_os, p0f, nmap, nmap_o, correlated, accuracy_p0f, accuracy_combined

For each true OS (real_os), we average the provided accuracies:
- p0f accuracy comes from accuracy_p0f
- correlated accuracy comes from accuracy_combined
Bars remain grouped by the exact real_os labels from the CSV.

Columns on the chart use the exact "real" OS labels from CSV.

Outputs a grouped bar chart per OS showing both accuracies and the improvement.
"""

import csv
import os
from collections import defaultdict, Counter
from typing import Dict, List

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

CSV_PATH = os.path.join(os.path.dirname(__file__), 'combined.csv')


def os_family(os_str: str) -> str:
    if not os_str:
        return 'Unknown'
    s = os_str.strip().lower()
    if 'windows' in s:
        return 'Windows'
    if 'ubuntu' in s or 'debian' in s or 'openwrt' in s or 'linux' in s:
        return 'Linux'
    if 'routeros' in s or 'mikrotik' in s:
        return 'RouterOS'
    if 'mac os' in s or 'macos' in s or 'os x' in s:
        return 'macOS'
    if 'freebsd' in s:
        return 'FreeBSD'
    if 'android' in s:
        return 'Android'
    if s in ('???', 'unknown'):
        return 'Unknown'
    return os_str.strip()


def load_rows(csv_path: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append(r)
    return rows


def _to_float(val: str | float | None) -> float | None:
    try:
        return float(val)
    except Exception:
        return None


def compute_stats(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, float]]:
    """Compute per-real_os stats using provided accuracies when available.

    Buckets are keyed by the exact value of the CSV "real_os" column.
    - accuracy_p0f is taken directly from CSV when present; else fallback to family/exact scoring
    - accuracy_combined is taken directly from CSV when present; else fallback to family/exact scoring
    We average scores per bucket. Bars are labeled by real_os.
    """

    def fallback_score(pred_label: str, real_label: str, real_family: str) -> float:
        pred_label = (pred_label or '').strip()
        if pred_label.lower() == real_label.lower() and real_label:
            return 1.0
        if os_family(pred_label) == real_family and real_family != 'Unknown':
            return 0.5
        return 0.0

    per_os = defaultdict(lambda: {'total': 0, 'p0f_score_sum': 0.0, 'corr_score_sum': 0.0})

    for r in rows:
        real_label = (r.get('real_os', '') or '').strip()
        real_family = os_family(r.get('real_family', real_label))

        p0f_label = (r.get('p0f', '') or '').strip()
        corr_label = (r.get('correlated', '') or '').strip()

        acc_p0f = _to_float(r.get('accuracy_p0f'))
        acc_combined = _to_float(r.get('accuracy_combined'))

        if acc_p0f is None:
            acc_p0f = fallback_score(p0f_label, real_label, real_family)
        if acc_combined is None:
            acc_combined = fallback_score(corr_label, real_label, real_family)

        bucket = per_os[real_label]
        bucket['total'] += 1
        bucket['p0f_score_sum'] += acc_p0f
        bucket['corr_score_sum'] += acc_combined

    # convert to accuracies
    for k, v in per_os.items():
        total = max(v['total'], 1)
        v['p0f_acc'] = v['p0f_score_sum'] / total
        v['corr_acc'] = v['corr_score_sum'] / total
        v['improvement'] = v['corr_acc'] - v['p0f_acc']
    return per_os


def plot_bars(stats: Dict[str, Dict[str, float]], title: str = 'Accuracy by Real OS: p0f vs Correlated', output: str | None = None):
    os_classes = sorted(stats.keys())
    p0f_acc = [stats[o]['p0f_acc'] for o in os_classes]
    corr_acc = [stats[o]['corr_acc'] for o in os_classes]
    improvements = [stats[o]['improvement'] for o in os_classes]

    sns.set(style='whitegrid')
    fig, ax = plt.subplots(figsize=(10, 6))

    x = np.arange(len(os_classes))
    width = 0.35

    b1 = ax.bar(x - width/2, p0f_acc, width, label='p0f', color='#3498db')
    b2 = ax.bar(x + width/2, corr_acc, width, label='p0f + nmap', color='#e74c3c')

    # labels
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2, h + 0.02, f"{h:.0%}", ha='center', va='bottom', fontsize=9)

    # improvement text
    for i, imp in enumerate(improvements):
        if imp > 0:
            ax.text(x[i], max(p0f_acc[i], corr_acc[i]) + 0.08, f"+{imp:.0%}", ha='center', color='green', fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(os_classes)
    ax.set_ylabel('Accuracy')
    ax.set_ylim(0, 1.2)
    ax.set_title(title)
    ax.legend()

    plt.tight_layout()
    if output:
        plt.savefig(output, dpi=300, bbox_inches='tight')
        print(f"Saved plot to {output}")
    plt.show()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Plot improvement from correlated fingerprinting')
    parser.add_argument('--csv', default=CSV_PATH, help='Path to combined.csv')
    parser.add_argument('--output', default=None, help='Path to save the plot image')
    args = parser.parse_args()

    rows = load_rows(args.csv)
    stats = compute_stats(rows)

    print('Per-OS stats:')
    for os_name in sorted(stats.keys()):
        s = stats[os_name]
        print(f"- {os_name}: total={s['total']}, p0f_acc={s['p0f_acc']:.2%}, corr_acc={s['corr_acc']:.2%}, improvement={s['improvement']:+.2%}")

    plot_bars(stats, output=args.output)


if __name__ == '__main__':
    main()
