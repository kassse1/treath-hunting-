#!/usr/bin/env python3
"""Render Week 6 figures from the committed hunt outputs (no network, no live data)."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "images"
IMG.mkdir(exist_ok=True)
INK = "#1a2332"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})


def fig_attack_chain():
    chain = [
        ("T1566.001", "Spearphishing\nAttachment", "Initial Access"),
        ("T1204.002", "Malicious File", "Execution"),
        ("T1059.001", "PowerShell", "Execution"),
        ("T1027.010", "Command\nObfuscation", "Defense Evasion"),
        ("T1071.001", "Web Protocols", "Command & Control"),
    ]
    colors = ["#2f6f9f", "#3b7f5f", "#3b7f5f", "#9f6f2f", "#8f3f5f"]
    fig, ax = plt.subplots(figsize=(11, 3.2))
    ax.set_xlim(0, len(chain) * 2.2)
    ax.set_ylim(0, 3)
    ax.axis("off")
    for i, ((tid, name, tactic), c) in enumerate(zip(chain, colors)):
        x = i * 2.2 + 0.15
        box = FancyBboxPatch((x, 0.8), 1.75, 1.4, boxstyle="round,pad=0.05,rounding_size=0.12",
                             linewidth=1.5, edgecolor=c, facecolor=c + "22")
        ax.add_patch(box)
        ax.text(x + 0.875, 1.85, tid, ha="center", va="center", fontsize=10, fontweight="bold", color=c)
        ax.text(x + 0.875, 1.35, name, ha="center", va="center", fontsize=10, color=INK)
        ax.text(x + 0.875, 0.55, tactic, ha="center", va="center", fontsize=8.5, style="italic", color="#555")
        if i < len(chain) - 1:
            ax.add_patch(FancyArrowPatch((x + 1.95, 1.5), (x + 2.2, 1.5),
                                         arrowstyle="-|>", mutation_scale=18, color="#888", linewidth=1.5))
    ax.text(len(chain) * 1.1, 2.75, "FIN-WS01 observed chain  (ATT&CK Enterprise v20, synthetic data)",
            ha="center", fontsize=11, fontweight="bold", color=INK)
    fig.tight_layout()
    fig.savefig(IMG / "attack_chain.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig_funnel():
    hosts = json.loads((ROOT / "docs" / "hunt_results.json").read_text())
    stages = [
        ("Endpoints in scope", 4),
        ("Office → interpreter", sum(1 for f in hosts.values()
                                          if any("spawned" in s for s in f["signals"]))),
        ("+ encoded command", sum(1 for f in hosts.values()
                                  if "T1027.010" in f["techniques"])),
        ("+ correlated egress\n(same process)", sum(1 for f in hosts.values()
                                                    if "T1071.001" in f["techniques"])),
    ]
    labels = [s[0] for s in stages]
    vals = [s[1] for s in stages]
    fig, ax = plt.subplots(figsize=(8, 4))
    bars = ax.barh(range(len(vals))[::-1], vals, color=["#8fb4cf", "#5f93b9", "#3b7f5f", "#b4543f"],
                   height=0.62)
    ax.set_yticks(range(len(vals))[::-1])
    ax.set_yticklabels(labels, fontsize=10.5)
    ax.set_xlabel("hosts remaining")
    ax.set_xlim(0, 4.5)
    ax.set_xticks(range(5))
    for b, v in zip(bars, vals):
        ax.text(v + 0.08, b.get_y() + b.get_height() / 2, str(v), va="center", fontweight="bold")
    ax.set_title("Week 6 hunt funnel: four hosts narrowed to one suspicious candidate",
                 fontsize=11.5, fontweight="bold", color=INK, pad=12)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "hunt_funnel.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    fig_attack_chain()
    fig_funnel()
    print("wrote images/attack_chain.png, images/hunt_funnel.png")
