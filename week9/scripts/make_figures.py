#!/usr/bin/env python3
"""Render the Week 9 detection-matrix figures and the ATT&CK Navigator coverage layer."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parents[1]
RES = json.loads((ROOT / "docs" / "test_results.json").read_text(encoding="utf-8"))
(ROOT / "images").mkdir(exist_ok=True)
(ROOT / "attack").mkdir(exist_ok=True)
INK = "#1a2332"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})


def fig_matrix():
    tests = RES["tests"]
    rules = list(RES["rules"])
    # 0 none, 1 harness only, 2 proxy, 3 technique
    grid = []
    for r in rules:
        row = []
        for t in tests:
            d = RES["rules"][r]["by_step"].get(str(t["step"])) or RES["rules"][r]["by_step"].get(t["step"])
            v = 0
            if d:
                v = 3 if d["technique"] else 2 if d["proxy"] else 1 if d["harness"] else 0
            row.append(v)
        grid.append(row)
    cmap = ListedColormap(["#f3f4f6", "#d9d2c5", "#e3b26b", "#3f7fb4"])
    fig, ax = plt.subplots(figsize=(11, 6.2))
    ax.imshow(grid, cmap=cmap, vmin=0, vmax=3, aspect="auto")
    ax.set_xticks(range(len(tests)))
    ax.set_xticklabels([f"{t['step']}. {t['technique']}" for t in tests], rotation=35, ha="right")
    ax.set_yticks(range(len(rules)))
    ax.set_yticklabels([f"{r}  (FP {len(RES['rules'][r]['false_positives'])})" for r in rules], fontsize=8.5)
    for i in range(len(rules) + 1):
        ax.axhline(i - 0.5, color="white", lw=2)
    for j in range(len(tests) + 1):
        ax.axvline(j - 0.5, color="white", lw=2)
    n7 = sum(r.startswith("w7_") for r in rules)
    ax.axhline(n7 - 0.5, color=INK, lw=1.6)
    ax.legend(handles=[Patch(color="#3f7fb4", label="matched the technique event"),
                       Patch(color="#e3b26b", label="matched only the test's emulation proxy"),
                       Patch(color="#d9d2c5", label="matched only the Atomic harness"),
                       Patch(color="#f3f4f6", label="no match")],
              loc="upper center", bbox_to_anchor=(0.45, -0.2), ncol=2, frameon=False, fontsize=8.5)
    ax.set_title("Atomic Red Team tests x detection rules (rows above the line = Week 7 CAR rules)",
                 fontsize=11.5, fontweight="bold", color=INK, pad=10)
    fig.tight_layout()
    fig.savefig(ROOT / "images" / "detection_matrix.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def fig_before_after():
    s = RES["summary"]
    cats = ["DETECTED", "PARTIAL", "MISSED"]
    colors = ["#3f7fb4", "#e3b26b", "#b4543f"]
    fig, ax = plt.subplots(figsize=(7.4, 3.2))
    labels = [f"Week 7 rules\n({s['week7']['rules']} rules, {s['week7']['false_positives']} FP)",
              f"Week 7 + Week 9\n({s['week9']['rules']} rules, {s['week9']['false_positives']} FP)"]
    for i, k in enumerate(["week7", "week9"]):
        left = 0
        for c, col in zip(cats, colors):
            v = s[k][c]
            if v:
                ax.barh(i, v, left=left, color=col, height=0.55)
                ax.text(left + v / 2, i, f"{v} {c.lower()}" if v >= 2 else str(v), ha="center", va="center", color="white",
                        fontsize=9, fontweight="bold")
            left += v
    ax.set_yticks([0, 1])
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, len(RES["tests"]))
    ax.legend(handles=[Patch(color=c, label=k.lower()) for k, c in zip(cats, colors)],
              loc="upper center", bbox_to_anchor=(0.5, -0.3), ncol=3, frameon=False, fontsize=8.5)
    ax.set_xlabel("Atomic tests (out of 9)")
    ax.set_title("Plan coverage before and after Week 9",
                 fontsize=11.5, fontweight="bold", color=INK)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(ROOT / "images" / "coverage_before_after.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def navigator():
    color = {"DETECTED": "#3f7fb4", "PARTIAL": "#e3b26b", "MISSED": "#b4543f"}
    techs = [{"techniqueID": t["technique"], "color": color[t["week9"]["status"]],
              "comment": f"Atomic {t['atomic']} ({t['guid'][:8]}): {t['week9']['status']} by "
                         f"{', '.join(t['week9']['rules']) or 'none'}; Week 7 rules: {t['week7']['status']}",
              "enabled": True} for t in RES["tests"]]
    layer = {"name": "Week 9 - Atomic Red Team detection coverage",
             "versions": {"attack": "20", "navigator": "4.9.1", "layer": "4.5"},
             "domain": "enterprise-attack",
             "description": "Blue = detected, amber = only the test's emulation proxy matched, red = missed. "
                            "Synthetic telemetry modelled from pinned Atomic tests.",
             "techniques": techs,
             "legendItems": [{"label": k.lower(), "color": v} for k, v in color.items()]}
    (ROOT / "attack" / "navigator_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")


if __name__ == "__main__":
    fig_matrix()
    fig_before_after()
    navigator()
    print("wrote images/detection_matrix.png, images/coverage_before_after.png, attack/navigator_layer.json")
