#!/usr/bin/env python3
"""Render Week 7 figures and the CAR->ATT&CK Navigator layer from executed results."""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]
IMG = ROOT / "images"
ATT = ROOT / "attack"
IMG.mkdir(exist_ok=True)
ATT.mkdir(exist_ok=True)
RES = json.loads((ROOT / "docs" / "hunt_results.json").read_text())
INK = "#1a2332"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})


def fig_raw_vs_tuned():
    labels = ["CAR-2014-04-003\nraw", "CAR-2014-04-003\ntuned", "after Week 6\ncorrelation"]
    raw = RES["car_2014_04_003_powershell"]["rows"]
    tuned = RES["car_2014_04_003_powershell_tuned"]["rows"]
    correlated = 1  # FIN-WS01 only, from the Week 6 same-process egress step
    vals = [raw, tuned, correlated]
    fp = [1, 0, 0]  # benign automation still matched by raw
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    x = range(len(vals))
    ax.bar(x, vals, color=["#8fb4cf", "#5f93b9", "#b4543f"], width=0.6, zorder=3)
    for i, (v, f) in enumerate(zip(vals, fp)):
        ax.text(i, v + 0.05, str(v), ha="center", fontweight="bold")
        if f:
            ax.text(i, v / 2, f"{f} benign\nautomation\n(FP)", ha="center", va="center",
                    fontsize=8.5, color="#5a2a1a")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel("hosts matched")
    ax.set_ylim(0, raw + 0.8)
    ax.set_title("CAR analytic tuning: fewer false positives at each step",
                 fontsize=12, fontweight="bold", color=INK, pad=12)
    ax.grid(axis="y", color="#e5e5e5", zorder=0)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(IMG / "raw_vs_tuned.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def navigator_layer():
    # CAR analytics implemented this week and the ATT&CK techniques they cover
    techniques = [
        {"techniqueID": "T1059.001", "score": 2, "comment": "CAR-2014-04-003 raw + tuned"},
        {"techniqueID": "T1027.010", "score": 1, "comment": "tuned variant: encoded command"},
        {"techniqueID": "T1204.002", "score": 1, "comment": "Office-spawned execution"},
        {"techniqueID": "T1059.003", "score": 1, "comment": "CAR-2013-02-003 (cmd variant coverage)"},
    ]
    layer = {
        "name": "Week 7 - CAR analytics coverage (executed)",
        "versions": {"attack": "20", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("ATT&CK techniques covered by the Week 7 MITRE CAR analytics "
                        "(CAR-2014-04-003, CAR-2013-02-003) implemented as Sigma and executed "
                        "in a SQLite log store. Synthetic data."),
        "techniques": [dict(t, color="#5f93b9", enabled=True) for t in techniques],
        "gradient": {"colors": ["#ffe766", "#5f93b9"], "minValue": 1, "maxValue": 2},
        "metadata": [{"name": "source", "value": "car.mitre.org + attack-stix-data v20"}],
    }
    (ATT / "navigator_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")


if __name__ == "__main__":
    fig_raw_vs_tuned()
    navigator_layer()
    print("wrote images/raw_vs_tuned.png and attack/navigator_layer.json")
