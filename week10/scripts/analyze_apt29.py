#!/usr/bin/env python3
"""Week 10 - analyse APT29's TTPs, map them to ATT&CK, and measure how much of
APT29 the project's emulation plan (Week 8) and detections (Week 9) cover.

Inputs (all committed):
    data/apt29_profile.json, data/apt41_techniques.json     from build_apt_profile.py
    ../week8/plan/emulation_plan.yaml                        emulated techniques
    ../week9/docs/test_results.json                          detection status per technique

Outputs:
    docs/apt29_ttp_table.md       every APT29 technique, source, procedure, our coverage
    docs/analysis.json            numbers used in the report
    docs/execution_output.txt     run log
    images/apt29_tactics.png      techniques per tactic, coloured by our coverage
    images/apt29_initial_access.png  phishing-related TTP chain
    attack/apt29_coverage_layer.json  Navigator layer
"""
import json
import textwrap
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
APT = json.loads((ROOT / "data" / "apt29_profile.json").read_text(encoding="utf-8"))
A41 = json.loads((ROOT / "data" / "apt41_techniques.json").read_text(encoding="utf-8"))
PLAN = yaml.safe_load((ROOT.parent / "week8" / "plan" / "emulation_plan.yaml").read_text(encoding="utf-8"))
W9 = json.loads((ROOT.parent / "week9" / "docs" / "test_results.json").read_text(encoding="utf-8"))
for d in ("docs", "images", "attack"):
    (ROOT / d).mkdir(exist_ok=True)
INK = "#1a2332"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10})

LABEL = dict(APT["tactic_names"])
LABEL["stealth"] = "Defense Evasion"

COLORS = {"detected": "#3f7fb4", "sibling": "#8fb4cf", "emulated": "#e3b26b", "gap": "#b4543f"}
TEXT = {"detected": "detected by a Week 9 rule",
        "sibling": "same parent technique detected (different sub-technique)",
        "emulated": "emulated in Week 8 plan, not yet detected",
        "gap": "not covered"}

# Analyst judgement (not ATT&CK data): the uncovered APT29 techniques that matter
# most for a spearphishing-focused hunt on Windows endpoints, with the data source
# each would need. Ordered by priority.
NEXT_HUNTS = [
    ("T1566.002", "Spearphishing Link", "proxy/DNS + Sysmon 11 (zip/iso in Downloads)",
     "APT29's most-reported delivery method in ATT&CK; our plan only emulates attachments"),
    ("T1027.006", "HTML Smuggling", "Sysmon 11: .iso/.img/.vhdx written by a browser right after an .html opens",
     "NOBELIUM 2021 (EnvyScout) delivered ISO payloads inside HTML attachments"),
    ("T1553.005", "Mark-of-the-Web Bypass", "Sysmon 1/11: files executed from a mounted ISO/VHDX volume",
     "ISO/VHDX containers strip MOTW, so Office macro blocking never triggers"),
    ("T1218.005", "Mshta", "Sysmon 1: mshta.exe with http/javascript in the command line",
     "already in the Week 9 Office-child list as a child; needs a standalone rule"),
    ("T1546.003", "WMI Event Subscription", "Sysmon 19/20/21",
     "APT29 persistence used in both Operation Ghost and SolarWinds; our persistence rules cover only Run keys/tasks"),
    ("T1078", "Valid Accounts", "Windows 4624/4625 + VPN logs",
     "APT29 often skips phishing entirely with password spraying + valid accounts"),
]


def parent(t):
    return t.split(".")[0]


def main():
    group = APT["techniques"]
    camp = {}
    for c in APT["campaigns"]:
        for tid, v in c["techniques"].items():
            camp.setdefault(tid, {"name": v["name"], "tactics": v["tactics"], "campaigns": [],
                                  "procedure": v["procedure"]})
            camp[tid]["campaigns"].append(c["id"])
    allt = {}
    for tid, v in group.items():
        allt[tid] = {**v, "source": "group"}
    for tid, v in camp.items():
        if tid in allt:
            allt[tid]["source"] = "group+campaign"
        else:
            allt[tid] = {"name": v["name"], "tactics": v["tactics"], "procedure": v["procedure"],
                         "references": [], "source": "campaign"}
        allt[tid]["campaigns"] = v["campaigns"]

    plan_t = set()
    for p in PLAN["phases"]:
        plan_t.add(p["technique"])
        plan_t.update(p.get("also", []))
    detected = {t["technique"] for t in W9["tests"] if t["week9"]["status"] == "DETECTED"}
    detected_parents = {parent(t) for t in detected}

    def coverage(tid):
        if tid in detected:
            return "detected"
        if tid in plan_t:
            return "emulated"
        if parent(tid) in detected_parents:
            return "sibling"
        return "gap"

    for tid, v in allt.items():
        v["coverage"] = coverage(tid)

    cov = Counter(v["coverage"] for v in allt.values())
    gcov = Counter(v["coverage"] for t, v in allt.items() if "group" in v["source"])
    plan_in_apt = sorted(t for t in plan_t if t in allt)
    plan_not_apt = sorted(t for t in plan_t if t not in allt)
    a41 = set(A41["techniques"])
    shared = sorted(set(group) & a41)
    jacc = len(shared) / len(set(group) | a41)

    # ---------------- table ----------------
    order = APT["tactic_order"]
    rows = ["| Technique | Tactic(s) | Source | APT29 procedure (ATT&CK v20) | Our coverage |",
            "|---|---|---|---|---|"]
    for tid, v in sorted(allt.items(), key=lambda kv: (min(order.index(t) for t in kv[1]["tactics"]), kv[0])):
        proc = v["procedure"].replace("|", "/")
        proc = proc if len(proc) < 170 else proc[:167] + "..."
        src = v["source"] + (f" ({', '.join(v.get('campaigns', []))})" if v.get("campaigns") else "")
        rows.append(f"| {tid} {v['name']} | {', '.join(LABEL[t] for t in v['tactics'])} | {src} | {proc} | "
                    f"{TEXT[v['coverage']]} |")
    (ROOT / "docs" / "apt29_ttp_table.md").write_text(
        f"# APT29 (G0016) techniques in ATT&CK {APT['attack_version']}\n\n"
        f"{len(allt)} techniques: {len(group)} at group level, {len(camp)} in campaigns "
        f"(C0023 Operation Ghost, C0024 SolarWinds Compromise). Generated by scripts/analyze_apt29.py.\n\n"
        + "\n".join(rows) + "\n", encoding="utf-8")

    # ---------------- figures ----------------
    tactic_counts = {t: Counter() for t in order}
    for v in allt.values():
        for t in v["tactics"]:
            tactic_counts[t][v["coverage"]] += 1
    used = [t for t in order if sum(tactic_counts[t].values())]
    fig, ax = plt.subplots(figsize=(9.5, 5.4))
    left = [0] * len(used)
    for k in ("detected", "sibling", "emulated", "gap"):
        vals = [tactic_counts[t][k] for t in used]
        ax.barh(range(len(used)), vals, left=left, color=COLORS[k], label=TEXT[k], height=0.66)
        left = [a + b for a, b in zip(left, vals)]
    for i, total in enumerate(left):
        ax.text(total + 0.3, i, str(total), va="center", fontsize=9)
    ax.set_yticks(range(len(used)))
    ax.set_yticklabels([LABEL[t] for t in used])
    ax.invert_yaxis()
    ax.set_xlabel("APT29 techniques (group + campaigns; a technique can sit under several tactics)")
    ax.set_title(f"APT29 in ATT&CK {APT['attack_version']}: {len(allt)} techniques by tactic, and our coverage",
                 fontsize=11.5, fontweight="bold", color=INK)
    ax.legend(loc="upper center", bbox_to_anchor=(0.45, -0.1), ncol=2, fontsize=8.5, frameon=False)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    fig.tight_layout()
    fig.savefig(ROOT / "images" / "apt29_tactics.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    chain = [("Delivery", ["T1566.001", "T1566.002", "T1566.003"]),
             ("Evasion of\nmail/Office controls", ["T1027.006", "T1553.005"]),
             ("User execution", ["T1204.002", "T1204.001"]),
             ("Execution", ["T1059.001", "T1218.005", "T1047"]),
             ("Tooling / C2", ["T1105", "T1573", "T1090.003"]),
             ("Persistence", ["T1547.001", "T1053.005", "T1546.003"]),
             ("Staging", ["T1005", "T1560.001"])]
    fig, ax = plt.subplots(figsize=(13, 4.6))
    ax.axis("off")
    ax.set_xlim(0, len(chain))
    ax.set_ylim(-0.4, 4.2)
    for i, (stage, techs) in enumerate(chain):
        ax.text(i + 0.5, 3.85, stage, ha="center", va="center", fontsize=9.5, fontweight="bold", color=INK)
        for j, tid in enumerate(techs):
            v = allt[tid]
            y = 3.0 - j * 1.05
            ax.add_patch(plt.Rectangle((i + 0.06, y - 0.42), 0.88, 0.84, color=COLORS[v["coverage"]], alpha=0.95))
            nm = v["name"].split(": ")[-1]
            nm = "\n".join(textwrap.wrap(nm, 20)[:2])
            ax.text(i + 0.5, y + 0.14, tid, ha="center", color="white", fontsize=9, fontweight="bold")
            ax.text(i + 0.5, y - 0.2, nm, ha="center", va="center", color="white", fontsize=7.4)
        if i < len(chain) - 1:
            ax.annotate("", xy=(i + 1.04, 3.85), xytext=(i + 0.96, 3.85),
                        arrowprops=dict(arrowstyle="->", color="#555"))
    ax.legend(handles=[Patch(color=COLORS[k], label=TEXT[k]) for k in COLORS], loc="lower center",
              bbox_to_anchor=(0.5, -0.12), ncol=4, frameon=False, fontsize=8.3)
    ax.set_title("APT29 spearphishing-to-staging techniques (ATT&CK v20) vs. our emulation and detections",
                 fontsize=11.5, fontweight="bold", color=INK)
    fig.tight_layout()
    fig.savefig(ROOT / "images" / "apt29_initial_access.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    # ---------------- navigator ----------------
    layer = {"name": "Week 10 - APT29 (G0016) TTPs vs project coverage",
             "versions": {"attack": "20", "navigator": "4.9.1", "layer": "4.5"},
             "domain": "enterprise-attack",
             "description": "All APT29 techniques (group + C0023 + C0024). Colour = our coverage after Week 9.",
             "techniques": [{"techniqueID": t, "color": COLORS[v["coverage"]], "enabled": True,
                             "comment": f"{v['source']}: {TEXT[v['coverage']]}"} for t, v in sorted(allt.items())],
             "legendItems": [{"label": TEXT[k], "color": c} for k, c in COLORS.items()]}
    (ROOT / "attack" / "apt29_coverage_layer.json").write_text(json.dumps(layer, indent=2), encoding="utf-8")

    # ---------------- numbers + log ----------------
    initial = sorted(t for t, v in allt.items() if "initial-access" in v["tactics"])
    analysis = {
        "attack_version": APT["attack_version"],
        "apt29": {"group_techniques": len(group), "campaign_techniques": len(camp),
                  "union": len(allt), "software": len(APT["software"]),
                  "campaigns": [f"{c['id']} {c['name']} ({c['first_seen']} - {c['last_seen']})" for c in APT["campaigns"]],
                  "initial_access_techniques": initial},
        "coverage_all": dict(cov), "coverage_group_only": dict(gcov),
        "plan_techniques_used_by_apt29": plan_in_apt, "plan_techniques_not_in_apt29": plan_not_apt,
        "apt41": {"techniques": len(a41), "shared_with_apt29": shared, "jaccard": round(jacc, 3)},
        "next_hunts": [{"technique": a, "name": b, "data_source": c, "why": d} for a, b, c, d in NEXT_HUNTS],
    }
    (ROOT / "docs" / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
    log = [
        f"ATT&CK {APT['attack_version']} - APT29 (G0016), aliases: {', '.join(APT['group']['aliases'][:8])}, ...",
        f"group-level techniques: {len(group)}; campaign techniques: {len(camp)}; union: {len(allt)}; software: {len(APT['software'])}",
        "campaigns: " + "; ".join(analysis["apt29"]["campaigns"]),
        f"initial-access techniques ({len(initial)}): {', '.join(initial)}",
        "",
        f"Week 8 plan techniques used by APT29 (group or campaign): {len(plan_in_apt)}/{len(plan_t)} -> {', '.join(plan_in_apt)}",
        f"Week 8 plan techniques NOT attributed to APT29: {', '.join(plan_not_apt)}",
        "",
        "coverage of all APT29 techniques: " + ", ".join(f"{k}={cov.get(k, 0)}" for k in COLORS),
        "coverage of group-level techniques: " + ", ".join(f"{k}={gcov.get(k, 0)}" for k in COLORS),
        f"share detected or sibling-detected: {(cov['detected'] + cov['sibling']) / len(allt):.1%}",
        "",
        f"APT41 (G0096): {len(a41)} techniques; shared with APT29 group-level: {len(shared)} "
        f"(Jaccard {jacc:.2f}) -> {', '.join(shared)}",
        "",
        "priority hunts for uncovered APT29 techniques (analyst judgement):",
        *[f"  {i + 1}. {a} {b} - {c}" for i, (a, b, c, _) in enumerate(NEXT_HUNTS)],
    ]
    (ROOT / "docs" / "execution_output.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print("\n".join(log))


if __name__ == "__main__":
    main()
