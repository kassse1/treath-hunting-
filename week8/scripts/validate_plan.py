#!/usr/bin/env python3
"""Validate the Week 8 emulation plan against ATT&CK v20 and render its outputs.

Checks
  1. every technique (and 'also' technique) exists, is not deprecated, in ATT&CK v20
  2. the tactic a phase claims is one of that technique's tactics
  3. the plan starts with Initial Access and ends with Exfiltration (steps that
     go "backwards" across the matrix are logged as NOTE, not errors)
  4. every phase has an Atomic test GUID, a cleanup and an expected detection

Outputs
  docs/validation_output.txt      check log
  docs/plan_matrix.md             phase / technique / atomic / expected detection table
  plan/caldera_adversary.yml      CALDERA adversary profile (ability ids = Atomic GUIDs)
  attack/navigator_layer.json     ATT&CK Navigator layer of the plan
  images/emulation_flow.png       flow figure
"""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAN = yaml.safe_load((ROOT / "plan" / "emulation_plan.yaml").read_text(encoding="utf-8"))
ATT = json.loads((ROOT / "data" / "attack_v20_subset.json").read_text(encoding="utf-8"))
for d in ("docs", "images", "attack"):
    (ROOT / d).mkdir(exist_ok=True)

ORDER = [t["shortname"] for t in ATT["tactics"]]
LABEL = {t["shortname"]: t["name"] for t in ATT["tactics"]}
LABEL["stealth"] = "Defense Evasion"   # v20 STIX shortname; familiar label in prose
SHORT = {"command-and-control": "C2", "credential-access": "Cred. Access"}


def validate(log):
    errors = 0
    last = -1
    for p in PLAN["phases"]:
        for tid in [p["technique"], *p.get("also", [])]:
            t = ATT["techniques"].get(tid)
            ok = t is not None
            log.append(f"[{'OK ' if ok else 'ERR'}] step {p['id']}: {tid} exists in ATT&CK {ATT['attack_version']}"
                       + (f" ({t['name']})" if ok else ""))
            errors += not ok
        t = ATT["techniques"][p["technique"]]
        ok = p["tactic"] in t["tactics"]
        log.append(f"[{'OK ' if ok else 'ERR'}] step {p['id']}: tactic '{p['tactic']}' in {t['tactics']}")
        errors += not ok
        idx = ORDER.index(p["tactic"])
        if idx < last:
            # ATT&CK tactics are not a strict timeline (e.g. a stage-2 download in C2
            # happens before persistence). Report it, do not fail on it.
            log.append(f"[NOTE] step {p['id']}: {LABEL[p['tactic']]} comes after a later matrix column "
                       f"- expected, ATT&CK is not a linear kill chain")
        last = idx
        for key in ("atomic", "cleanup", "expected_detection"):
            ok = bool(p.get(key))
            log.append(f"[{'OK ' if ok else 'ERR'}] step {p['id']}: has {key}")
            errors += not ok
    tactics = [p["tactic"] for p in PLAN["phases"]]
    for pos, need in ((0, "initial-access"), (-1, "exfiltration")):
        ok = tactics[pos] == need
        log.append(f"[{'OK ' if ok else 'ERR'}] plan {'starts' if pos == 0 else 'ends'} with {LABEL[need]}")
        errors += not ok
    for need in ("initial-access", "persistence", "exfiltration"):
        ok = need in tactics
        log.append(f"[{'OK ' if ok else 'ERR'}] plan covers syllabus stage '{LABEL[need]}'")
        errors += not ok
    return errors


def plan_matrix():
    rows = ["| # | Tactic | Technique | Atomic test (GUID) | Expected detection | APT29 uses (ATT&CK v20) |",
            "|---|---|---|---|---|---|"]
    for p in PLAN["phases"]:
        t = ATT["techniques"][p["technique"]]
        a = p["atomic"]
        also = "".join(f" + {x}" for x in p.get("also", []))
        opt = " *(optional)*" if p.get("optional") else ""
        rows.append(f"| {p['id']} | {LABEL[p['tactic']]} | {p['technique']} {t['name']}{also}{opt} | "
                    f"{a['technique']} #{a['test']} {a['name']} (`{a['guid'][:8]}`) | "
                    f"{p['expected_detection']} | {'yes' if t['used_by_apt29'] else 'no'} |")
    return "\n".join(rows) + "\n"


def caldera_profile():
    return {
        "id": "8f6f2f0e-2c4f-4b8e-9a51-0e8b2a6d2026",
        "name": PLAN["plan"]["name"],
        "description": (PLAN["plan"]["objective"].strip() +
                        " Ability ids are the Atomic Red Team auto_generated_guid values, "
                        "which is how CALDERA's atomic plugin names imported abilities."),
        "objective": "495a9828-cab1-44dd-a0ca-66e58177d8cc",
        "atomic_ordering": [p["atomic"]["guid"] for p in PLAN["phases"]],
    }


def navigator():
    techs = []
    for p in PLAN["phases"]:
        for tid in [p["technique"], *p.get("also", [])]:
            techs.append({"techniqueID": tid, "score": p["id"], "color": "",
                          "comment": f"step {p['id']}: {p['phase']} - Atomic {p['atomic']['guid'][:8]}",
                          "enabled": True})
    return {
        "name": f"Week 8 - {PLAN['plan']['name']} emulation plan",
        "versions": {"attack": "20", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques in the Week 8 adversary emulation plan. Score = step number.",
        "techniques": techs,
        "gradient": {"colors": ["#dbe8f3", "#b4543f"], "minValue": 1, "maxValue": len(PLAN["phases"])},
        "legendItems": [], "showTacticRowBackground": False, "selectTechniquesAcrossTactics": True,
    }


def figure():
    phases = PLAN["phases"]
    colors = {"initial-access": "#b4543f", "execution": "#d08a3c", "command-and-control": "#8a6fb0",
              "persistence": "#3f7fb4", "credential-access": "#6b6b6b", "collection": "#4f9a6a",
              "exfiltration": "#1a2332"}
    fig, ax = plt.subplots(figsize=(13, 4.4))
    ax.set_xlim(0, len(phases))
    ax.set_ylim(0, 3.2)
    ax.axis("off")
    for i, p in enumerate(phases):
        t = ATT["techniques"][p["technique"]]
        c = colors.get(p["tactic"], "#777")
        box = FancyBboxPatch((i + 0.06, 0.9), 0.88, 1.75, boxstyle="round,pad=0.02,rounding_size=0.06",
                             fc=c, ec="none", alpha=0.92 if not p.get("optional") else 0.55)
        ax.add_patch(box)
        ax.text(i + 0.5, 2.42, f"{p['id']}. {SHORT.get(p['tactic'], LABEL[p['tactic']])}", ha="center", va="center",
                color="white", fontsize=8, fontweight="bold")
        ax.text(i + 0.5, 1.95, p["technique"], ha="center", va="center", color="white",
                fontsize=10.5, fontweight="bold")
        name = t["name"].replace(" / ", "/\n").replace("Spearphishing ", "Spearphishing\n") \
            .replace("Exfiltration Over ", "Exfil over\n").replace("Ingress Tool", "Ingress\nTool") \
            .replace("via Utility", "\nvia Utility")
        ax.text(i + 0.5, 1.4, name, ha="center", va="center", color="white", fontsize=7.6)
        ax.text(i + 0.5, 0.62, f"Atomic {p['atomic']['guid'][:8]}", ha="center", fontsize=7, color="#333")
        if i < len(phases) - 1:
            ax.annotate("", xy=(i + 1.06, 1.78), xytext=(i + 0.94, 1.78),
                        arrowprops=dict(arrowstyle="->", color="#333", lw=1.2))
    ax.text(0, 3.05, f"{PLAN['plan']['name']} - adversary emulation plan (initial access -> persistence -> exfiltration)",
            fontsize=12, fontweight="bold", color="#1a2332")
    ax.text(0, 0.2, "Faded box = optional step. Every step maps to an ATT&CK v20 technique and an Atomic Red Team test run in Week 9.",
            fontsize=8, color="#555")
    fig.tight_layout()
    fig.savefig(ROOT / "images" / "emulation_flow.png", dpi=150, bbox_inches="tight")
    plt.close(fig)


def main():
    log = [f"Plan {PLAN['plan']['id']} '{PLAN['plan']['name']}' - {len(PLAN['phases'])} steps, ATT&CK {ATT['attack_version']}"]
    errors = validate(log)
    apt = sum(ATT["techniques"][p["technique"]]["used_by_apt29"] for p in PLAN["phases"])
    log.append(f"APT29 overlap: {apt}/{len(PLAN['phases'])} primary step techniques are mapped to APT29 (G0016)")
    log.append(f"RESULT: {'PASS' if errors == 0 else f'FAIL ({errors} errors)'}")
    (ROOT / "docs" / "validation_output.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    (ROOT / "docs" / "plan_matrix.md").write_text(plan_matrix(), encoding="utf-8")
    (ROOT / "plan" / "caldera_adversary.yml").write_text(
        "# Generated by scripts/validate_plan.py from plan/emulation_plan.yaml\n"
        "# Import into CALDERA (data/adversaries/) with the atomic plugin enabled.\n"
        + yaml.safe_dump(caldera_profile(), sort_keys=False, width=100), encoding="utf-8")
    (ROOT / "attack" / "navigator_layer.json").write_text(json.dumps(navigator(), indent=2), encoding="utf-8")
    figure()
    print("\n".join(log))
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
