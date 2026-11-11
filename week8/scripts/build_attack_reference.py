#!/usr/bin/env python3
"""Extract the ATT&CK v20 facts for every technique in the Week 8 emulation plan.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
    cd attack-stix-data && git sparse-checkout set --no-cone /enterprise-attack/enterprise-attack.json
    python3 scripts/build_attack_reference.py /path/to/enterprise-attack.json

Writes data/attack_v20_subset.json (committed, so validate_plan.py runs offline).
"""
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "plan" / "emulation_plan.yaml"
OUT = ROOT / "data" / "attack_v20_subset.json"


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def alive(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def plan_techniques():
    plan = yaml.safe_load(PLAN.read_text(encoding="utf-8"))
    ids = set()
    for p in plan["phases"]:
        ids.add(p["technique"])
        ids.update(p.get("also", []))
        ids.add(p["atomic"]["technique"])
    return sorted(ids)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    objects = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objects}
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    techniques = {ext_id(o): o for o in objects if o["type"] == "attack-pattern" and alive(o)}
    rels = [o for o in objects if o["type"] == "relationship" and alive(o)]
    out = {
        "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
        "attack_version": collection.get("x_mitre_version"),
        "tactics": [{"id": ext_id(by_id[t]), "name": by_id[t]["name"],
                     "shortname": by_id[t]["x_mitre_shortname"]} for t in matrix["tactic_refs"]],
        "techniques": {},
    }
    for tid in plan_techniques():
        t = techniques[tid]
        groups = sorted(by_id[r["source_ref"]]["name"] for r in rels
                        if r["target_ref"] == t["id"] and r["relationship_type"] == "uses"
                        and by_id[r["source_ref"]]["type"] == "intrusion-set")
        mitigations = sorted(f'{ext_id(by_id[r["source_ref"]])} {by_id[r["source_ref"]]["name"]}'
                             for r in rels if r["target_ref"] == t["id"]
                             and r["relationship_type"] == "mitigates")
        strategies = sorted(f'{ext_id(by_id[r["source_ref"]])} {by_id[r["source_ref"]]["name"]}'
                            for r in rels if r["target_ref"] == t["id"]
                            and r["relationship_type"] == "detects")
        out["techniques"][tid] = {
            "name": t["name"],
            "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "group_count": len(groups),
            "used_by_apt29": "APT29" in groups,
            "mitigations": mitigations,
            "detection_strategies": strategies,
        }
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"ATT&CK {out['attack_version']}: wrote {len(out['techniques'])} techniques to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
