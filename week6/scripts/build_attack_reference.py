#!/usr/bin/env python3
"""Extract the ATT&CK facts used in Week 6 from the official MITRE STIX bundle.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
    cd attack-stix-data && git sparse-checkout set --no-cone /enterprise-attack/enterprise-attack.json
    python3 scripts/build_attack_reference.py /path/to/enterprise-attack.json

The output (data/attack_v20_subset.json) is committed so the rest of the
pipeline runs without downloading the 55 MB bundle.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "attack_v20_subset.json"

TECHNIQUES = [
    "T1566", "T1566.001", "T1204", "T1204.002", "T1059", "T1059.001",
    "T1059.003", "T1027", "T1027.010", "T1071", "T1071.001", "T1105",
    "T1547", "T1547.001", "T1036", "T1036.007", "T1598.002",
]


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def alive(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    objects = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objects}
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    tactics = [
        {"id": ext_id(by_id[t]), "name": by_id[t]["name"], "shortname": by_id[t]["x_mitre_shortname"]}
        for t in matrix["tactic_refs"]
    ]
    techniques = {ext_id(o): o for o in objects if o["type"] == "attack-pattern" and alive(o)}
    rels = [o for o in objects if o["type"] == "relationship" and alive(o)]

    out = {
        "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
        "attack_version": collection.get("x_mitre_version"),
        "tactics": tactics,
        "techniques": {},
    }
    for tid in TECHNIQUES:
        t = techniques[tid]
        stix_id = t["id"]
        groups = sorted(
            by_id[r["source_ref"]]["name"]
            for r in rels
            if r["target_ref"] == stix_id and r["relationship_type"] == "uses"
            and by_id[r["source_ref"]]["type"] == "intrusion-set"
        )
        software = sorted(
            by_id[r["source_ref"]]["name"]
            for r in rels
            if r["target_ref"] == stix_id and r["relationship_type"] == "uses"
            and by_id[r["source_ref"]]["type"] in ("malware", "tool")
        )
        mitigations = sorted(
            f'{ext_id(by_id[r["source_ref"]])} {by_id[r["source_ref"]]["name"]}'
            for r in rels
            if r["target_ref"] == stix_id and r["relationship_type"] == "mitigates"
        )
        strategies = []
        for r in rels:
            if r["target_ref"] == stix_id and r["relationship_type"] == "detects":
                s = by_id[r["source_ref"]]
                analytics = []
                for aref in s.get("x_mitre_analytic_refs", []):
                    a = by_id[aref]
                    logs = [
                        {
                            "data_component": by_id[l["x_mitre_data_component_ref"]]["name"],
                            "log_source": l.get("name"),
                            "channel": l.get("channel"),
                        }
                        for l in a.get("x_mitre_log_source_references", [])
                    ]
                    analytics.append({
                        "id": ext_id(a),
                        "platforms": a.get("x_mitre_platforms"),
                        "description": a.get("description", "").strip(),
                        "log_sources": logs,
                    })
                strategies.append({"id": ext_id(s), "name": s["name"], "analytics": analytics})
        out["techniques"][tid] = {
            "name": t["name"],
            "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
            "platforms": t.get("x_mitre_platforms"),
            "version": t.get("x_mitre_version"),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "description_first_paragraph": t.get("description", "").split("\n\n")[0],
            "groups": groups,
            "software_count": len(software),
            "mitigations": mitigations,
            "detection_strategies": strategies,
        }
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"ATT&CK {out['attack_version']}: wrote {len(out['techniques'])} techniques to {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
