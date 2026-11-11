#!/usr/bin/env python3
"""Extract the APT29 (G0016) TTP profile - and APT41 (G0096) for comparison - from
the official MITRE ATT&CK STIX bundle.

Usage:
    git clone --depth 1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data.git
    cd attack-stix-data && git sparse-checkout set --no-cone /enterprise-attack/enterprise-attack.json
    python3 scripts/build_apt_profile.py /path/to/enterprise-attack.json

Writes data/apt29_profile.json and data/apt41_techniques.json (committed so the
analysis runs offline). Group-level and campaign-level ("attributed-to")
technique use are kept apart, because ATT&CK records them separately.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack",):
            return ref.get("external_id")
    return None


def alive(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def clean(text):
    text = re.sub(r"\(Citation: [^)]+\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\(https://attack\.mitre\.org/[^)]+\)", r"\1", text)
    return " ".join(text.split())


def citations(rel, by_ref):
    out = []
    for r in rel.get("external_references", []):
        if r.get("source_name") and r.get("url"):
            out.append({"source": r["source_name"], "url": r["url"]})
    return out


def techniques_used(src_id, objects, by_id, rels):
    out = {}
    for r in rels:
        if r["source_ref"] == src_id and r["relationship_type"] == "uses" and r["target_ref"].startswith("attack-pattern"):
            t = by_id.get(r["target_ref"])
            if not t or not alive(t):
                continue
            tid = ext_id(t)
            out[tid] = {
                "name": t["name"] if "." not in tid else
                f'{by_id_name(tid, objects)}: {t["name"]}',
                "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                "procedure": clean(r.get("description")),
                "references": citations(r, by_id),
            }
    return out


_names = {}


def by_id_name(tid, objects):
    parent = tid.split(".")[0]
    if not _names:
        for o in objects:
            if o["type"] == "attack-pattern" and alive(o):
                _names[ext_id(o)] = o["name"]
    return _names.get(parent, parent)


def software_used(src_id, by_id, rels):
    sw = set()
    for r in rels:
        if r["source_ref"] == src_id and r["relationship_type"] == "uses" and r["target_ref"].startswith(("malware", "tool")):
            s = by_id[r["target_ref"]]
            sw.add(f'{ext_id(s)} {s["name"]}')
    return sorted(sw)


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    objects = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objects}
    rels = [o for o in objects if o["type"] == "relationship" and alive(o)]
    collection = next(o for o in objects if o["type"] == "x-mitre-collection")
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix")
    groups = {ext_id(o): o for o in objects if o["type"] == "intrusion-set"}

    g = groups["G0016"]
    campaigns = []
    for r in rels:
        if r["relationship_type"] == "attributed-to" and r["target_ref"] == g["id"]:
            c = by_id[r["source_ref"]]
            campaigns.append({
                "id": ext_id(c), "name": c["name"],
                "first_seen": c.get("first_seen", "")[:10], "last_seen": c.get("last_seen", "")[:10],
                "description": clean(c.get("description")).split(". ")[0] + ".",
                "techniques": techniques_used(c["id"], objects, by_id, rels),
                "software": software_used(c["id"], by_id, rels),
            })
    profile = {
        "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
        "attack_version": collection.get("x_mitre_version"),
        "tactic_order": [by_id[t]["x_mitre_shortname"] for t in matrix["tactic_refs"]],
        "tactic_names": {by_id[t]["x_mitre_shortname"]: by_id[t]["name"] for t in matrix["tactic_refs"]},
        "group": {"id": "G0016", "name": g["name"], "aliases": g.get("aliases", []),
                  "description": clean(g.get("description"))},
        "techniques": techniques_used(g["id"], objects, by_id, rels),
        "software": software_used(g["id"], by_id, rels),
        "campaigns": sorted(campaigns, key=lambda c: c["first_seen"]),
    }
    DATA.mkdir(exist_ok=True)
    (DATA / "apt29_profile.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    a41 = groups["G0096"]
    (DATA / "apt41_techniques.json").write_text(json.dumps({
        "attack_version": profile["attack_version"], "group": {"id": "G0096", "name": a41["name"],
                                                                "aliases": a41.get("aliases", [])},
        "techniques": {k: {"name": v["name"], "tactics": v["tactics"]}
                       for k, v in techniques_used(a41["id"], objects, by_id, rels).items()},
    }, indent=2, ensure_ascii=False), encoding="utf-8")
    camp = sum(len(c["techniques"]) for c in campaigns)
    print(f"ATT&CK {profile['attack_version']}: APT29 {len(profile['techniques'])} group techniques, "
          f"{len(profile['software'])} software, {len(campaigns)} campaigns ({camp} campaign technique uses)")


if __name__ == "__main__":
    main()
