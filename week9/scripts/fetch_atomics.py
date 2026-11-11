#!/usr/bin/env python3
"""Fetch the Atomic Red Team tests named in the Week 8 plan, pinned to one commit.

Reads ../week8/plan/emulation_plan.yaml, downloads atomics/<T>/<T>.yaml from
redcanaryco/atomic-red-team at a fixed commit, checks each GUID, and writes
atomics/selected_tests.json (committed, so the rest of Week 9 runs offline).

    python3 scripts/fetch_atomics.py
"""
import json
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT.parent / "week8" / "plan" / "emulation_plan.yaml"
OUT = ROOT / "atomics" / "selected_tests.json"
COMMIT = "a0e3f9bc69fed2fd711bd1f1aa87a40c33482fe6"
RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{c}/atomics/{t}/{t}.yaml"


def main():
    plan = yaml.safe_load(PLAN.read_text(encoding="utf-8"))
    cache = {}
    out = {"source": "https://github.com/redcanaryco/atomic-red-team", "commit": COMMIT,
           "license": "MIT (Red Canary)", "plan": plan["plan"]["id"], "tests": []}
    for step in plan["phases"]:
        a = step["atomic"]
        if a["technique"] not in cache:
            url = RAW.format(c=COMMIT, t=a["technique"])
            with urllib.request.urlopen(url, timeout=30) as r:
                cache[a["technique"]] = yaml.safe_load(r.read().decode("utf-8"))
        test = cache[a["technique"]]["atomic_tests"][a["test"] - 1]
        assert test["auto_generated_guid"] == a["guid"], f"GUID mismatch for {a}"
        args = {k: v.get("default") for k, v in (test.get("input_arguments") or {}).items()}
        if "destination_url" in a:
            args["destination_url"] = a["destination_url"]
        out["tests"].append({
            "step": step["id"], "plan_technique": step["technique"], "tactic": step["tactic"],
            "atomic_technique": a["technique"], "test_number": a["test"], "guid": a["guid"],
            "name": test["name"], "executor": test["executor"]["name"],
            "elevation_required": test["executor"].get("elevation_required", False),
            "input_arguments": args,
            "command": test["executor"].get("command", "").strip(),
            "cleanup_command": (test["executor"].get("cleanup_command") or "").strip(),
        })
        print(f"step {step['id']}: {a['technique']} #{a['test']} {test['name']} ({a['guid'][:8]}) OK")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(out['tests'])} tests to {OUT.relative_to(ROOT)} (commit {COMMIT[:10]})")


if __name__ == "__main__":
    main()
