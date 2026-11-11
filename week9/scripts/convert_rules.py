#!/usr/bin/env python3
"""Convert the Week 9 Sigma rules (Week 7 CAR rules + new Week 9 rules) to SPL and SQLite.

    python3 -m pip install pysigma pysigma-backend-splunk pysigma-backend-sqlite pysigma-pipeline-sysmon
    python3 scripts/convert_rules.py

The Sysmon pipeline is applied to BOTH backends so every query carries its
Sysmon EventID (1 process, 3 network, 11 file, 13 registry), which is what lets
one table hold all event types in run_siem.py.

Outputs: queries/<rule>.spl, queries/<rule>.sql, docs/conversion.json
"""
import json
from importlib.metadata import version
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").glob("*.yml"))
QDIR = ROOT / "queries"
QDIR.mkdir(exist_ok=True)


def main():
    splunk = SplunkBackend(processing_pipeline=sysmon_pipeline())
    sqlite = sqliteBackend(processing_pipeline=sysmon_pipeline())
    summary = {"tool": "pySigma", "versions": {p: version(p) for p in (
        "pySigma", "pysigma-backend-splunk", "pySigma-backend-sqlite", "pysigma-pipeline-sysmon")},
        "pipeline": "sysmon (both backends)", "rules": {}}
    for path in RULES:
        coll = SigmaCollection.load_ruleset([path])
        spl = splunk.convert(coll)[0]
        sql = sqlite.convert(coll)[0]
        (QDIR / f"{path.stem}.spl").write_text(
            'index=win_sysmon source="WinEventLog:Microsoft-Windows-Sysmon/Operational"\n'
            f"| search {spl}\n", encoding="utf-8")
        (QDIR / f"{path.stem}.sql").write_text(sql + "\n", encoding="utf-8")
        rule = coll.rules[0]
        summary["rules"][path.stem] = {"title": rule.title, "level": str(rule.level.name).lower(),
                                       "tags": [str(t) for t in rule.tags], "spl": spl, "sqlite": sql}
        print(f"[{path.stem}]\n  SPL   : {spl}\n  SQLite: {sql}\n")
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "conversion.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"converted {len(RULES)} rules")


if __name__ == "__main__":
    main()
