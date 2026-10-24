#!/usr/bin/env python3
"""Convert the Week 7 CAR Sigma rules to Splunk SPL and SQLite WHERE clauses.

Reproduce locally:
    python3 -m pip install "pysigma>=1.5,<2" \
        "pysigma-backend-splunk>=1.1,<2" "pysigma-backend-sqlite>=2.1,<3" \
        "pysigma-pipeline-sysmon>=1,<2" "pysigma-pipeline-windows>=1,<2"
    python3 scripts/convert_rules.py

Outputs (committed so the queries can be read without running the tool):
    queries/<rule>.spl    Splunk search for the group Splunk lab
    queries/<rule>.sql    SQLite WHERE clause used by run_hunt.py
    docs/conversion.json   backend/pipeline versions + generated queries
"""
import json
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.resolver import ProcessingPipelineResolver

ROOT = Path(__file__).resolve().parents[1]
RULES = sorted((ROOT / "rules").glob("*.yml"))
QDIR = ROOT / "queries"
QDIR.mkdir(exist_ok=True)

# Sysmon pipeline maps the generic process_creation fields onto Sysmon's
# EventID 1 channel for the Splunk output; the SQLite store uses plain columns.
splunk_backend = SplunkBackend(processing_pipeline=sysmon_pipeline())
sqlite_backend = sqliteBackend()


def main():
    summary = {"tool": "pySigma", "backends": {"splunk": "pysigma-backend-splunk",
                                               "sqlite": "pysigma-backend-sqlite"},
               "pipeline": "sysmon (Splunk output)", "rules": {}}
    for rule_path in RULES:
        name = rule_path.stem
        collection = SigmaCollection.load_ruleset([rule_path])
        spl = splunk_backend.convert(collection)[0]
        sql = sqlite_backend.convert(collection)[0]
        (QDIR / f"{name}.spl").write_text(
            f"index=win_sysmon source=\"WinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1\n"
            f"| search {spl}\n", encoding="utf-8")
        (QDIR / f"{name}.sql").write_text(sql + "\n", encoding="utf-8")
        summary["rules"][name] = {"spl": spl, "sqlite_where": sql}
        print(f"[{name}]")
        print(f"  SPL   : {spl}")
        print(f"  SQLite: {sql}\n")
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "docs" / "conversion.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote {len(RULES)} rule conversions to queries/ and docs/conversion.json")


if __name__ == "__main__":
    main()
