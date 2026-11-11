#!/usr/bin/env python3
"""Load the Atomic run telemetry into a SQLite 'SIEM', execute every converted rule,
and score each Atomic test as detected / partial / missed.

Attribution works the way it does in a real purple-team exercise: a match is
assigned to the Atomic step whose UTC window (data/run_log.csv) contains it.
The `_truth` label is used only to tell WHAT matched (technique event, test
proxy, Invoke-AtomicRedTeam harness or benign baseline); the queries never see it.

    python3 scripts/run_siem.py          # stdlib only

Outputs: docs/test_results.json, docs/detection_matrix.md, docs/execution_output.txt
"""
import csv
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "data" / "atomic_run_telemetry.ndjson"
RUNLOG = ROOT / "data" / "run_log.csv"
TESTS = json.loads((ROOT / "atomics" / "selected_tests.json").read_text(encoding="utf-8"))["tests"]
QDIR = ROOT / "queries"
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)


def load(conn):
    rows = [json.loads(l) for l in EVENTS.read_text(encoding="utf-8").splitlines() if l.strip()]
    cols = sorted({k for r in rows for k in r} - {"EventID"})
    conn.execute("CREATE TABLE logs (rowid_ INTEGER PRIMARY KEY, EventID INTEGER, "
                 + ", ".join(f'"{c}" TEXT' for c in cols) + ")")
    for r in rows:
        keys = ["EventID", *[c for c in cols if c in r]]
        conn.execute(f"INSERT INTO logs ({', '.join(chr(34) + k + chr(34) for k in keys)}) "
                     f"VALUES ({', '.join('?' * len(keys))})",
                     [r["EventID"], *[str(r[c]) for c in keys[1:]]])
    return len(rows)


def windows():
    with RUNLOG.open(encoding="utf-8") as f:
        return [(int(r["step"]), r["start_utc"], r["end_utc"]) for r in csv.DictReader(f)]


def step_of(t, wins):
    for s, a, b in wins:
        if a <= t <= b:
            return s
    return None


def status(hits):
    if hits["technique"]:
        return "DETECTED"
    if hits["proxy"]:
        return "PARTIAL"
    return "MISSED"


def main():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    n = load(conn)
    wins = windows()
    log = [f"Loaded {n} events into SQLite table 'logs'; {len(wins)} Atomic step windows from run_log.csv", ""]
    rules = {}
    for q in sorted(QDIR.glob("*.sql")):
        sql = q.read_text(encoding="utf-8").strip().rstrip(";")
        res = conn.execute(sql).fetchall()
        per = {"rows": len(res), "by_step": {}, "false_positives": [], "harness_hits": 0}
        for r in res:
            s = step_of(r["UtcTime"], wins)
            truth = r["_truth"]
            if s is None or truth == "baseline":
                per["false_positives"].append(f'{r["Computer"]} {r["UtcTime"]} {r["Image"]}')
                continue
            d = per["by_step"].setdefault(s, {"technique": 0, "proxy": 0, "harness": 0})
            d[truth] += 1
            per["harness_hits"] += truth == "harness"
        rules[q.stem] = per
        log.append(f"[{q.stem}] rows={len(res)} steps={sorted(per['by_step'])} "
                   f"harness_hits={per['harness_hits']} false_positives={len(per['false_positives'])}")
        for fp in per["false_positives"]:
            log.append(f"    FP: {fp}")

    sets = {"week7": [r for r in rules if r.startswith("w7_")], "week9": list(rules)}
    tests = []
    for t in TESTS:
        s = t["step"]
        entry = {"step": s, "technique": t["plan_technique"], "atomic": f'{t["atomic_technique"]} #{t["test_number"]}',
                 "guid": t["guid"], "name": t["name"]}
        for name, members in sets.items():
            agg = {"technique": 0, "proxy": 0, "harness": 0}
            by = []
            for r in members:
                d = rules[r]["by_step"].get(s)
                if d:
                    for k in agg:
                        agg[k] += d[k]
                    if d["technique"] or d["proxy"]:
                        by.append(r)
            entry[name] = {"status": status(agg), "rules": by, "harness_only": not by and agg["harness"] > 0}
        tests.append(entry)

    log.append("")
    log.append(f"{'step':<5}{'technique':<11}{'week7 rule set':<19}{'week7+week9 rule set':<22}detected by")
    for e in tests:
        w7 = e["week7"]["status"] + (" (harness)" if e["week7"]["harness_only"] else "")
        log.append(f"{e['step']:<5}{e['technique']:<11}{w7:<19}{e['week9']['status']:<22}{', '.join(e['week9']['rules'])}")
    summary = {}
    for name in sets:
        c = {k: sum(e[name]["status"] == k for e in tests) for k in ("DETECTED", "PARTIAL", "MISSED")}
        fps = sum(len(rules[r]["false_positives"]) for r in sets[name])
        summary[name] = {**c, "false_positives": fps, "rules": len(sets[name])}
        log.append(f"{name} rule set ({len(sets[name])} rules): {c['DETECTED']} detected, {c['PARTIAL']} partial, "
                   f"{c['MISSED']} missed of {len(tests)} tests; {fps} false positives on baseline")

    (DOCS / "test_results.json").write_text(json.dumps({"summary": summary, "tests": tests, "rules": rules},
                                                       indent=2), encoding="utf-8")
    md = ["| Step | Technique | Atomic test | Week 7 rules | Week 7 + Week 9 rules | Detected by |",
          "|---|---|---|---|---|---|"]
    for e in tests:
        w7 = e["week7"]["status"] + (" (harness only)" if e["week7"]["harness_only"] else "")
        md.append(f"| {e['step']} | {e['technique']} | {e['atomic']} {e['name']} | {w7} | {e['week9']['status']} | "
                  f"{', '.join('`' + r + '`' for r in e['week9']['rules'])} |")
    (DOCS / "detection_matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (DOCS / "execution_output.txt").write_text("\n".join(log) + "\n", encoding="utf-8")
    print("\n".join(log))


if __name__ == "__main__":
    main()
