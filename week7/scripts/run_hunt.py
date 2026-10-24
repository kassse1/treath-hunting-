#!/usr/bin/env python3
"""Execute the Week 7 CAR analytics against a local SQLite log store.

This actually runs the SQLite queries that convert_rules.py generated from the
Sigma rules. It builds an in-process database from the Sysmon-schema endpoint
telemetry, loads each committed queries/*.sql, runs it, and records the matching
hosts. Nothing here touches a network or starts a process.

Pipeline:  rules/*.yml  --pySigma-->  queries/*.sql  --(this script)-->  results

Outputs:
    docs/hunt_results.json      matches per analytic (raw vs tuned)
    docs/execution_output.txt   run log with row counts and matched hosts
"""
import json
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "data" / "endpoint_events.ndjson"
QDIR = ROOT / "queries"
DOCS = ROOT / "docs"
DOCS.mkdir(exist_ok=True)

# Columns the Sigma process_creation field names map to (Sysmon EventID 1).
COLUMNS = ["EventID", "UtcTime", "Computer", "Image", "CommandLine",
           "ParentImage", "ParentCommandLine", "User", "ProcessId"]

RUN_ORDER = [
    ("car_2014_04_003_powershell", "CAR-2014-04-003 raw (PowerShell not from explorer)"),
    ("car_2014_04_003_powershell_tuned", "CAR-2014-04-003 tuned (Office + encoded)"),
    ("car_2013_02_003_cmd_parent", "CAR-2013-02-003 tuned (cmd from Office/reader)"),
]


def build_db(conn):
    conn.execute(f"CREATE TABLE logs ({', '.join(c + ' TEXT' for c in COLUMNS)})")
    rows = 0
    for line in EVENTS.read_text().splitlines():
        e = json.loads(line)
        if e.get("EventID") != 1:          # process_creation analytics only read EventID 1
            continue
        conn.execute(
            f"INSERT INTO logs ({', '.join(COLUMNS)}) VALUES ({', '.join('?' for _ in COLUMNS)})",
            [str(e.get(c, "")) for c in COLUMNS])
        rows += 1
    conn.commit()
    return rows


def main():
    conn = sqlite3.connect(":memory:")
    indexed = build_db(conn)

    results = {}
    log = ["Week 7 CAR analytics execution (SQLite log store)",
           "=" * 60,
           f"EventID=1 process-creation records indexed: {indexed}", ""]

    for name, label in RUN_ORDER:
        sql = (QDIR / f"{name}.sql").read_text().strip()
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description]
        matched = [dict(zip(cols, r)) for r in cur.fetchall()]
        hosts = sorted({m["Computer"] for m in matched})
        results[name] = {
            "label": label,
            "sql": sql,
            "rows": len(matched),
            "hosts": hosts,
            "matches": [{"Computer": m["Computer"], "ParentImage": m["ParentImage"].rsplit("\\", 1)[-1],
                         "Image": m["Image"].rsplit("\\", 1)[-1],
                         "CommandLine": m["CommandLine"]} for m in matched],
        }
        log.append(f"[{name}]  {label}")
        log.append(f"    rows: {len(matched)}   hosts: {', '.join(hosts) or 'none'}")
        for m in matched:
            log.append(f"      {m['Computer']}: {m['ParentImage'].rsplit(chr(92),1)[-1]} -> "
                       f"{m['Image'].rsplit(chr(92),1)[-1]}  | {m['CommandLine']}")
        log.append("")

    log.append("Interpretation")
    log.append("-" * 60)
    log.append("Raw CAR-2014-04-003 flags every non-interactive PowerShell (FIN-WS01, FIN-WS03,")
    log.append("FIN-WS04) - three hosts, including the approved automation on FIN-WS03. The tuned")
    log.append("variant adds Office parent + encoded command and keeps only FIN-WS01 and FIN-WS04,")
    log.append("removing the benign automation. FIN-WS04 still needs the Week 6 process-correlation")
    log.append("step (its egress belonged to a different process) to be dismissed. CAR-2013-02-003")
    log.append("returns no rows here because the simulated chain used PowerShell, not cmd.exe; it is")
    log.append("retained as coverage for the Office->cmd->PowerShell variant.")

    out = "\n".join(log)
    (DOCS / "execution_output.txt").write_text(out, encoding="utf-8")
    (DOCS / "hunt_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
