#!/usr/bin/env python3
"""Week 6 hunt: correlate mail + endpoint telemetry and map to ATT&CK v20.

Reads the deterministic telemetry produced by generate_telemetry.py, applies
the detection logic described in the report, and emits:
  docs/hunt_results.json          machine-readable findings per host
  docs/execution_output.txt       human-readable run log
  attack/navigator_layer.json     MITRE ATT&CK Navigator layer for the chain
  data/attack_chain.csv           observed-step -> ATT&CK technique table

The ATT&CK facts (names, tactics, URLs) are read from the committed subset
data/attack_v20_subset.json, which was extracted from the official STIX bundle
by build_attack_reference.py. Nothing here executes code or touches a network.
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACK = json.loads((ROOT / "data" / "attack_v20_subset.json").read_text())
MAIL = [json.loads(l) for l in (ROOT / "data" / "mail_events.ndjson").read_text().splitlines()]
ENDP = [json.loads(l) for l in (ROOT / "data" / "endpoint_events.ndjson").read_text().splitlines()]

OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe")
INTERPRETERS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe")
ENCODED_FLAGS = (" -enc ", " -enc", "-encodedcommand", " -e ")
DOC_IP_RANGES = ("203.0.113.", "198.51.100.", "192.0.2.")  # RFC 5737


def base(path):
    return path.rsplit("\\", 1)[-1].lower()


def is_encoded(cmd):
    c = " " + cmd.lower() + " "
    return any(f in c for f in ENCODED_FLAGS)


def is_external(ip):
    return ip.startswith(("203.0.113.", "198.51.100."))  # documentation "internet"


def hunt():
    log = []
    hosts = {}

    # Index endpoint events by host
    by_host = {}
    for e in ENDP:
        by_host.setdefault(e["Computer"], []).append(e)

    for host, events in sorted(by_host.items()):
        procs = [e for e in events if e["EventID"] == 1]
        files = [e for e in events if e["EventID"] == 11]
        nets = [e for e in events if e["EventID"] == 3]

        finding = {"host": host, "signals": [], "techniques": [], "disposition": None, "notes": ""}

        # Signal 1: suspicious inbound mail delivered to this host's user
        mail = [m for m in MAIL if m["labels"]["host"] == host]
        bad_mail = [m for m in mail if m["mail"]["dmarc"] == "fail" or m["mail"]["spf"] == "fail"]
        if bad_mail:
            att = bad_mail[0]["mail"].get("attachment")
            finding["signals"].append(
                f"inbound mail failed SPF/DMARC from {bad_mail[0]['mail']['from']}"
                + (f", attachment {att['name']}" if att else ""))
            finding["techniques"].append("T1566.001")

        # Signal 2: Office app wrote a document to a user-writable path
        for f in files:
            if base(f["Image"]) in OFFICE and any(
                    seg in f["TargetFilename"] for seg in ("\\Downloads\\", "\\Temp\\", "\\Desktop\\")):
                finding["signals"].append(f"Office wrote {base(f['TargetFilename'])} to a user path")

        # Signal 3: Office parent spawned an interpreter (user execution -> exec)
        office_children = [p for p in procs
                           if base(p.get("ParentImage", "")) in OFFICE
                           and base(p["Image"]) in INTERPRETERS]
        for p in office_children:
            finding["signals"].append(
                f"{base(p['ParentImage'])} spawned {base(p['Image'])} (pid {p['ProcessId']})")
            finding["techniques"] += ["T1204.002"]
            if base(p["Image"]) in ("powershell.exe", "pwsh.exe"):
                finding["techniques"].append("T1059.001")
            elif base(p["Image"]) == "cmd.exe":
                finding["techniques"].append("T1059.003")
            if is_encoded(p["CommandLine"]):
                finding["signals"].append("  -> encoded command argument present")
                finding["techniques"].append("T1027.010")

        # Signal 4: correlated egress from the SAME interpreter process guid
        encoded_office_procs = [p for p in office_children
                                if base(p["Image"]) in ("powershell.exe", "pwsh.exe")
                                and is_encoded(p["CommandLine"])]
        correlated = []
        for p in encoded_office_procs:
            for n in nets:
                if n.get("ProcessGuid") == p.get("ProcessGuid") and is_external(n["DestinationIp"]):
                    correlated.append((p, n))
        for p, n in correlated:
            finding["signals"].append(
                f"  -> same process {p['ProcessId']} connected out to "
                f"{n['DestinationHostname']} ({n['DestinationIp']}:{n['DestinationPort']})")
            finding["techniques"] += ["T1071.001"]

        # Disposition
        tset = set(finding["techniques"])
        if {"T1566.001", "T1204.002", "T1059.001", "T1027.010", "T1071.001"} <= tset:
            finding["disposition"] = "SUSPICIOUS - full delivery-to-C2 chain, investigate"
        elif encoded_office_procs and not correlated:
            finding["disposition"] = "PARTIAL - encoded Office PowerShell but no correlated egress (control)"
            finding["notes"] = "outbound traffic belongs to a different process; host-only joins would over-match"
        elif office_children and not encoded_office_procs:
            finding["disposition"] = "BENIGN MATCH - Office spawned PowerShell, no encoding, internal destination"
            finding["notes"] = "approved reporting automation; would be a false positive if alerted blindly"
        else:
            finding["disposition"] = "BENIGN - no Office->interpreter execution chain"

        finding["techniques"] = sorted(tset, key=lambda t: (len(t), t))
        hosts[host] = finding

    return hosts


def write_outputs(hosts):
    (ROOT / "docs").mkdir(exist_ok=True)
    (ROOT / "attack").mkdir(exist_ok=True)

    (ROOT / "docs" / "hunt_results.json").write_text(
        json.dumps(hosts, indent=2), encoding="utf-8")

    lines = ["Week 6 hunt execution log", "=" * 60, ""]
    for host, f in hosts.items():
        lines.append(f"[{host}] {f['disposition']}")
        for s in f["signals"]:
            lines.append(f"    - {s}")
        lines.append(f"    techniques: {', '.join(f['techniques']) or 'none'}")
        if f["notes"]:
            lines.append(f"    note: {f['notes']}")
        lines.append("")
    out = "\n".join(lines)
    (ROOT / "docs" / "execution_output.txt").write_text(out, encoding="utf-8")
    print(out)

    # ATT&CK chain CSV for the suspicious host, in attack order
    chain_order = ["T1566.001", "T1204.002", "T1059.001", "T1027.010", "T1071.001"]
    with (ROOT / "data" / "attack_chain.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["order", "technique_id", "name", "tactic", "observed_on_FIN-WS01"])
        for i, tid in enumerate(chain_order, 1):
            t = ATTACK["techniques"][tid]
            w.writerow([i, tid, t["name"], ",".join(t["tactics"]), "yes"])

    # Navigator layer
    seen = {}
    for f in hosts.values():
        for tid in f["techniques"]:
            seen[tid] = seen.get(tid, 0) + 1
    techniques_layer = []
    for tid, count in seen.items():
        techniques_layer.append({
            "techniqueID": tid,
            "score": count,
            "comment": ATTACK["techniques"][tid]["name"],
            "color": "",
            "enabled": True,
        })
    layer = {
        "name": "Week 6 - Spearphishing simulation (synthetic)",
        "versions": {"attack": "20", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": ("Techniques observed in the Week 6 synthetic spearphishing hunt. "
                        "Score = number of simulated hosts exhibiting the technique. "
                        "Data is synthetic; see data/attack_v20_subset.json for provenance."),
        "techniques": techniques_layer,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 1, "maxValue": 2},
        "legendItems": [{"label": "1 host", "color": "#ffe766"},
                        {"label": "2+ hosts", "color": "#ff6666"}],
        "metadata": [{"name": "source", "value": ATTACK["source"]}],
    }
    (ROOT / "attack" / "navigator_layer.json").write_text(
        json.dumps(layer, indent=2), encoding="utf-8")
    print(f"\nNavigator layer: {len(techniques_layer)} techniques across hosts")


if __name__ == "__main__":
    write_outputs(hunt())
