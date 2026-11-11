#!/usr/bin/env python3
"""Model the Sysmon telemetry that the Week 9 Atomic tests produce on LAB-WIN10-01.

This repository cannot run Windows, so - as in Weeks 5-7 - the telemetry is
SYNTHETIC. It is not invented freely: every technique event is built from the
real command line of the pinned Atomic test (atomics/selected_tests.json, with
its default input arguments substituted) wrapped the way Invoke-AtomicRedTeam
launches it (command_prompt -> cmd.exe /c, powershell -> powershell.exe & {}).
A benign baseline (admin activity, approved automation, updaters) is added so
false positives can be measured.

Each event carries a ground-truth label `_truth` used ONLY for scoring, never by
the detection queries:
    technique  event produced by the technique under test
    proxy      event produced by how the test emulates the technique
               (e.g. PowerShell download standing in for mail delivery)
    harness    event produced by Invoke-AtomicRedTeam itself
    baseline   benign activity

Outputs:
    data/atomic_run_telemetry.ndjson   events (replace with a Splunk export after a real run)
    data/run_log.csv                   per-step UTC windows, same format the runbook writes
"""
import csv
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = json.loads((ROOT / "atomics" / "selected_tests.json").read_text(encoding="utf-8"))["tests"]
OUT = ROOT / "data" / "atomic_run_telemetry.ndjson"
RUNLOG = ROOT / "data" / "run_log.csv"

HOST = "LAB-WIN10-01"
USER = "CORP\\art.tester"
SID = "S-1-5-21-3623811015-3361044348-30300820-1013"
TEMP = "C:\\Users\\art.tester\\AppData\\Local\\Temp"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
EXCEL = "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"
ATOMICS = "C:\\AtomicRedTeam\\atomics"
GH_RAW = ("185.199.108.133", "raw.githubusercontent.com")
GH = ("140.82.121.4", "github.com")
START = datetime(2026, 11, 9, 9, 0, 0, tzinfo=timezone.utc)
STEP_GAP = timedelta(minutes=5)

events = []
pid = [5000]


def ts(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def next_pid():
    pid[0] += 4
    return pid[0]


def add(t, truth, step, **fields):
    e = {"UtcTime": ts(t), "Computer": fields.pop("Computer", HOST), "User": fields.pop("User", USER)}
    e.update(fields)
    e["_truth"] = truth
    e["_step"] = step
    events.append(e)
    return e


def proc(t, truth, step, image, cmdline, parent, parent_cmd, **kw):
    return add(t, truth, step, EventID=1, Image=image, CommandLine=cmdline, ParentImage=parent,
               ParentCommandLine=parent_cmd, ProcessId=next_pid(), **kw)


def resolve(test):
    cmd = test["command"]
    for k, v in test["input_arguments"].items():
        cmd = cmd.replace("#{" + k + "}", str(v))
    return cmd.replace("$PathToAtomicsFolder", ATOMICS)


ROOT_PS_CMD = 'powershell.exe -NoExit -Command "Import-Module Invoke-AtomicRedTeam"'


def harness(t, step, test, cmd):
    """Invoke-AtomicRedTeam wraps the test command in a child shell."""
    if test["executor"] == "command_prompt":
        flat = " & ".join(l.strip() for l in cmd.splitlines() if l.strip())
        return proc(t, "harness", step, CMD, f'"cmd.exe" /c {flat}', PS, ROOT_PS_CMD)
    flat = "; ".join(l.strip() for l in cmd.splitlines() if l.strip())
    return proc(t, "harness", step, PS, f'"powershell.exe" & {{{flat}}}', PS, ROOT_PS_CMD)


def step_events(test, t0):
    s = test["step"]
    cmd = resolve(test)
    h = harness(t0, s, test, cmd)
    t = t0 + timedelta(seconds=2)
    if s == 1:   # download macro attachment (proxy for mail delivery)
        add(t, "proxy", s, EventID=3, Image=PS, Initiated="true", Protocol="tcp",
            DestinationIp=GH[0], DestinationHostname=GH[1], DestinationPort=443)
        add(t + timedelta(seconds=1), "proxy", s, EventID=3, Image=PS, Initiated="true", Protocol="tcp",
            DestinationIp=GH_RAW[0], DestinationHostname=GH_RAW[1], DestinationPort=443)
        add(t + timedelta(seconds=2), "proxy", s, EventID=11, Image=PS,
            TargetFilename=f"{TEMP}\\PhishingAttachment.xlsm")
    elif s == 2:  # Invoke-MalDoc: Word via COM, macro writes .jse and shells "ping 8.8.8.8"
        add(t, "harness", s, EventID=3, Image=PS, Initiated="true", Protocol="tcp",
            DestinationIp=GH_RAW[0], DestinationHostname=GH_RAW[1], DestinationPort=443)
        add(t + timedelta(seconds=1), "harness", s, EventID=13, Image=PS, EventType="SetValue",
            TargetObject=f"HKU\\{SID}\\SOFTWARE\\Microsoft\\Office\\16.0\\Word\\Security\\AccessVBOM",
            Details="DWORD (0x00000001)")
        proc(t + timedelta(seconds=3), "harness", s, WORD, f'"{WORD}" /Automation -Embedding',
             "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p")
        jse = test["input_arguments"]["jse_path"]
        add(t + timedelta(seconds=6), "technique", s, EventID=11, Image=WORD, TargetFilename=jse)
        proc(t + timedelta(seconds=6), "technique", s, "C:\\Windows\\System32\\PING.EXE",
             "ping 8.8.8.8", WORD, f'"{WORD}" /Automation -Embedding')
    elif s == 3:  # powershell.exe -e <base64>
        proc(t, "technique", s, PS, cmd, CMD, h["CommandLine"])
    elif s == 4:  # cmd /c certutil -urlcache
        inner = cmd.split("cmd /c ", 1)[1]
        c2 = proc(t, "harness", s, CMD, f"cmd  /c {inner}", CMD, h["CommandLine"])
        proc(t + timedelta(seconds=1), "technique", s, "C:\\Windows\\System32\\certutil.exe", inner,
             CMD, c2["CommandLine"])
        add(t + timedelta(seconds=2), "technique", s, EventID=3, Image="C:\\Windows\\System32\\certutil.exe",
            Initiated="true", Protocol="tcp", DestinationIp=GH_RAW[0], DestinationHostname=GH_RAW[1],
            DestinationPort=443)
        add(t + timedelta(seconds=3), "technique", s, EventID=11, Image="C:\\Windows\\System32\\certutil.exe",
            TargetFilename="C:\\AtomicRedTeam\\Atomic-license.txt")
    elif s == 5:  # REG ADD HKCU Run
        proc(t, "technique", s, "C:\\Windows\\System32\\reg.exe", cmd, CMD, h["CommandLine"])
        m = re.search(r'/V "([^"]+)".*/D "([^"]+)"', cmd)
        add(t + timedelta(seconds=1), "technique", s, EventID=13, Image="C:\\Windows\\system32\\reg.exe",
            EventType="SetValue",
            TargetObject=f"HKU\\{SID}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\{m.group(1)}",
            Details=m.group(2))
    elif s == 6:  # SCHTASKS /Create
        proc(t, "technique", s, "C:\\Windows\\System32\\schtasks.exe", cmd, CMD, h["CommandLine"])
        add(t + timedelta(seconds=1), "technique", s, EventID=4698, Image="", TaskName="\\spawn",
            Channel="Security")
    elif s == 7:  # rundll32 comsvcs.dll MiniDump
        line = cmd.replace("(Get-Process lsass).id", "748").replace("$env:TEMP", TEMP)
        rd = proc(t, "technique", s, "C:\\Windows\\System32\\rundll32.exe", line, PS, h["CommandLine"],
                  IntegrityLevel="High")
        add(t + timedelta(seconds=1), "technique", s, EventID=10, SourceImage=rd["Image"],
            TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1FFFFF")
        add(t + timedelta(seconds=2), "technique", s, EventID=11, Image=rd["Image"],
            TargetFilename=f"{TEMP}\\lsass-comsvcs.dmp")
    elif s == 8:  # 7z u archive.7z *txt -pblue
        line = [l for l in cmd.splitlines() if "7z.exe" in l][0].strip()
        line = line.replace("%ProgramFiles%", "C:\\Program Files")
        proc(t, "technique", s, "C:\\Program Files\\7-Zip\\7z.exe", line, CMD, h["CommandLine"])
        add(t + timedelta(seconds=1), "technique", s, EventID=11, Image="C:\\Program Files\\7-Zip\\7z.exe",
            TargetFilename=f"{ATOMICS}\\T1560.001\\victim-files\\archive.7z")
    elif s == 9:  # Invoke-WebRequest POST to the lab C2
        add(t, "technique", s, EventID=11, Image=PS, TargetFilename=f"{TEMP}\\LineNumbers.txt")
        url = test["input_arguments"]["destination_url"]
        ip, port = re.search(r"//([\d.]+):(\d+)", url).groups()
        add(t + timedelta(seconds=1), "technique", s, EventID=3, Image=PS, Initiated="true", Protocol="tcp",
            DestinationIp=ip, DestinationHostname="", DestinationPort=int(port))
    return h


def baseline():
    b = "baseline"
    day = datetime(2026, 11, 9, tzinfo=timezone.utc)
    t = day.replace(hour=8, minute=12)
    proc(t, b, 0, PS, '"powershell.exe"', "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE")
    add(t + timedelta(minutes=1), b, 0, EventID=3, Image=PS, Initiated="true", Protocol="tcp",
        DestinationIp="13.107.246.40", DestinationHostname="download.microsoft.com", DestinationPort=443)
    proc(day.replace(hour=8, minute=20), b, 0, "C:\\Windows\\System32\\certutil.exe",
         'certutil.exe -hashfile C:\\Tools\\sysmon64.exe SHA256', CMD, '"cmd.exe"')
    # Teams updater writes its own Run value
    add(day.replace(hour=8, minute=31), b, 0, EventID=13,
        Image="C:\\Users\\art.tester\\AppData\\Local\\Microsoft\\Teams\\Update.exe", EventType="SetValue",
        TargetObject=f"HKU\\{SID}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\com.squirrel.Teams.Teams",
        Details='C:\\Users\\art.tester\\AppData\\Local\\Microsoft\\Teams\\Update.exe --processStart "Teams.exe"')
    # IT admin creates a backup task from an interactive shell
    proc(day.replace(hour=8, minute=40), b, 0, "C:\\Windows\\System32\\schtasks.exe",
         'schtasks /create /tn "NightlyBackup" /tr "C:\\Scripts\\backup.cmd" /sc daily /st 02:00 /ru SYSTEM',
         CMD, '"cmd.exe"', User="CORP\\it.admin")
    proc(day.replace(hour=8, minute=41), b, 0, "C:\\Program Files\\7-Zip\\7z.exe",
         '"C:\\Program Files\\7-Zip\\7z.exe" a C:\\Backup\\scripts.7z C:\\Scripts',
         CMD, '"cmd.exe"', User="CORP\\it.admin")
    # Finance user saves a macro workbook from Excel (legitimate)
    add(day.replace(hour=8, minute=50), b, 0, EventID=11, Image=EXCEL,
        TargetFilename="C:\\Users\\fin.user\\Documents\\Budget_2027.xlsm", User="CORP\\fin.user")
    # Approved report automation (the Week 7 false positive), on FIN-WS03
    proc(day.replace(hour=11, minute=5), b, 0, PS,
         'powershell.exe -NoProfile -File \\\\fs01.corp.local\\reports\\refresh_pivot.ps1',
         EXCEL, f'"{EXCEL}" /e', Computer="FIN-WS03", User="CORP\\svc_report")
    # Word opened normally by a user
    proc(day.replace(hour=11, minute=12), b, 0, WORD, f'"{WORD}" /n "C:\\Users\\fin.user\\Documents\\Memo.docx"',
         "C:\\Windows\\explorer.exe", "C:\\Windows\\Explorer.EXE", Computer="FIN-WS02", User="CORP\\fin.user")


def main():
    rows = []
    for i, test in enumerate(TESTS):
        t0 = START + i * STEP_GAP
        step_events(test, t0)
        rows.append({"step": test["step"], "technique": test["atomic_technique"], "guid": test["guid"],
                     "start_utc": ts(t0 - timedelta(seconds=1)), "end_utc": ts(t0 + timedelta(seconds=45)),
                     "executed": "yes", "notes": "modelled run (synthetic)"})
    baseline()
    events.sort(key=lambda e: e["UtcTime"])
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    with RUNLOG.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    by = {}
    for e in events:
        by[e["_truth"]] = by.get(e["_truth"], 0) + 1
    print(f"wrote {len(events)} events {by} to {OUT.relative_to(ROOT)}; run log {RUNLOG.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
