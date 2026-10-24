#!/usr/bin/env python3
"""Generate synthetic detection telemetry for the Week 6 spearphishing exercise.

This script does NOT create email messages. It emits the kind of structured
log records a SIEM would already hold after mail-gateway and endpoint agents
parsed activity, so the hunt can be reproduced without any phishing artifact.

Outputs
  data/mail_events.ndjson      mail-gateway log records (one per delivered message)
  data/endpoint_events.ndjson  Sysmon-schema endpoint records (EventID 1/3/11)

Safety
  * Senders use the reserved .example TLD; destinations use RFC 5737
    documentation IP ranges. Nothing resolves or routes.
  * The attachment field carries only a name and a SHA-256 of a short,
    harmless placeholder string. No macro, script, binary or email body
    is produced anywhere.
  * No process runs and no connection is made. The endpoint records follow
    Sysmon field names; they are generated, not captured from Windows.

Output is deterministic so the report figures reproduce exactly.
"""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIL = ROOT / "data" / "mail_events.ndjson"
ENDP = ROOT / "data" / "endpoint_events.ndjson"
T0 = datetime(2026, 10, 19, 9, 14, 2, tzinfo=timezone.utc)


def ts(offset_seconds):
    return (T0 + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Mail-gateway records. Each describes a delivered message as the gateway
# logged it: sender, recipient, auth verdict, attachment name + hash. No body.
# ---------------------------------------------------------------------------
PLACEHOLDER_ATTACHMENT = "WEEK6-SIMULATION-HARMLESS-PLACEHOLDER"

mail_events = [
    {
        "@timestamp": ts(0),
        "event": {"category": "email", "action": "delivered"},
        "mail": {
            "message_id": "<sim-1001@invoices.vendor-billing.example>",
            "from": "accounts@vendor-billing.example",
            "display_name": "Accounts Payable",
            "to": "d.rahman@corp.example",
            "subject": "Outstanding invoice - action required",
            "spf": "fail", "dkim": "none", "dmarc": "fail",
            "sender_ip": "203.0.113.47",
            "attachment": {"name": "Invoice_Oct2026.docm",
                           "sha256": sha256(PLACEHOLDER_ATTACHMENT),
                           "content_type": "application/vnd.ms-word.document.macroEnabled.12"},
        },
        "labels": {"scenario": "suspicious_simulation", "host": "FIN-WS01"},
    },
    {
        "@timestamp": ts(-3600),
        "event": {"category": "email", "action": "delivered"},
        "mail": {
            "message_id": "<po-55021@purchasing.corp.example>",
            "from": "procurement@corp.example",
            "display_name": "Procurement",
            "to": "d.rahman@corp.example",
            "subject": "October purchase order",
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "sender_ip": "192.0.2.10",
            "attachment": {"name": "PO_October.pdf",
                           "sha256": sha256("WEEK6-BENIGN-VENDOR-PDF"),
                           "content_type": "application/pdf"},
        },
        "labels": {"scenario": "benign_control", "host": "FIN-WS02"},
    },
    {
        "@timestamp": ts(-7200),
        "event": {"category": "email", "action": "delivered"},
        "mail": {
            "message_id": "<news-9087@news.corp.example>",
            "from": "newsletter@corp.example",
            "display_name": "Internal Comms",
            "to": "d.rahman@corp.example",
            "subject": "Weekly security tips",
            "spf": "pass", "dkim": "pass", "dmarc": "pass",
            "sender_ip": "192.0.2.11",
            "attachment": None,
        },
        "labels": {"scenario": "benign_control", "host": "FIN-WS01"},
    },
]

# ---------------------------------------------------------------------------
# Endpoint records (Sysmon schema). FIN-WS01 shows the full simulated chain;
# the others are benign or partial controls to exercise the hunt logic.
#   EventID 11 = FileCreate, 1 = ProcessCreate, 3 = NetworkConnect
# ---------------------------------------------------------------------------
endpoint_events = [
    # FIN-WS01: attachment saved -> Word spawns encoded PowerShell -> egress
    {"EventID": 11, "UtcTime": ts(95), "Computer": "FIN-WS01",
     "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "TargetFilename": "C:\\Users\\d.rahman\\Downloads\\Invoice_Oct2026.docm",
     "User": "CORP\\d.rahman"},
    {"EventID": 1, "UtcTime": ts(140), "Computer": "FIN-WS01",
     "ProcessGuid": "{proc-ws01-ps}", "ProcessId": 7120,
     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "OriginalFileName": "PowerShell.EXE",
     "CommandLine": "powershell.exe -NoProfile -EncodedCommand VwBlAGUAawA2ACAAcwBpAG0A",
     "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "ParentCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\d.rahman\\Downloads\\Invoice_Oct2026.docm\"",
     "User": "CORP\\d.rahman", "IntegrityLevel": "Medium"},
    {"EventID": 3, "UtcTime": ts(172), "Computer": "FIN-WS01",
     "ProcessGuid": "{proc-ws01-ps}", "ProcessId": 7120,
     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "Initiated": True, "Protocol": "tcp",
     "DestinationIp": "203.0.113.200", "DestinationPort": 443,
     "DestinationHostname": "cdn-update.staticassets.example", "User": "CORP\\d.rahman"},

    # FIN-WS02: benign PDF opened from Explorer; no interpreter, no egress
    {"EventID": 11, "UtcTime": ts(-3540), "Computer": "FIN-WS02",
     "Image": "C:\\Program Files\\Adobe\\Acrobat\\Acrobat\\Acrobat.exe",
     "TargetFilename": "C:\\Users\\k.orynbet\\Downloads\\PO_October.pdf",
     "User": "CORP\\k.orynbet"},
    {"EventID": 1, "UtcTime": ts(-3500), "Computer": "FIN-WS02",
     "ProcessGuid": "{proc-ws02-explorer}", "ProcessId": 4410,
     "Image": "C:\\Program Files\\Adobe\\Acrobat\\Acrobat\\Acrobat.exe",
     "CommandLine": "\"Acrobat.exe\" \"C:\\Users\\k.orynbet\\Downloads\\PO_October.pdf\"",
     "ParentImage": "C:\\Windows\\explorer.exe",
     "ParentCommandLine": "C:\\Windows\\Explorer.EXE",
     "User": "CORP\\k.orynbet", "IntegrityLevel": "Medium"},

    # FIN-WS03: approved admin automation - Office spawns PowerShell but no
    # encoded command and the destination is internal (benign matching control)
    {"EventID": 1, "UtcTime": ts(300), "Computer": "FIN-WS03",
     "ProcessGuid": "{proc-ws03-ps}", "ProcessId": 5190,
     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "OriginalFileName": "PowerShell.EXE",
     "CommandLine": "powershell.exe -NoProfile -File C:\\Scripts\\Export-Report.ps1",
     "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     "ParentCommandLine": "\"EXCEL.EXE\" /automation",
     "User": "CORP\\svc_report", "IntegrityLevel": "Medium"},
    {"EventID": 3, "UtcTime": ts(330), "Computer": "FIN-WS03",
     "ProcessGuid": "{proc-ws03-ps}", "ProcessId": 5190,
     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "Initiated": True, "Protocol": "tcp",
     "DestinationIp": "10.20.0.15", "DestinationPort": 445,
     "DestinationHostname": "fileserver01.corp.example", "User": "CORP\\svc_report"},

    # FIN-WS04: encoded PowerShell from Office, but outbound belongs to a
    # DIFFERENT process (browser) - correlation control, must be excluded
    {"EventID": 1, "UtcTime": ts(210), "Computer": "FIN-WS04",
     "ProcessGuid": "{proc-ws04-ps}", "ProcessId": 8300,
     "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "OriginalFileName": "PowerShell.EXE",
     "CommandLine": "powershell.exe -enc VABlAHMAdAA2ACAAYwBvAG4AdAByAG8AbAA=",
     "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "ParentCommandLine": "\"WINWORD.EXE\" /n \"C:\\Users\\a.serik\\Downloads\\memo.docm\"",
     "User": "CORP\\a.serik", "IntegrityLevel": "Medium"},
    {"EventID": 3, "UtcTime": ts(240), "Computer": "FIN-WS04",
     "ProcessGuid": "{proc-ws04-chrome}", "ProcessId": 9001,
     "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "Initiated": True, "Protocol": "tcp",
     "DestinationIp": "203.0.113.201", "DestinationPort": 443,
     "DestinationHostname": "www.example", "User": "CORP\\a.serik"},
]


def main():
    MAIL.parent.mkdir(parents=True, exist_ok=True)
    with MAIL.open("w", encoding="utf-8") as fh:
        for e in mail_events:
            fh.write(json.dumps(e) + "\n")
    with ENDP.open("w", encoding="utf-8") as fh:
        for e in endpoint_events:
            fh.write(json.dumps(e) + "\n")
    print(f"wrote {len(mail_events)} mail records -> {MAIL.relative_to(ROOT)}")
    print(f"wrote {len(endpoint_events)} endpoint records -> {ENDP.relative_to(ROOT)}")
    print(f"placeholder attachment sha256 = {sha256(PLACEHOLDER_ATTACHMENT)}")


if __name__ == "__main__":
    main()
