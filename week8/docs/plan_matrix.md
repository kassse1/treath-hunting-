| # | Tactic | Technique | Atomic test (GUID) | Expected detection | APT29 uses (ATT&CK v20) |
|---|---|---|---|---|---|
| 1 | Initial Access | T1566.001 Spearphishing Attachment | T1566.001 #1 Download Macro-Enabled Phishing Attachment (`114ccff9`) | Week 6 mail filter (macro attachment + SPF/DMARC fail) | yes |
| 2 | Execution | T1204.002 Malicious File | T1566.001 #2 Word spawned a command shell and used an IP address in the command line (`cbb6799a`) | CAR-2013-02-003 (Week 7) - Office spawning a shell | yes |
| 3 | Execution | T1059.001 PowerShell + T1027.010 | T1059.001 #17 PowerShell Command Execution (`a538de64`) | CAR-2014-04-003 raw and tuned (Week 7) | yes |
| 4 | Command and Control | T1105 Ingress Tool Transfer | T1105 #7 certutil download (urlcache) (`dd3b61dd`) | New Week 9 rule (certutil download) | yes |
| 5 | Persistence | T1547.001 Registry Run Keys / Startup Folder | T1547.001 #1 Reg Key Run (`e55be3fd`) | New Week 9 rule (Run key written by a script host / reg.exe) | yes |
| 6 | Persistence | T1053.005 Scheduled Task | T1053.005 #2 Scheduled task Local (`42f53695`) | New Week 9 rule (schtasks /create from a shell) | yes |
| 7 | Credential Access | T1003.001 LSASS Memory *(optional)* | T1003.001 #2 Dump LSASS.exe Memory using comsvcs.dll (`2536dee2`) | New Week 9 rule (comsvcs MiniDump) | no |
| 8 | Collection | T1560.001 Archive via Utility + T1005 | T1560.001 #4 Compress Data and lock with password for Exfiltration with 7zip (`d1334303`) | New Week 9 rule (archiver with password switch) | no |
| 9 | Exfiltration | T1041 Exfiltration Over C2 Channel | T1041 #1 C2 Data Exfiltration (`d1253f6e`) | Week 6 same-process egress correlation; new Week 9 network rule | no |
