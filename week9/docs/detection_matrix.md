| Step | Technique | Atomic test | Week 7 rules | Week 7 + Week 9 rules | Detected by |
|---|---|---|---|---|---|
| 1 | T1566.001 | T1566.001 #1 Download Macro-Enabled Phishing Attachment | MISSED (harness only) | PARTIAL | `w9_macro_doc_written_by_non_office`, `w9_powershell_external_connection` |
| 2 | T1204.002 | T1566.001 #2 Word spawned a command shell and used an IP address in the command line | MISSED (harness only) | DETECTED | `w9_office_suspicious_child` |
| 3 | T1059.001 | T1059.001 #17 PowerShell Command Execution | DETECTED | DETECTED | `w7_car_2014_04_003_powershell`, `w9_powershell_encoded_any_parent` |
| 4 | T1105 | T1105 #7 certutil download (urlcache) | MISSED | DETECTED | `w9_certutil_download` |
| 5 | T1547.001 | T1547.001 #1 Reg Key Run | MISSED | DETECTED | `w9_run_key_set` |
| 6 | T1053.005 | T1053.005 #2 Scheduled task Local | MISSED | DETECTED | `w9_schtasks_create_from_shell` |
| 7 | T1003.001 | T1003.001 #2 Dump LSASS.exe Memory using comsvcs.dll | MISSED (harness only) | DETECTED | `w9_lsass_dump_comsvcs` |
| 8 | T1560.001 | T1560.001 #4 Compress Data and lock with password for Exfiltration with 7zip | MISSED | DETECTED | `w9_archive_with_password` |
| 9 | T1041 | T1041 #1 C2 Data Exfiltration | MISSED (harness only) | DETECTED | `w9_powershell_external_connection` |
