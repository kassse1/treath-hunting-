# Week 8 defense (7–8 minutes) — Assignment 5

Danial Rahman, CS-2421. Topic: Detecting Spearphishing Attacks in Corporate Networks. Rehearse with a timer. Have these open: `images/emulation_flow.png`, `plan/emulation_plan.yaml`, `docs/validation_output.txt` and `plan/caldera_adversary.yml`.

## 0:00–1:00 — Objective
The Week 8 task is to build a simple adversary emulation plan (initial access → persistence → exfiltration) and document it with ATT&CK. Until now we studied one stage of a phishing attack: the macro that runs encoded PowerShell. This week we write down the whole intrusion so it can be replayed in the lab and every detection can be tested.

## 1:00–2:00 — Emulation vs pen test, and the threat profile
Emulation replays a known adversary's behaviours to measure detection. It does not try to "win". Our profile is a finance-themed phishing intrusion modelled on APT29. ATT&CK v20 maps 7 of our 11 techniques to APT29 at group level. An 8th, the password-protected 7-Zip archive, appears in APT29's SolarWinds campaign. We emulate behaviours with Atomic Red Team, not APT29 malware.

## 2:00–4:00 — The plan (show emulation_flow.png)
There are nine steps. Phishing attachment → user opens it → encoded PowerShell → certutil downloads stage 2 → Run key and scheduled task for persistence → optional LSASS dump → 7-Zip with a password → POST to the lab C2. Each step has an ATT&CK technique, a pinned Atomic test GUID, the telemetry we expect, the detection we expect, a success criterion and a cleanup command. The expected-detection column is a prediction that Week 9 tests.

## 4:00–5:00 — Rules of engagement
One isolated VM with a snapshot. The C2 is a Kali box on a simulated-internet segment. Red, blue and white roles are separate, and the teacher is the white cell. Steps are 5 minutes apart so each one is visible on its own in Splunk. We abort if anything leaves the lab VLAN. The LSASS step is optional, and its dump file is deleted.

## 5:00–6:30 — Plan as code (show validation_output.txt + caldera_adversary.yml)
The YAML is validated against MITRE's STIX data: every technique exists in ATT&CK 20.1, each tactic is valid for its technique, and every step has a cleanup command. The validator found one interesting point. Persistence comes *after* Command and Control in our plan, which runs against the matrix order. That is correct behaviour, because ATT&CK is not a linear kill chain like Lockheed's, so it is logged as a note and not an error. The same script writes a CALDERA adversary profile, ordered by Atomic GUID, and a Navigator layer.

## 6:30–7:30 — Limitations and next step
We do not reproduce APT29's custom malware or cloud tradecraft. Step 1 downloads the attachment instead of emailing it. Next week we run all nine tests and check every "expected detection" against what the SIEM really shows. Questions?

## Likely questions
- *Why include LSASS and exfiltration if APT29 isn't mapped to them?* The syllabus asks for an exfiltration stage and names T1003 for Week 9. Both techniques are used by many groups (44 and 28). We state honestly in the plan that they are not attributed to APT29.
- *Why YAML instead of a Word table?* It can be validated, turned into CALDERA and Navigator files, and Week 9 reads the same GUIDs from it, so the plan and the execution cannot drift apart.
- *What is the difference from the Week 4 kill chain?* The kill chain is linear. ATT&CK tactics are a matrix and can be visited out of order, and our validator note shows exactly that.
