# Weeks 9–10 defense (7–8 minutes) — Assignment 6

Danial Rahman, CS-2421. Topic: Detecting Spearphishing Attacks in Corporate Networks. Rehearse with a timer. Have these open:

- `../week9/images/detection_matrix.png`
- `../week9/images/coverage_before_after.png`
- `../week9/docs/execution_output.txt`
- `images/apt29_tactics.png`
- `images/apt29_initial_access.png`
- the Navigator layer `attack/apt29_coverage_layer.json`

## 0:00–0:45 — Objective
Assignment 6 covers two syllabus weeks. In Week 9 we run Atomic Red Team tests and analyse the results in a SIEM. In Week 10 we analyse APT29's TTPs and map them to ATT&CK. We run our Week 8 emulation plan, see what our detections really catch, and then measure that against a real APT.

## 0:45–2:00 — Week 9: the Atomic tests
There are nine Atomic tests, pinned by GUID at one commit of the Red Canary repository, including the T1059 and T1003 tests the syllabus names. The runbook runs them by GUID on the isolated lab VM and logs UTC windows. Our repository can't run Windows, so the telemetry is synthetic, but it is generated from each test's *real* command line, wrapped the way Invoke-AtomicRedTeam launches it, plus a benign baseline. Every event has a ground-truth label used only for scoring.

## 2:00–3:30 — Week 9 results (show detection_matrix.png, then coverage_before_after.png)
Sigma → pySigma → SPL and SQLite, 12 rules executed. The Week 7 rules alone detected 1 of 9 tests. With the 9 new rules: 8 detected, 1 partial, 0 missed. Three lessons:
1. Our tuned Week 7 PowerShell rule missed the PowerShell test because the test uses `-e`, not `-enc`, and its parent is cmd, not Word.
2. The "Office spawns cmd" rule missed the maldoc test because Word launched `ping.exe` directly.
3. The raw CAR rule fired in 5 windows but only matched the technique once. The other 4 times it caught the test harness. Without harness labels we would have reported 5/9.

## 3:30–4:00 — Cost
Coverage cost 3 new false positives (Teams Run key, admin backup task, Update-Help). These rules are hunting leads at medium or low severity, not alerts. Gaps left open: no rule on Sysmon 10 lsass access, and step 1 (delivery) is only partial because the test downloads the file and does not email it.

## 4:00–5:30 — Week 10: APT29 (show apt29_tactics.png)
All of this comes from MITRE's STIX data, ATT&CK 20.1. APT29 is the SVR, also known as Cozy Bear, NOBELIUM and Midnight Blizzard. It has 66 group techniques and 2 campaigns (Operation Ghost and SolarWinds), 119 techniques in total. The heaviest tactics are persistence, privilege escalation, defense evasion and credential access: quiet, long access. Case studies: the Dukes era with attachments, encoded PowerShell, Run keys and scheduled tasks, which is our Week 8 plan almost one-for-one. SolarWinds, where APT29 used 7-Zip password archives, our step 8. NOBELIUM 2021 with Constant Contact and HTML smuggling. And 2024, with password spray and RDP-file phishing.

## 5:30–6:45 — Mapping and gaps (show apt29_initial_access.png + Navigator layer)
8 of our 11 plan techniques are APT29 techniques. We detect 6 APT29 techniques and are adjacent to 8 more, about 12% of the profile. We cover the classic Dukes phishing chain. HTML smuggling, Mark-of-the-Web bypass, spearphishing links, WMI persistence and the whole cloud and identity side are red. Compared with APT41, the two groups share 19 techniques, and 5 of our 6 detections are APT41 techniques too, so the rules transfer.

## 6:45–7:30 — Conclusion and next steps
Emulation turned two "covered" rules into misses, and ATT&CK made the remaining gap measurable. Next hunts in priority order: spearphishing link, HTML smuggling/ISO, Mark-of-the-Web bypass, mshta, WMI subscriptions, valid accounts. Questions?

## Likely questions
- *Did you actually run the tests?* The runbook is ready for the lab VM. The analysis here uses telemetry generated from the real pinned test commands, and it is labelled synthetic. After a lab run, the Splunk export replaces the NDJSON and the same scripts re-score it.
- *Why is step 1 only "partial"?* Both rules matched the PowerShell download the test uses to stand in for email delivery. A real phishing email arrives through Outlook, and we did not count matching the stand-in as a detection.
- *Why APT29 and not APT41?* Spearphishing is APT29's signature, and that is our topic. APT41 is included as a comparison.
- *Is 12% bad?* It is honest. The project deliberately went deep on one intrusion path, and the Navigator layer now shows where to go next.
