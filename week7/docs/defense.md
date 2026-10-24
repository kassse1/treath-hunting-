# Week 7 defense (7–8 minutes)

Danial Rahman, CS-2421. Topic: Detecting Spearphishing Attacks in Corporate Networks. Rehearse with a timer; have `images/raw_vs_tuned.png`, `docs/execution_output.txt` and the Navigator layer open.

## 0:00–1:00 — Objective
The Week 7 syllabus task is to select an analytic from MITRE CAR, implement it in a SIEM, and map it to ATT&CK. Week 6 mapped the attacker's behaviour; this week we build the detections for the execution stage of that same phishing chain and show how a raw CAR analytic is tuned to cut false positives.

## 1:00–2:00 — Analytics vs detections, and our pipeline
CAR gives an *analytic* — a vendor-neutral hunting idea in pseudocode. A *detection* is that idea realised as a query in one product. We bridge them with: CAR analytic → Sigma rule → pySigma → Splunk SPL **and** SQLite → executed results. Writing it once in Sigma means the same rule runs in our Splunk lab and in a local SQLite store we can reproduce without a licence.

## 2:00–3:30 — The analytics we chose
CAR-2014-04-003, PowerShell Execution: CAR's rule is "PowerShell whose parent isn't explorer.exe." It maps to T1059.001 and is intentionally broad. We implemented it raw, and a tuned version that also requires an Office parent and an encoded command — that adds T1027.010 and T1204.002 and matches our phishing chain. We also took CAR-2013-02-003, cmd.exe with an abnormal parent, for the Office→cmd variant (T1059.003).

## 3:30–5:00 — Execution and results (show raw_vs_tuned.png + execution_output.txt)
`run_hunt.py` loads the Sysmon telemetry into a real SQLite table and runs the generated SQL — this is actual query execution, not a mock. Raw CAR-2014-04-003 matches three hosts, **including FIN-WS03**, which is approved Excel automation — a false positive. The tuned rule matches two: FIN-WS01 and FIN-WS04. The bar chart is the story: raw 3 → tuned 2.

## 5:00–6:00 — Why FIN-WS04 survives, and the funnel
FIN-WS04 still matches the tuned rule, because at a single process event it really is encoded PowerShell from Word. It is only cleared by the Week 6 correlation step — its outbound traffic belonged to a different process. So across the project the funnel is raw 3 → tuned 2 → correlated 1. One analytic finds candidates; tuning and correlation resolve them. That is the main message of the three weeks.

## 6:00–7:00 — ATT&CK mapping (show Navigator layer)
The tuned analytic covers T1059.001, T1027.010, T1204.002; the cmd analytic covers T1059.003. The Navigator layer overlaps Week 6 on the Execution tactic — deliberately: Week 6 is the behaviour, Week 7 is what we actually detect. CAR-2013-02-003 returned zero rows because this chain used PowerShell; we keep it as coverage for the cmd variant.

## 7:00–7:45 — Limitations and close
Four synthetic records show rule logic and tuning effect, not real precision. The SPL must be validated in the Splunk lab against real field extractions; `-enc` matching needs script-block logging to go further. Next increment (Week 8) builds an emulation plan that exercises these analytics end to end. Questions?

## Likely questions
- *Did you really run the queries?* Yes — `run_hunt.py` executes the committed `queries/*.sql` against an in-memory SQLite DB built from the telemetry. The SPL is generated for the Splunk lab.
- *Why keep an analytic that returns zero rows?* It encodes a real, different hypothesis (Office→cmd). Zero rows on this dataset is correct, not a failure.
- *Why Sigma in the middle?* One rule, many targets. Same analytic to Splunk and SQLite with no rewrite, which is how you keep a detection set portable.
