# Week 6 defense (7–8 minutes)

Danial Rahman, CS-2421. Topic: Detecting Spearphishing Attacks in Corporate Networks. Rehearse with a timer; have `images/attack_chain.png`, `images/hunt_funnel.png` and the Navigator layer open.

## 0:00–1:00 — Topic and weekly objective
Our group topic is detecting spearphishing in corporate networks. The Week 6 syllabus task is to study one ATT&CK technique, simulate an attack, and map the results to ATT&CK. We chose **T1566.001 Spearphishing Attachment** and followed it through the whole chain it triggers, so we map five techniques across four tactics, not just one cell. Everything is synthetic — no email, no execution, no network.

## 1:00–2:30 — The technique and the framework
ATT&CK is tactics (the goal), techniques (the how), and procedures (real implementations). We use Enterprise v20, read from MITRE's official STIX data so our facts are verifiable. T1566.001 is Initial Access; in v20 it is attributed to 79 groups and 62 tools — that is why it anchors the project. MITRE's own detection strategy DET0236 says to correlate inbound mail → attachment on disk → process execution → outbound traffic. That is exactly the chain we reconstruct.

## 2:30–3:30 — The simulated chain (show attack_chain.png)
On host FIN-WS01: a mail record fails SPF/DMARC and carries a macro-document (T1566.001). The user opens it, Word writes it to Downloads and spawns a child (T1204.002). The child is PowerShell (T1059.001) with an `-EncodedCommand` flag (T1027.010). The same PowerShell process then connects out on 443 (T1071.001). Each arrow is tied to one technique and tactic — that is the mapping the task asks for.

## 3:30–5:00 — The hunt and the controls (show hunt_funnel.png)
We don't just assert the chain; we hunt for it. Four hosts, narrowed by each condition. FIN-WS02 opened a PDF from Explorer — no chain. FIN-WS03 is Excel spawning PowerShell but with no encoding and an internal destination — approved automation, a false positive if alerted blindly. FIN-WS04 has encoded Office PowerShell, but its outbound traffic belonged to a *different* process, so it fails the same-process test. Only FIN-WS01 completes the chain. The controls are the point: behaviour alone is not compromise.

## 5:00–6:30 — Navigator layer and safety
Show the imported Navigator layer: the five techniques light up across the matrix, scored by how many hosts show each. On safety: no message is generated — mail is log records with a hashed placeholder attachment; no process runs; `.example` domains and RFC 5737 IPs mean nothing resolves or routes. The generator is deterministic, so every number reproduces.

## 6:30–7:30 — Limitations and next step
Four hosts and one path show the logic works, not detection accuracy. A real hunt adds macro telemetry, DNS, proxy, and treats `-enc` as one weak indicator. Week 7 turns the execution stage of this chain into MITRE CAR analytics and runs them in a SIEM, showing how tuning cuts false positives. Questions?

## Likely questions
- *Why T1566.001 and not T1566.002?* Attachment delivery matches our Office-macro chain; link-based delivery (T1566.002) is noted as an alternative path to the same tactics.
- *Is `-EncodedCommand` really malicious?* No — it is one indicator. Admins encode commands too (that is FIN-WS03's lesson). It needs parent process and correlated egress to matter.
- *Where do the ATT&CK facts come from?* `data/attack_v20_subset.json`, extracted from MITRE's STIX bundle by `scripts/build_attack_reference.py` — not from memory.
