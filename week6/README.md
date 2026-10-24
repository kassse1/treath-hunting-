# Week 6 — ATT&CK Framework: Spearphishing Attachment chain

Project: **Detecting Spearphishing Attacks in Corporate Networks** · Danial Rahman · CS-2421 · Introduction to Threat Hunting.

Syllabus 2026–2027, §3.3 Week 6 task: study one ATT&CK technique, simulate an attack, map results to ATT&CK tactics and techniques. We study **T1566.001 Spearphishing Attachment** and map the full chain it triggers to **ATT&CK Enterprise v20**. All data is synthetic; nothing is executed.

## Layout

```
week6/
├── README.md
├── data/
│   ├── attack_v20_subset.json     ATT&CK v20 facts extracted from MITRE STIX (provenance for the report)
│   ├── mail_events.ndjson         mail-gateway log records (no email bodies)
│   ├── endpoint_events.ndjson     Sysmon-schema telemetry (EventID 1/3/11), 4 hosts
│   └── attack_chain.csv           observed step -> ATT&CK technique table
├── scripts/
│   ├── build_attack_reference.py  rebuild the ATT&CK subset from the STIX bundle
│   ├── generate_telemetry.py      regenerate the synthetic telemetry (deterministic)
│   ├── hunt_and_map.py            run the hunt, map to ATT&CK, emit Navigator layer
│   └── make_figures.py            render the two figures
├── images/{attack_chain.png, hunt_funnel.png}
├── attack/navigator_layer.json    importable ATT&CK Navigator layer
└── docs/{week6_report.md, defense.md, hunt_results.json, execution_output.txt}
```

## Reproduce

```bash
cd week6
python3 scripts/generate_telemetry.py   # -> data/*.ndjson
python3 scripts/hunt_and_map.py          # -> docs/*, attack/navigator_layer.json, data/attack_chain.csv
python3 scripts/make_figures.py          # -> images/*
```
Only `matplotlib` is required (for figures). To rebuild `data/attack_v20_subset.json`, clone `mitre-attack/attack-stix-data` and run `build_attack_reference.py` against `enterprise-attack.json` (see the script header).

## Result

Four hosts narrow to one suspicious candidate (FIN-WS01) that completes T1566.001 → T1204.002 → T1059.001 → T1027.010 → T1071.001. FIN-WS03 (approved automation) and FIN-WS04 (uncorrelated egress) are controls that must *not* be flagged. See `docs/week6_report.md`.

## Safety

No email is generated; mail is log records with a hashed harmless placeholder attachment. No process runs and no connection is made. Senders use `.example`; all IPs are RFC 5737 documentation ranges.

## Defend from a phone

Open `docs/week6_report.md`, the two images, and import `attack/navigator_layer.json` into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Follow `docs/defense.md` (7–8 min). Saved results are not a live run.
