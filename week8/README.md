# Week 8 — Adversary emulation plan (Assignment 5)

Project: **Detecting Spearphishing Attacks in Corporate Networks** · Danial Rahman · CS-2421 · Introduction to Threat Hunting.

Syllabus 2026–2027, §3.3 Week 8 task: develop a simple adversary emulation plan (initial access → persistence → data exfiltration) and document it using ATT&CK techniques. This folder holds **Operation INVOICE STORM**, a 9-step plan modelled on APT29's spearphishing tradecraft. Each step maps to an ATT&CK v20 technique and a pinned Atomic Red Team test. The plan is validated as code and exported to CALDERA and ATT&CK Navigator.

## Layout

```
week8/
├── plan/
│   ├── emulation_plan.yaml        the plan (scope, RoE, roles, 9 steps)
│   └── caldera_adversary.yml      generated CALDERA adversary profile
├── data/attack_v20_subset.json    ATT&CK 20.1 facts for the plan techniques (from MITRE STIX)
├── scripts/
│   ├── build_attack_reference.py  STIX bundle -> data/attack_v20_subset.json
│   └── validate_plan.py           checks + CALDERA profile + Navigator layer + figure
├── attack/navigator_layer.json
├── images/emulation_flow.png
└── docs/{week8_report.md, defense.md, plan_matrix.md, validation_output.txt,
          Week8_Danial_Rahman_Report.docx/.pdf}
```

## Reproduce

```bash
cd week8
python3 -m pip install pyyaml matplotlib
python3 scripts/validate_plan.py
```

Result: `RESULT: PASS`. 11 techniques are valid in ATT&CK 20.1, and 8 of the 11 are used by APT29 at group or campaign level. One NOTE: ATT&CK is not a linear kill chain. See `docs/week8_report.md`.
