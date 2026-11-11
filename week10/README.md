# Week 10 — Learning APT techniques: APT29 TTPs mapped to ATT&CK (Assignment 6, part 2)

Project: **Detecting Spearphishing Attacks in Corporate Networks** · Danial Rahman · CS-2421 · Introduction to Threat Hunting.

Syllabus 2026–2027, §3.3 Week 10 task: analyse the TTPs of APT29 or APT41 and map them to MITRE ATT&CK. We analyse **APT29 (G0016)** from MITRE's ATT&CK 20.1 STIX data (group + campaigns C0023/C0024, 119 techniques), compare it with APT41 (G0096), and measure how much of APT29 our Week 8 plan emulates and our Week 9 rules detect.

Assignment 6 = Week 9 (`../week9`) + Week 10 (this folder). Combined report: `docs/Week9-10_Danial_Rahman_Report.pdf/.docx`. Combined 7–8 minute defense script: `docs/defense.md`.

## Layout

```
week10/
├── data/apt29_profile.json        APT29 techniques, procedures + citations, software, campaigns (ATT&CK 20.1)
├── data/apt41_techniques.json     APT41 techniques (comparison)
├── scripts/
│   ├── build_apt_profile.py       STIX bundle -> data/*.json
│   └── analyze_apt29.py           mapping, coverage vs Week 8/9, figures, Navigator layer
├── images/{apt29_tactics.png, apt29_initial_access.png}
├── attack/apt29_coverage_layer.json
└── docs/{week10_report.md, defense.md, apt29_ttp_table.md, analysis.json, execution_output.txt,
          Week9-10_Danial_Rahman_Report.docx/.pdf}
```

## Reproduce

```bash
cd week10
python3 -m pip install pyyaml matplotlib
python3 scripts/analyze_apt29.py
```

## Result

- 8 of the 11 Week 8 plan techniques are used by APT29.
- Of APT29's 119 techniques, Week 9 rules detect 6 and are adjacent (same parent technique) to 8 more, about 12%.
- 103 techniques are not covered, mainly cloud/identity, supply chain and container-based delivery.
- APT41 shares 19 techniques with APT29 (Jaccard 0.15).
