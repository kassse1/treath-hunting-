# Week 5 Office and PowerShell Threat Hunt

Project: Detecting Spearphishing Attacks in Corporate Networks.
Danial Rahman · CS-2421 · Introduction to Threat Hunting.

This increment extends Week 4 with a testable hunting hypothesis and executed Splunk queries. All events are synthetic. No malware or PowerShell payload was run.

## Files

- `docs/week5_report.md`: report with results and limitations.
- `docs/defense.md`: 7–8 minute defense guide.
- `data/events.ndjson`: ten JSON events on five fictional endpoints.
- `data/analyst_context.json`: exercise context used for candidate review.
- `queries/*.spl`: four searches executed in Splunk Enterprise 9.4.2.
- `docs/*_splunk_response.ndjson`: recorded API query responses.
- `docs/hunt_results.json`: executed search summary.
- `scripts/run_splunk_hunt.py`: API reproduction script; credentials come from environment variables.
- `queries/*.eql` and corresponding JSON bodies: optional Elasticsearch alternatives, not executed.
- `scripts/run_elastic_hunt.py`: optional Elasticsearch loading and search script, not executed.

## Repeat in Splunk

1. Use an available Splunk Enterprise lab and create index `week5_hunt`.
2. In Add Data, upload `data/events.ndjson` as JSON lines with sourcetype `week5_json`. Verify ten individual events.
3. Set the search time range to All time. Paste each `queries/*.spl` query into Search and Reporting.
4. Expect 5, 4, 3 and 2 returned rows. The last query returns LAB-01 and LAB-03. Both have a delay of 120 seconds.
5. Read the analyst context: LAB-01 is suspicious simulation; LAB-03 is approved reporting automation and a benign match.

For API reproduction, configure `WEEK5_SPLUNK_URL`, `WEEK5_SPLUNK_USER` and `WEEK5_SPLUNK_PASSWORD` locally, then run:

```bash
python3 scripts/run_splunk_hunt.py
```

Use a trusted certificate. For a localhost lab with a self-signed certificate only, the script supports `WEEK5_SPLUNK_LOCAL_SELF_SIGNED=1`. Keep passwords outside the repository. If rebuilding the dataset, use `python3 scripts/prepare_data.py`, then upload it once to a fresh lab index to avoid duplicates.

## Commit the weekly increment

Copy this directory into your existing group repository as `week5/`, then run from the repository root:

```bash
git add week5
git commit -m "Week 5: add hypothesis driven PowerShell hunt and Splunk results"
git push
```

No repository URL was supplied and no remote push is claimed. Commit new changes when they occur. Keep Week 4 available so the teacher can inspect progress.

## Defend from a phone

Open the separate PDF report and defense PDF. Show the hypothesis, final query and result table. Explain that results are recorded from a completed Splunk run. A live search requires access to the group lab; do not present the saved responses as live execution.
