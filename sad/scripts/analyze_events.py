"""Local teaching example. Input is synthetic, not RSA incident evidence."""
import csv
from pathlib import Path
from datetime import datetime
root = Path(__file__).resolve().parents[1]
with (root / 'data/synthetic_events.csv').open() as f:
    events = list(csv.DictReader(f))
results = []
for email in events:
    if email['event'] != 'email' or 'external sender' not in email['details']:
        continue
    start = datetime.fromisoformat(email['timestamp'].replace('Z', '+00:00'))
    chain = [e for e in events if e['host'] == email['host'] and
             0 <= (datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) - start).total_seconds() <= 600]
    opens = [e for e in chain if e['event'] == 'file_open' and e['object'] == email['object']]
    processes = [e for e in chain if e['event'] == 'process' and 'parent=EXCEL.EXE' in e['details']]
    connections = [e for e in chain if e['event'] == 'network' and
                   any('process=' + p['object'] + ';' in e['details'] for p in processes)]
    if opens and processes and connections:
        results.append(email['host'])
        print('REVIEW:', email['host'], '| external attachment -> file open -> Excel child -> outbound connection')
print('Hosts requiring review:', len(set(results)))
print('Synthetic demonstration only. This output does not confirm malware or an exploit.')
