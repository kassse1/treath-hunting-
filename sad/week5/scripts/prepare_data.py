"""Generate safe synthetic telemetry; no PowerShell commands are executed."""
from pathlib import Path
import json
root=Path(__file__).resolve().parents[1]
data=[]
def add(host,minute,cat,entity,process,parent='',command='',**extra):
    e={'@timestamp':f'2026-10-10T08:{minute:02d}:00Z','event':{'category':cat,'type':'start' if cat=='process' else 'connection'},'host':{'id':host,'name':host},'process':{'entity_id':entity,'name':process,'parent':{'name':parent},'command_line':command}}
    e.update(extra);data.append(e)
for host,entity,parent,command in [
 ('LAB-01','proc-a','WINWORD.EXE','powershell.exe -EncodedCommand DEMO_PLACEHOLDER'),
 ('LAB-02','proc-b','explorer.exe','powershell.exe -File inventory.ps1'),
 ('LAB-03','proc-c','EXCEL.EXE','powershell.exe -EncodedCommand DEMO_PLACEHOLDER'),
 ('LAB-04','proc-d','WINWORD.EXE','powershell.exe -EncodedCommand DEMO_PLACEHOLDER'),
 ('LAB-05','proc-e','WINWORD.EXE','powershell.exe -File approved_report.ps1')]:
    add(host,2,'process',entity,'powershell.exe',parent,command)
for host,entity,proc in [('LAB-01','proc-a','powershell.exe'),('LAB-02','proc-b','powershell.exe'),('LAB-03','proc-c','powershell.exe'),('LAB-04','unrelated-browser','browser.exe'),('LAB-05','proc-e','powershell.exe')]:
    add(host,4,'network',entity,proc,network={'direction':'egress'},destination={'ip':'198.51.100.23','port':443})
data.sort(key=lambda e:(e['@timestamp'],e['host']['id']))
(root/'data/events.ndjson').write_text(''.join(json.dumps(e)+'\n' for e in data))
context={
 'LAB-01':{'label':'suspicious simulation','context':'Synthetic unapproved Office to encoded PowerShell chain. Investigate; no real malware was run.'},
 'LAB-02':{'label':'benign control','context':'Inventory script launched from Explorer, not an Office application.'},
 'LAB-03':{'label':'benign matching control','context':'Synthetic approved Excel reporting automation. Matches the rule and requires context to resolve.'},
 'LAB-04':{'label':'correlation control','context':'Office PowerShell exists, but the network event belongs to another process.'},
 'LAB-05':{'label':'benign control','context':'Office automation without an encoded command argument.'}}
(root/'data/analyst_context.json').write_text(json.dumps(context,indent=2))
queries={
 'q1_powershell': 'process where process.name : ("powershell.exe", "pwsh.exe")',
 'q2_office_parent': 'process where process.name : ("powershell.exe", "pwsh.exe") and process.parent.name : ("winword.exe", "excel.exe")',
 'q3_encoded_office': 'process where process.name : ("powershell.exe", "pwsh.exe") and process.parent.name : ("winword.exe", "excel.exe") and process.command_line : ("* -encodedcommand *", "* -enc *")',
 'q4_correlated_sequence': 'sequence by host.id, process.entity_id with maxspan=10m\n  [process where process.name : ("powershell.exe", "pwsh.exe") and process.parent.name : ("winword.exe", "excel.exe") and process.command_line : ("* -encodedcommand *", "* -enc *")]\n  [network where network.direction == "egress"]'}
for name,q in queries.items():
 (root/'queries'/f'{name}.eql').write_text(q+'\n')
 (root/'queries'/f'{name}.json').write_text(json.dumps({'query':q,'size':100},indent=2))
print('Generated 10 synthetic events on 5 hosts and 4 EQL queries.')
