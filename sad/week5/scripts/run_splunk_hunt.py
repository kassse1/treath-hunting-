"""Run searches in a Splunk lab. Password is read from the environment."""
import os,json,ssl,urllib.request,urllib.parse,base64,time,csv,io
from pathlib import Path
root=Path(__file__).resolve().parents[1]
base=os.environ.get('WEEK5_SPLUNK_URL','https://127.0.0.1:8089').rstrip('/')
username=os.environ.get('WEEK5_SPLUNK_USER','admin')
password=os.environ['WEEK5_SPLUNK_PASSWORD']
ctx=ssl.create_default_context()
if os.environ.get('WEEK5_SPLUNK_LOCAL_SELF_SIGNED')=='1':
    if urllib.parse.urlparse(base).hostname not in ('127.0.0.1','localhost'):raise ValueError('Self-signed option is restricted to localhost')
    ctx.check_hostname=False;ctx.verify_mode=ssl.CERT_NONE
auth=base64.b64encode((username+':'+password).encode()).decode()
def request(path,values=None):
    data=None if values is None else urllib.parse.urlencode(values).encode()
    r=urllib.request.Request(base+path,data=data,headers={'Authorization':'Basic '+auth})
    with urllib.request.urlopen(r,context=ctx,timeout=90) as f:return f.read().decode()
summary={'engine':'Splunk Enterprise','version':os.environ.get('WEEK5_SPLUNK_VERSION','check server version'),'dataset':'synthetic','events':10,'queries':[]}
for f in sorted((root/'queries').glob('q*.spl')):
    raw=request('/services/search/jobs/export',{'search':'search '+f.read_text(),'output_mode':'json','exec_mode':'oneshot'})
    objects=[json.loads(line) for line in raw.splitlines() if line.strip()]
    messages=[x for x in objects if 'result' not in x and x.get('type') in ('ERROR','FATAL')]
    if messages:raise RuntimeError(str(messages))
    (root/'docs'/f'{f.stem}_splunk_response.ndjson').write_text(raw)
    results=[o['result'] for o in objects if 'result' in o]
    hosts=sorted({r['host_id'] for r in results})
    summary['queries'].append({'query':f.stem,'matches':len(results),'hosts':hosts})
(root/'docs/hunt_results.json').write_text(json.dumps(summary,indent=2))
print(json.dumps(summary,indent=2))
