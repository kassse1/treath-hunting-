"""Load the teaching dataset into a LOCAL Elasticsearch lab and execute EQL."""
from pathlib import Path
import urllib.request, json, os
root=Path(__file__).resolve().parents[1]
base=os.environ.get('WEEK5_ELASTIC_URL','http://127.0.0.1:9200').rstrip('/')
index='week5-hunt-demo'
def request(method,path,payload=None,ctype='application/json'):
    data=None if payload is None else (payload.encode() if isinstance(payload,str) else json.dumps(payload).encode())
    r=urllib.request.Request(base+path,data=data,method=method,headers={'Content-Type':ctype})
    with urllib.request.urlopen(r,timeout=60) as f:return json.load(f)
version=request('GET','/')['version']['number']
mapping={'mappings':{'properties':{'@timestamp':{'type':'date'},'event':{'properties':{'category':{'type':'keyword'},'type':{'type':'keyword'}}},'host':{'properties':{'id':{'type':'keyword'},'name':{'type':'keyword'}}},'process':{'properties':{'entity_id':{'type':'keyword'},'name':{'type':'keyword'},'command_line':{'type':'wildcard'},'parent':{'properties':{'name':{'type':'keyword'}}}}},'network':{'properties':{'direction':{'type':'keyword'}}},'destination':{'properties':{'ip':{'type':'ip'},'port':{'type':'integer'}}}}}}
try:request('PUT','/'+index,mapping)
except urllib.error.HTTPError as e:
    if e.code!=400:raise
    body=json.loads(e.read())
    if body.get('error',{}).get('type')!='resource_already_exists_exception':raise
lines=(root/'data/events.ndjson').read_text().splitlines()
bulk=''.join(json.dumps({'index':{'_index':index,'_id':str(i)}})+'\n'+line+'\n' for i,line in enumerate(lines))
response=request('POST','/_bulk?refresh=true',bulk,'application/x-ndjson')
if response.get('errors'):raise RuntimeError('Bulk ingest failed: '+json.dumps(response))
summary={'engine':'Elasticsearch','version':version,'index':index,'dataset':'synthetic','events':len(lines),'queries':[]}
for file in sorted((root/'queries').glob('q*.json')):
    result=request('POST',f'/{index}/_eql/search',json.loads(file.read_text()))
    if result.get('is_running'):raise RuntimeError('Query is still running')
    (root/'docs'/f'{file.stem}_response.json').write_text(json.dumps(result,indent=2))
    hits=result.get('hits',{});seq=hits.get('sequences',[]);ev=hits.get('events',[])
    hosts=sorted({e['_source']['host']['id'] for s in seq for e in s['events']}|{e['_source']['host']['id'] for e in ev})
    summary['queries'].append({'query':file.stem,'matches':len(seq) if seq else len(ev),'hosts':hosts,'kind':'sequences' if file.stem.startswith('q4') else 'events'})
(root/'docs/hunt_results.json').write_text(json.dumps(summary,indent=2))
print(json.dumps(summary,indent=2))
