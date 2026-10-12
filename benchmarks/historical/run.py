"""Synthetic historical fixture benchmark, not archive availability or marketing accuracy."""
import json,time,tracemalloc,hashlib,sys
from pathlib import Path
from uuid import uuid4
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'src'))
from agent.history.runtime import HistoricalScanOrchestrator
from agent.history.javascript import recover_sources,mapped_location,literal_assignments

TOKEN='ghp_'+'v7G9k3Q2s8N4b6Y1m5R0c9T7w2L8p4D6x1Z3'
BODY='const githubToken="'+TOKEN+'";fetch(url,{headers:{Authorization:"Bearer "+githubToken}});'
fixtures=[('literal',BODY,True),('minified','(()=>{'+BODY+'})();',True),('placeholder','const token="ghp_'+'x'*36+'";',False),
          ('plain','const revision="'+'a'*64+'";',False),('huge-prefix','/*'+'a'*100000+'*/'+BODY,True),
          ('static-parts','const githubToken="'+TOKEN[:20]+'" + "'+TOKEN[20:]+'";',True)]
runner=object.__new__(HistoricalScanOrchestrator)
runner.identity={'id':str(uuid4()),'key':hashlib.sha256(b'historical-controlled-fixture-only').digest(),'key_id':str(uuid4()),'source_type':'HISTORY','correlation_identity':None}
started=time.perf_counter();tracemalloc.start();results=[];tp=fp=fn=tn=bytes_read=0
for name,body,expected in fixtures:
    before=time.perf_counter();findings,_,_=runner.analyze(body,'https://example.com/'+name+'.js','20240101120000')
    actual=bool(findings);tp+=int(expected and actual);fn+=int(expected and not actual);fp+=int(not expected and actual);tn+=int(not expected and not actual)
    bytes_read+=len(body.encode());results.append({'fixture':name,'expected':expected,'detected':actual,'seconds':round(time.perf_counter()-before,6)})
elapsed=time.perf_counter()-started;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
report={'benchmark':'LeakHunterX Historical Fixtures v1','synthetic_only':True,'fixtures':results,'precision':tp/(tp+fp) if tp+fp else None,
        'recall':tp/(tp+fn) if tp+fn else None,'false_positive_rate':fp/(fp+tn) if fp+tn else None,'seconds':elapsed,
        'files_per_second':len(fixtures)/elapsed,'mb_per_second':bytes_read/1_000_000/elapsed,'peak_traced_python_bytes':peak,
        'ai_disagreement_rate':None,'ai_measurement':'Not measured; this deterministic fixture run makes no AI requests.'}
output=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).with_name('results.json')
output.write_text(json.dumps(report,indent=2));print(json.dumps({key:value for key,value in report.items() if key!='fixtures'}))
if fp or fn:raise SystemExit(1)
