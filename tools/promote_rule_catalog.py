"""Promote exercised candidates; emit one catalog plus cloud ingestion identities."""
import copy,hashlib,json,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
sys.path.insert(0,str(ROOT/'benchmarks'))
from catalog_fixtures import recipe_case
from agent.js.leak_detector import EnterpriseLeakDetector
from agent.js.detection_policy import update_patterns

def main():
    candidates=json.loads((ROOT/'tools/catalog-candidates.json').read_text())
    baseline=copy.deepcopy(EnterpriseLeakDetector.PATTERNS);update_patterns(baseline)
    ranked=sorted(candidates['candidates'],key=lambda row:(row['rule']['mode']!='format',-row['rule']['min_entropy'],-len(row['rule']['keyword']),row['rule']['id']))
    selected=ranked[:500-len(baseline)]
    if len(selected)!=462:raise ValueError('Insufficient exercised rules')
    rules=sorted([row['rule'] for row in selected],key=lambda row:row['id'])
    if len({row['id'] for row in rules}|set(baseline))!=500:raise ValueError('Rule identity collision')
    catalog={'version':'catalog-500-v1','source_commit':candidates['source_commit'],'source_archive_sha256':candidates['source_sha256'],'rules':rules}
    raw=(json.dumps(catalog,indent=2,sort_keys=True)+'\n').encode();digest=hashlib.sha256(raw).hexdigest()
    (ROOT/'src/agent/js/catalog.json').write_bytes(raw)
    (ROOT/'src/agent/js/catalog_manifest.py').write_text(f'"""Generated identity; regenerate with tools/promote_rule_catalog.py."""\nCATALOG_SHA256 = {digest!r}\n')
    specimens=[]
    for row in selected:
        for positive in row['positives']:specimens.append(recipe_case(row['rule'],positive))
    (ROOT/'benchmarks/catalog-cases.json').write_text(json.dumps({'version':'catalog-500-v1','scope':'deterministic synthetic recipes; values generated only during offline tests; not production accuracy','cases':specimens},indent=2)+'\n')
    backend=ROOT.parent/'backend-leakhunterx/app/services/detector_catalog.py'
    backend.write_text('"""Generated finite ingestion identities. No executable upstream rules.\nSource: mongodb/kingfisher '+candidates['source_commit']+' (Apache-2.0).\n"""\nCATALOG_SHA256 = '+repr(digest)+'\nDETECTOR_POLICIES = frozenset(("detector-v1", "detector-v2", "detector-v3", "detector-v4"))\nCATALOG_IDS = frozenset('+repr(tuple(row['id'] for row in rules))+')\n')
    print(json.dumps({'active_rules':500,'existing_rules':len(baseline),'new_rules':len(rules),'sha256':digest,'specimens':len(specimens)}))
if __name__=='__main__':main()
