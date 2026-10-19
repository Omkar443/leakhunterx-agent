"""Frozen synthetic rule-expansion challenge, full detector, no provider requests."""
import argparse,hashlib,json,math,platform,sys,time
from pathlib import Path
from collections import Counter
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from agent.js.leak_detector import EnterpriseLeakDetector
from agent.js.rule_catalog import matcher
from catalog_fixtures import cases as fixture_cases

def run():
    args=argparse.ArgumentParser();args.add_argument('--output',type=Path,default=ROOT/'benchmarks/results/catalog-500.json');args.add_argument('--check',action='store_true');args=args.parse_args()
    raw=(ROOT/'benchmarks/catalog-cases.json').read_bytes();cases=fixture_cases()
    failures=[];counts=Counter();start=time.monotonic()
    for case in cases:
        findings=EnterpriseLeakDetector().check_content(case['content'])
        values={finding['value'] for finding in findings}
        expected=case['secret'];counts['positive_cases']+=1;counts['tp']+=expected in values;counts['fn']+=expected not in values
        extras=values-{expected};counts['fp']+=len(extras)
        if expected not in values or extras:failures.append({'rule':case['rule'],'split':case['split'],'missed':expected not in values,'extra_rules':[f['type'] for f in findings if f['value']!=expected]})
        for kind,value in [('placeholder','[REDACTED]'),('example','your_api_key_here'),('repeated','x'*len(expected))]:
            negative=case['content'].replace(expected,value)
            rows=EnterpriseLeakDetector().check_content(negative);counts['negative_cases']+=1
            counts['false_positive_files']+=bool(rows);counts['negative_findings']+=len(rows)
            if rows:failures.append({'rule':case['rule'],'split':case['split'],'negative':kind,'extra_rules':[row['type'] for row in rows]})
    report={'version':'catalog-500-v1','scope':'synthetic offline challenge; not real-world accuracy or provider activity','catalog_sha256':matcher().digest,'corpus_sha256':hashlib.sha256(raw).hexdigest(),'python':platform.python_version(),'counts':dict(counts),'precision':counts['tp']/(counts['tp']+counts['fp']+counts['negative_findings']) if counts['tp'] else 0,'recall':counts['tp']/counts['positive_cases'],'negative_file_false_positive_rate':counts['false_positive_files']/counts['negative_cases'],'seconds':round(time.monotonic()-start,3),'failures':failures}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({key:value for key,value in report.items() if key!='failures'},indent=2))
    if args.check and failures:raise SystemExit('Catalog challenge failed')
if __name__=='__main__':run()
