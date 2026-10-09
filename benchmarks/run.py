"""python benchmarks/run.py --output benchmarks/results/<name>.json"""
import argparse
import hashlib
import json
import platform
import sys
import time
import tracemalloc
import subprocess
import types
from pathlib import Path
import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from corpus import cases
from agent.js.leak_detector import EnterpriseLeakDetector


def ai_metrics(data, labels, corpus_sha256):
    if not data.get('provider') or not data.get('model') or not data.get('policy_version'):
        raise ValueError('AI provenance required')
    if data.get('incomplete') or data.get('corpus_sha256') != corpus_sha256:
        raise ValueError('AI evaluation must be complete and match this corpus')
    rows = data['items']; seen = set(); disagree = evaluated = 0
    for row in rows:
        identity = row['case_id']
        if identity in seen or identity not in labels or row['verdict'] not in ('VALID','FALSE_POSITIVE','UNCERTAIN'):
            raise ValueError('Invalid AI evaluation')
        expected = 'VALID' if labels[identity] else 'FALSE_POSITIVE'
        if row.get('expected') != expected or row.get('status') not in ('completed','failed','skipped_low_priority','pending'):
            raise ValueError('Invalid AI ground truth or status')
        seen.add(identity)
        if row['status'] == 'completed' and row['verdict'] != 'UNCERTAIN':
            evaluated += 1; disagree += row['verdict'] != expected
    return {'rate':disagree/evaluated if evaluated else None,'sampled':len(rows),'evaluated':evaluated,
        'undetermined':len(rows)-evaluated,'coverage':evaluated/len(rows) if rows else 0,
        'disagreements':disagree,'provider':data['provider'],'model':data['model'],
        'policy_version':data['policy_version'],'definition':'Raw AI verdict vs labelled synthetic ground truth; excludes failed/uncertain with coverage disclosed.'}


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ai-results', type=Path)
    parser.add_argument('--baseline', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    Detector = EnterpriseLeakDetector
    if args.baseline:
        # Immutable trusted local revision; no checkout/reset of the working tree.
        source = subprocess.check_output(['git','show','383f6f1:src/agent/js/leak_detector.py'], cwd=Path(__file__).resolve().parents[1]).decode()
        module = types.ModuleType('agent.js.baseline_detector')
        exec(compile(source,'baseline_detector.py','exec'),module.__dict__)
        Detector = module.EnterpriseLeakDetector
    digest = hashlib.sha256()
    counts = dict(tp=0, fp=0, fn=0, negative_files=0, false_positive_files=0, files=0, bytes=0)
    failures, labels = [], {}
    rss_peak = psutil.Process().memory_info().rss
    tracemalloc.start()
    start = time.perf_counter()
    for case in cases():
        content = case['content']
        digest.update(json.dumps({k:v for k,v in case.items() if k != 'content'}, sort_keys=True).encode())
        digest.update(content.encode())
        detector = Detector(aggressive=True)
        # Prefer the path-aware detector when available; keep baseline runnable.
        if hasattr(detector, 'source_path'): detector.source_path = case['path']
        found = {(row['type'], row['value']) for row in detector.check_content(content)}
        expected = set(case['expected'])
        tp, fp, fn = len(found & expected), len(found - expected), len(expected - found)
        counts['tp'] += tp; counts['fp'] += fp; counts['fn'] += fn
        counts['files'] += 1; counts['bytes'] += len(content.encode())
        if not expected:
            counts['negative_files'] += 1
            counts['false_positive_files'] += bool(found)
        labels[case['id']] = bool(expected)
        if fp or fn: failures.append({'case':case['id'], 'fp_rules':sorted(t for t,v in found-expected), 'fn_rules':sorted(t for t,v in expected-found)})
        rss_peak = max(rss_peak, psutil.Process().memory_info().rss)
    elapsed = time.perf_counter()-start
    _, allocated_peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
    ai = {'rate':None, 'evaluated':0, 'reason':'No provider evaluation supplied; not measured.'}
    if args.ai_results:
        ai = ai_metrics(json.loads(args.ai_results.read_text(encoding='utf-8')), labels, digest.hexdigest())
    report = {'benchmark':'LeakHunterX Benchmark v1', 'corpus_sha256':digest.hexdigest(), 'scope':'synthetic, offline, detector-only; not real-world accuracy',
        'detector_revision':'383f6f1' if args.baseline else 'detector-v1 working tree',
        'environment':{'python':platform.python_version(),'platform':platform.platform()}, 'counts':counts,
        'precision':counts['tp']/(counts['tp']+counts['fp']) if counts['tp']+counts['fp'] else None,
        'recall':counts['tp']/(counts['tp']+counts['fn']) if counts['tp']+counts['fn'] else None,
        'false_positive_rate':counts['false_positive_files']/counts['negative_files'],
        'scan_seconds':elapsed,'files_per_second':counts['files']/elapsed,'mb_per_second':counts['bytes']/1048576/elapsed,
        'peak_sampled_rss_bytes':rss_peak,'peak_python_allocated_bytes':allocated_peak,'ai_disagreement':ai,'failures':failures}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('failures','environment')}, indent=2))
    if args.check and (report['precision'] < .98 or report['recall'] < .95 or report['false_positive_rate'] > .02 or elapsed > 60 or rss_peak > 512*1048576):
        raise SystemExit('Benchmark regression gate failed')


if __name__ == '__main__': run()
