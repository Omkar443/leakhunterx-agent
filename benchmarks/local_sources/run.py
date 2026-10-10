"""Generated, synthetic local-source benchmark. No network or cloud credentials.

Run each size in a fresh process to measure resident memory independently:
PYTHONPATH=src python benchmarks/local_sources/run.py --files 10000
"""
import argparse
import json
import resource
import socket
import tempfile
import time
from pathlib import Path
from agent.local.registry import Registry
from agent.local.scanner import scan_local


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--files',type=int,choices=(500,10000,100000),required=True)
    args=parser.parse_args()
    socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError('Benchmark network disabled'))
    with tempfile.TemporaryDirectory(prefix='lhx-local-benchmark-') as tmp:
        base=Path(tmp); root=base/'project'; root.mkdir(); private=base/'private'; private.mkdir(mode=0o700)
        body='const description = "Local source benchmark resource";\n'+'// Ordinary source text.\n'*8
        for i in range(args.files): (root/f'{i:06}.js').write_text(body)
        (root/'000000.js').write_text('const token = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5";\n'+body)
        registry=Registry(private/'agent.db'); target=registry.add(root,'Benchmark')
        start=time.monotonic(); first=None
        def event(kind,data):
            nonlocal first
            if kind=='secret_found' and first is None: first=time.monotonic()-start
        summary=scan_local(registry,target,on_event=event)
        elapsed=time.monotonic()-start
        print(json.dumps(dict(files=args.files,processed=summary['processed_files'],complete=summary['complete'],
            seconds=round(elapsed,3),files_per_second=round(summary['processed_files']/elapsed,2),
            mb_per_second=round(summary['bytes_processed']/1_000_000/elapsed,3),
            peak_rss_mb=round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,2),
            first_finding_seconds=round(first,3) if first is not None else None,
            findings=summary['findings_count'],profile='standard',network='disabled')))
        if not summary['complete'] or summary['processed_files']!=args.files or first is None: raise SystemExit(1)


if __name__=='__main__': main()
