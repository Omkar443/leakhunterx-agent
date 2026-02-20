"""
Output formatter - handles ALL formatting logic
Separated from main.py to maintain pure orchestration
"""

import json
from pathlib import Path
from typing import Dict, Any


def format_scan_results(
    scan_id: str,
    agent_id: str,
    target: str,
    analysis_results: Dict[str, Any],
    failed: bool = False,
    error: str = None,
    mode: str = "development",
    output_json: bool = False
):
    """Format and output scan results - ALL formatting logic here"""
    
    if mode == "file" or output_json:
        _output_json_results(
            scan_id=scan_id,
            agent_id=agent_id,
            target=target,
            analysis_results=analysis_results,
            failed=failed,
            error=error
        )
    
    if mode in ["development", "file"]:
        _print_human_readable_summary(
            scan_id=scan_id,
            agent_id=agent_id,
            target=target,
            analysis_results=analysis_results,
            failed=failed,
            error=error
        )


def _output_json_results(
    scan_id: str,
    agent_id: str,
    target: str,
    analysis_results: Dict[str, Any],
    failed: bool = False,
    error: str = None
):
    """Output results as JSON file"""
    results = {
        "scan_id": scan_id,
        "agent_id": agent_id,
        "target": target,
        "failed": failed,
        "error": error,
        **analysis_results
    }
    
    output_file = Path(f"scan_{scan_id}.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📁 Full results saved to: {output_file}")


def _print_human_readable_summary(
    scan_id: str,
    agent_id: str,
    target: str,
    analysis_results: Dict[str, Any],
    failed: bool = False,
    error: str = None
):
    """Print human-readable summary"""
    
    print("\n" + "="*60)
    print("LEAKHUNTERX SCAN RESULTS")
    print("="*60)
    print(f"Agent ID:    {agent_id}")
    print(f"Scan ID:     {scan_id}")
    print(f"Target:      {target}")
    
    if failed:
        print(f"\n❌ SCAN FAILED: {error}")
        print("="*60)
        return
    
    # Extract metrics from analysis results
    js_files = analysis_results.get("js_files_analyzed", 0)
    endpoints = len(analysis_results.get("endpoints", []))
    secrets = len(analysis_results.get("secrets", []))
    findings = analysis_results.get("findings", [])
    
    print(f"JS Files:    {js_files}")
    print(f"Endpoints:   {endpoints}")
    print(f"Secrets:     {secrets}")
    
    if findings:
        print(f"\nTOP FINDINGS:")
        for finding in findings[:5]:  # Show top 5
            severity = finding.get("severity", "INFO")
            value_preview = finding.get("value", "")[:50]
            if len(finding.get("value", "")) > 50:
                value_preview += "..."
            print(f"  [{severity}] {finding['type']}: {value_preview}")
        
        if len(findings) > 5:
            print(f"  ... and {len(findings) - 5} more findings")
    
    print("="*60)