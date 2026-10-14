"""Fail closed before a stable tag can publish binaries or a PyPI package."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agent.version import VERSION


def check(ref: str) -> bool:
    if not ref.startswith('refs/tags/'):
        return False  # A manual build produces artifacts only.
    tag = ref.removeprefix('refs/tags/')
    if tag != f'v{VERSION}':
        raise ValueError('Release tag must match the embedded package version')
    package_version = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / 'pyproject.toml').read_text(), re.MULTILINE)
    if not package_version or package_version.group(1) != VERSION:
        raise ValueError('Package metadata must match the embedded version')
    stable = re.fullmatch(r'v\d+\.\d+\.\d+', tag) is not None
    if not stable:
        if not re.fullmatch(r'v\d+\.\d+\.\d+rc\d+', tag):
            raise ValueError('Use a stable semantic version or a numbered rc version')
        # Candidate publication is explicit and limited to tested main history.
        # It does not assert that stable acceptance or soak testing is complete.
        subprocess.run(['git', 'merge-base', '--is-ancestor', 'HEAD', 'origin/main'], cwd=ROOT, check=True)
        return False
    evidence = json.loads((ROOT / 'docs/release-acceptance.json').read_text())
    for gate in ('phase1_manual_accepted', 'phase1_soak_passed', 'phase2_accepted', 'latest_agent_hosted_retest_passed'):
        if evidence.get(gate) is not True:
            raise ValueError(f'Release acceptance is incomplete: {gate}')
    if evidence.get('version') != VERSION:
        raise ValueError('Acceptance must apply to this version')
    if type(evidence.get('soak_hours')) not in (int, float) or evidence['soak_hours'] < 24:
        raise ValueError('Record at least 24 hours of successful staging soak')
    for key in ('accepted_by', 'accepted_at', 'evidence_reference'):
        if not isinstance(evidence.get(key), str) or not evidence[key].strip():
            raise ValueError(f'Missing acceptance evidence: {key}')
    for repo in ('backend', 'frontend', 'agent'):
        if not re.fullmatch(r'[0-9a-f]{40}', evidence.get(f'{repo}_tested_commit', '')):
            raise ValueError(f'Missing tested commit: {repo}')
    # A tag on dev or a candidate branch cannot silently become the public release.
    subprocess.run(['git', 'merge-base', '--is-ancestor', 'HEAD', 'origin/main'], cwd=ROOT, check=True)
    subprocess.run(['git', 'merge-base', '--is-ancestor', evidence['agent_tested_commit'], 'HEAD'], cwd=ROOT, check=True)
    return True


if __name__ == '__main__':
    stable = check(os.environ.get('RELEASE_REF', ''))
    publish = os.environ.get('RELEASE_REF', '').startswith('refs/tags/')
    output = f'stable={str(stable).lower()}\npublish={str(publish).lower()}\n'
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write(output)
    print(output.strip())
