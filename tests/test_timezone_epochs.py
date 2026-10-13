"""Persistent agent epochs must agree with backend UTC on every host timezone."""
import os
from pathlib import Path
import subprocess
import sys
import pytest


@pytest.mark.parametrize('timezone',['Asia/Kolkata','America/Los_Angeles','UTC'])
def test_persisted_epochs_are_timezone_independent(timezone):
    source=Path(__file__).resolve().parents[1]/'src'
    environment={**os.environ,'TZ':timezone,'PYTHONPATH':str(source)}
    script='''
import time
if hasattr(time,'tzset'):time.tzset()
from agent.state_manager import ScanState
state=ScanState(scan_id='synthetic-clock')
assert abs(state.created_at-int(time.time()))<2
assert abs(state.updated_at-int(time.time()))<2
'''
    subprocess.run([sys.executable,'-c',script],env=environment,check=True,capture_output=True)
