import importlib.util
from pathlib import Path
import subprocess
import pytest

spec=importlib.util.spec_from_file_location('release_gate',Path(__file__).resolve().parents[1]/'packaging/check_release.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def test_manual_build_is_not_stable():
    assert gate.check('refs/heads/main') is False


def test_candidate_requires_main_ancestry(monkeypatch):
    calls=[]
    monkeypatch.setattr(gate.subprocess,'run',lambda argv,**kwargs:calls.append(argv))
    assert gate.check('refs/tags/v'+gate.VERSION) is False
    assert calls==[['git','merge-base','--is-ancestor','HEAD','origin/main']]


def test_wrong_tag_cannot_publish():
    with pytest.raises(ValueError,match='match'):
        gate.check('refs/tags/v0.0.0rc1')


def test_candidate_outside_main_cannot_publish(monkeypatch):
    def deny(*args,**kwargs):
        raise subprocess.CalledProcessError(1,args[0])
    monkeypatch.setattr(gate.subprocess,'run',deny)
    with pytest.raises(subprocess.CalledProcessError):
        gate.check('refs/tags/v'+gate.VERSION)


def test_stable_still_requires_actual_acceptance(monkeypatch,tmp_path):
    monkeypatch.setattr(gate,'VERSION','1.1.0')
    monkeypatch.setattr(gate,'ROOT',tmp_path)
    (tmp_path/'docs').mkdir()
    (tmp_path/'docs/release-acceptance.json').write_text('{}')
    (tmp_path/'pyproject.toml').write_text('version = "1.1.0"')
    with pytest.raises(ValueError,match='acceptance is incomplete'):
        gate.check('refs/tags/v1.1.0')
