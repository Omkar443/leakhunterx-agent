import importlib.util
import json
from pathlib import Path

import pytest


def gate():
    path=Path(__file__).resolve().parents[1]/'packaging/check_release.py'
    spec=importlib.util.spec_from_file_location('release_gate_fixture',path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_main_push_and_candidate_tag_do_not_publish_stable_packages():
    module=gate()
    assert module.check('refs/heads/main') is False
    assert module.check('refs/tags/v'+module.VERSION) is False
    with pytest.raises(ValueError,match='match'): module.check('refs/tags/v99.0.0')


def test_stable_publication_requires_real_acceptance(monkeypatch,tmp_path):
    module=gate(); monkeypatch.setattr(module,'VERSION','1.1.0'); monkeypatch.setattr(module,'ROOT',tmp_path)
    (tmp_path/'docs').mkdir()
    (tmp_path/'pyproject.toml').write_text('version = "1.1.0"')
    (tmp_path/'docs/release-acceptance.json').write_text(json.dumps({'version':'1.1.0','phase1_manual_accepted':False}))
    with pytest.raises(ValueError,match='phase1_manual_accepted'): module.check('refs/tags/v1.1.0')
