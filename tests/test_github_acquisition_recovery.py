"""Real Git regression for interrupted downloads poisoning a later scan."""
from agent.local.scanner import scan_local
from agent.local.failures import GitHubScanError
import pytest
from test_github_sources import repository, git


def test_interrupted_git_lock_cannot_poison_new_scan_or_pinned_resume(repository):
    registry, target, root = repository
    original_pin = git(root, 'rev-parse', 'HEAD')
    def interrupt(kind, data):
        if kind == 'secret_found':
            raise KeyboardInterrupt()
    first = scan_local(registry, target, on_event=interrupt)
    assert first['status'] == 'interrupted'
    cache = registry.path.parent / 'repositories' / target['id']
    legacy = cache / 'objects.git'
    legacy.mkdir(mode=0o700, exist_ok=True)
    git(legacy, 'init', '--bare', '.')
    lock = legacy / 'shallow.lock'
    lock.write_text(original_pin + '\n')
    (root / 'other.js').write_text('const safe=1;')
    git(root, 'add', '.')
    git(root, 'commit', '-m', 'New head after interrupted scan')

    second = scan_local(registry, target)
    assert second['status'] == 'completed' and second['complete']
    assert second['commit_sha'] != original_pin
    # No deletion of locks belonging to another operation is needed.
    assert lock.exists()
    resumed = scan_local(registry, target, scan_id=first['scan_id'], resume=True)
    assert resumed['status'] == 'completed' and resumed['complete']
    assert resumed['commit_sha'] == original_pin
    assert not list(cache.glob('git-attempt-*'))


def test_failed_acquisition_cleans_only_its_own_attempt(repository):
    from agent.sources.github import private_directory
    registry, target, root = repository
    cache = private_directory(private_directory(registry.path.parent / 'repositories') / target['id'])
    orphan = cache / 'git-attempt-orphan'
    orphan.mkdir(mode=0o700, parents=True)
    (orphan / 'shallow.lock').write_text('Other interrupted operation')
    def fail(objects, args, **options):
        (objects / 'shallow.lock').write_text('Current attempt')
        raise GitHubScanError('github_acquisition_failed')
    with pytest.raises(GitHubScanError) as error:
        scan_local(registry, target, github_runner=fail)
    assert error.value.reason == 'github_acquisition_failed'
    assert list(cache.glob('git-attempt-*')) == [orphan]


def test_missing_git_has_a_finite_actionable_failure(monkeypatch, tmp_path):
    from agent.sources.github import git_command
    monkeypatch.setattr('agent.sources.github.shutil.which', lambda _: None)
    with pytest.raises(GitHubScanError) as error:
        git_command(tmp_path, ['init', '--bare', '.'])
    assert error.value.reason == 'github_git_unavailable'
