from pathlib import Path
import re
from agent.version import VERSION

ROOT=Path(__file__).resolve().parents[1]


def test_pypi_images_are_absolute_and_exist_in_release():
    readme=(ROOT/'README.md').read_text()
    for name in ('readme-banner','architecture'):
        # Existing immutable asset tags remain valid across source candidates;
        # requiring the unpublished candidate tag would break PyPI images.
        assert re.search(r'https://raw\.githubusercontent\.com/Omkar443/leakhunterx-agent/v\d+\.\d+\.\d+(?:rc\d+)?/assets/'+name+r'\.png',readme)
        assert (ROOT/'assets'/f'{name}.png').read_bytes().startswith(b'\x89PNG')
    assert 'src="assets/' not in readme
    assert not re.search(r'\]\((docs|assets)/',readme)


def test_release_dependencies_match_requirements_and_pin_stable_versions():
    metadata=(ROOT/'pyproject.toml').read_text()
    lines=(ROOT/'requirements.txt').read_text().strip().splitlines()
    assert '"httpx==0.28.1"' in metadata
    for line in lines:
        assert re.fullmatch(r'[a-z0-9-]+==\d+\.\d+\.\d+',line)
        assert f'"{line}"' in metadata
