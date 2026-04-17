"""Every spyware sample must be valid Python and carry the mandatory lab header."""
import ast

import pytest

from tests.conftest import collect_sample_paths


@pytest.fixture(scope="module")
def sample_paths():
    paths = collect_sample_paths()
    if not paths:
        pytest.skip("no spyware samples on disk yet — tests turn green after Task 7")
    return paths


def test_at_least_one_sample_exists_after_round_1():
    # This will FAIL until Task 7 lands round-1/spyware.py. That is the desired state:
    # it is the canary ensuring R1 produced a sample file at the expected location.
    paths = collect_sample_paths()
    assert paths, "expected core/spyware-samples/round-*/spyware.py to exist"


def test_all_samples_are_parseable_python(sample_paths):
    for path in sample_paths:
        source = path.read_text(encoding="utf-8")
        ast.parse(source, filename=str(path))


def test_all_samples_have_valid_header(sample_paths, parse_sample_header):
    for path in sample_paths:
        header = parse_sample_header(path)
        assert header.round in (1, 2, 3)
        assert "docker" in header.scope_note.lower()
        assert len(header.mitre_ttps) >= 1
