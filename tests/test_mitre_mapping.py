"""Each sample's declared MITRE TTPs must be a subset of its round's allowlist."""
import pytest

from generators.data import scenario_facts as sf
from tests.conftest import collect_sample_paths, parse_header


@pytest.fixture(scope="module")
def sample_paths():
    paths = collect_sample_paths()
    if not paths:
        pytest.skip("no samples yet — turns green at Task 7")
    return paths


def test_declared_ttps_are_subset_of_round_allowlist(sample_paths):
    failures = []
    for path in sample_paths:
        header = parse_header(path)
        if header.round not in sf.MITRE_ALLOWLIST:
            failures.append(f"{path}: round {header.round} has no allowlist entry")
            continue
        unexpected = header.mitre_ttps - sf.MITRE_ALLOWLIST[header.round]
        if unexpected:
            failures.append(
                f"{path}: declared TTPs {sorted(unexpected)} are not in "
                f"R{header.round} allowlist"
            )
    assert not failures, "\n".join(failures)


def test_sample_declares_at_least_three_ttps(sample_paths):
    undersized = []
    for path in sample_paths:
        header = parse_header(path)
        if len(header.mitre_ttps) < 3:
            undersized.append((path, sorted(header.mitre_ttps)))
    assert not undersized, (
        f"samples should exercise ≥3 techniques; undersized: {undersized}"
    )


def test_r1_sample_declares_expected_techniques_when_present(sample_paths):
    """When round-1/spyware.py exists, it must declare at least these core R1 TTPs."""
    import pathlib
    r1 = next(
        (p for p in sample_paths if p.parent.name == "round-1"),
        None,
    )
    if r1 is None:
        pytest.skip("round-1 sample not yet written")
    header = parse_header(r1)
    required = {"T1056.001", "T1005", "T1071.001", "T1041"}
    missing = required - header.mitre_ttps
    assert not missing, f"R1 sample missing required TTPs: {sorted(missing)}"
