"""Shared pytest fixtures, path shims, and sample-header parser.

Why the sys.path shim: core/spyware-samples/ has a hyphen, which is not a valid
Python package name. Samples (spyware.py) are executed inside the victim
container with PYTHONPATH=/opt/spyware/shared and import their shared deps as
`import collector` / `import exfil_http`. To exercise those same imports in
host-side unit tests, we inject the hyphenated shared/ directory into sys.path
here.
"""
from __future__ import annotations

import pathlib
import re
import sys
from dataclasses import dataclass

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
SAMPLES_ROOT = REPO_ROOT / "core" / "spyware-samples"
SHARED_DIR = SAMPLES_ROOT / "shared"

if SHARED_DIR.is_dir() and str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))


HEADER_LINE_LAB = re.compile(r"^#\s*GHOST-IN-THE-BOX LAB\s*—\s*EDUCATIONAL SAMPLE\s*$")
HEADER_LINE_SCOPE = re.compile(r"^#\s*Round:\s*(\d+)\s*\|\s*(.+)$")
HEADER_LINE_COURSE = re.compile(r"^#\s*For use in university cybersecurity courses\s*$")
HEADER_LINE_MITRE = re.compile(r"^#\s*MITRE ATT&CK:\s*(.+)$")
TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass(frozen=True)
class SampleHeader:
    source_path: pathlib.Path
    round: int
    scope_note: str
    mitre_ttps: frozenset[str]


def parse_header(source_path: pathlib.Path) -> SampleHeader:
    """Parse the required 4-line lab header; raise AssertionError on drift."""
    lines = source_path.read_text(encoding="utf-8").splitlines()
    if len(lines) < 4:
        raise AssertionError(f"{source_path}: fewer than 4 header lines")

    if not HEADER_LINE_LAB.match(lines[0]):
        raise AssertionError(f"{source_path}: line 1 does not match lab tag: {lines[0]!r}")
    m_scope = HEADER_LINE_SCOPE.match(lines[1])
    if not m_scope:
        raise AssertionError(f"{source_path}: line 2 does not match scope: {lines[1]!r}")
    if not HEADER_LINE_COURSE.match(lines[2]):
        raise AssertionError(f"{source_path}: line 3 does not match course line: {lines[2]!r}")
    m_mitre = HEADER_LINE_MITRE.match(lines[3])
    if not m_mitre:
        raise AssertionError(f"{source_path}: line 4 does not match MITRE line: {lines[3]!r}")

    ttps = frozenset(TTP_PATTERN.findall(m_mitre.group(1)))
    if not ttps:
        raise AssertionError(f"{source_path}: MITRE line present but no TTP IDs parsed")

    return SampleHeader(
        source_path=source_path,
        round=int(m_scope.group(1)),
        scope_note=m_scope.group(2).strip(),
        mitre_ttps=ttps,
    )


def collect_sample_paths() -> list[pathlib.Path]:
    """All round-*/spyware.py files under core/spyware-samples/."""
    return sorted(SAMPLES_ROOT.glob("round-*/spyware.py"))


@pytest.fixture
def parse_sample_header():
    """Fixture wrapping parse_header() so tests get it via dependency injection."""
    return parse_header
