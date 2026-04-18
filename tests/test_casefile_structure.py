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
