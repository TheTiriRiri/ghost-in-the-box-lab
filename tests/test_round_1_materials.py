import pathlib

ROUND_DIR = pathlib.Path(__file__).parent.parent / "module-techlab" / "rounds" / "round-1-naive"


def test_zadania_exists():
    assert (ROUND_DIR / "zadania.md").is_file()


def test_zadania_covers_all_required_steps():
    text = (ROUND_DIR / "zadania.md").read_text(encoding="utf-8")
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
    for tid in ("T1056.001", "T1113", "T1005", "T1071.001", "T1041"):
        assert tid in text, f"instructor-notes.md missing TTP {tid}"


def test_instructor_notes_contains_yara_reference_rule():
    text = (ROUND_DIR / "instructor-notes.md").read_text(encoding="utf-8")
    assert "rule" in text and "meta:" in text and "strings:" in text, (
        "reference YARA rule missing from instructor notes"
    )
